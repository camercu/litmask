//! AEAD-mask token emitters: encrypt a plaintext under the build's
//! `mask_key` (keyed on the call site) and emit the `{ const BLOB; decrypt
//! }` block, plus the name-masking helpers the derives build on.

use proc_macro2::TokenStream;
use quote::quote;
use syn::ext::IdentExt;
use zeroize::Zeroize;

use litmask_internal::{
    CURRENT_CIPHER, KEY_ARTIFACT, KEY_LEN, NONCE_LEN, SEED_ARTIFACT, TAG_LEN, aead_encrypt,
    nonce_for_call_site,
};

use super::artifact::load_out_dir_artifact;
use super::path::{canonicalize_file_path, manifest_dir};

/// AEAD-mask an arbitrary resolved name, emitting a runtime decrypt
/// expression returning `String`. The serde derives pass the name a
/// field/variant/container resolves to after `#[serde(rename = ...)]`.
/// Serde-only: its names are `Box::leak`ed (never dropped), so they take
/// the plain non-zeroizing seam; `MaskDebug` uses [`mask_ident`].
#[cfg(feature = "unstable-serde")]
pub(crate) fn mask_name(span: proc_macro2::Span, name: &str) -> TokenStream {
    mask_str(span, name.as_bytes().to_vec())
}

/// AEAD-mask an identifier's name, emitting a runtime decrypt
/// expression returning `Zeroizing<String>` so the name is overwritten
/// when the per-`fmt` temporary drops (§2.15.1.5). Single owner of the
/// masking derives' raw-ident contract: `r#type` renders/serializes as
/// `type`, never with the raw prefix — matching the plain derives.
///
/// Only `#[derive(MaskDebug)]` uses this; serde names take the plain
/// [`mask_name`] (see there for why).
pub(crate) fn mask_ident(ident: &syn::Ident) -> TokenStream {
    mask_str_zeroizing(ident.span(), ident.unraw().to_string().into_bytes())
}

/// Emit a `&'static str` expression yielding a masked resolved name at
/// runtime: decrypt the AEAD blob once, leak the `String`, cache in a
/// `OnceLock`. The serde derives need `&'static str` names
/// (`serialize_field`, `Error::missing_field`, ...), which a
/// runtime-decrypted name can only satisfy by leaking; the cache
/// bounds the leak to one allocation per use site. (`MaskDebug` uses
/// `mask_ident` instead — the `Formatter` API takes `&str`, so it
/// never needs the leak and can zeroize the name on drop.)
#[cfg(feature = "unstable-serde")]
pub(crate) fn masked_static_name(span: proc_macro2::Span, name: &str) -> TokenStream {
    let decrypt = mask_name(span, name);
    quote! {
        {
            static __LITMASK_NAME: ::std::sync::OnceLock<&'static str> =
                ::std::sync::OnceLock::new();
            *__LITMASK_NAME.get_or_init(|| ::std::boxed::Box::leak(
                (#decrypt).into_boxed_str(),
            ))
        }
    }
}

/// Emit a byte slice as a byte-string literal token (`b"..."`), typed
/// `&'static [u8; N]`. Used by the `mask!` and `weak_mask!` expansions
/// to inline the encrypted / obfuscated bytes as a `const` in the
/// caller's code. A byte-string literal is one token regardless of
/// length, so it keeps macro expansion and downstream parsing cheap
/// for large blobs (e.g. `mask_include_bytes!` of a sizeable file) —
/// a comma-separated `[u8; N]` array literal would emit `N` tokens.
pub(crate) fn byte_string_literal(bytes: &[u8]) -> TokenStream {
    let lit = proc_macro2::Literal::byte_string(bytes);
    quote! { #lit }
}

/// Return type of a masking macro's runtime expansion. Drives the
/// decrypt-and-construct expression emitted alongside the encrypted
/// blob constant. Private to this module — callers select via the
/// typed [`mask_str`] / [`mask_bytes`] / [`mask_cstr`] helpers.
#[derive(Clone, Copy)]
enum MaskKind {
    /// `String` from UTF-8 bytes.
    Str,
    /// `Zeroizing<String>` from UTF-8 bytes — overwrites the plaintext
    /// when the value drops. Used by `#[derive(MaskDebug)]` names.
    StrZeroizing,
    /// `Vec<u8>` from raw bytes.
    Bytes,
    /// `CString` from UTF-8 bytes (NUL re-added at decode time).
    CStr,
}

/// AEAD-encrypt `plaintext` under the build's `mask_key` and emit a
/// runtime decrypt expression returning `String` (UTF-8). Used by
/// every masking macro whose output is a string: `mask!("text")`,
/// `mask_include_str!`, `mask_concat!`, `mask_env!`,
/// `mask_option_env!`'s `Some` branch, `mask_file!`,
/// `mask_format!`'s per-fragment masking.
pub(crate) fn mask_str(span: proc_macro2::Span, plaintext: Vec<u8>) -> TokenStream {
    mask_plaintext(plaintext, span, MaskKind::Str)
}

/// Like [`mask_str`] but emits a decrypt returning `Zeroizing<String>`,
/// overwriting the plaintext on drop. Used by [`mask_ident`] for
/// `#[derive(MaskDebug)]` names.
fn mask_str_zeroizing(span: proc_macro2::Span, plaintext: Vec<u8>) -> TokenStream {
    mask_plaintext(plaintext, span, MaskKind::StrZeroizing)
}

/// AEAD-encrypt `plaintext` and emit a runtime decrypt expression
/// returning `Vec<u8>`. Used by `mask!(b"...")` and
/// `mask_include_bytes!`.
pub(crate) fn mask_bytes(span: proc_macro2::Span, plaintext: Vec<u8>) -> TokenStream {
    mask_plaintext(plaintext, span, MaskKind::Bytes)
}

/// AEAD-encrypt `plaintext` and emit a runtime decrypt expression
/// returning `CString` (NUL re-added at decode time). Used by
/// `mask!(c"...")`. The NUL terminator is dropped from `plaintext`
/// before encryption and reconstituted via `__decrypt_cstring_call!`
/// at the user's call site; that macro emits a `compile_error!`
/// under `--no-default-features`.
pub(crate) fn mask_cstr(span: proc_macro2::Span, plaintext: Vec<u8>) -> TokenStream {
    mask_plaintext(plaintext, span, MaskKind::CStr)
}

/// Encrypt `plaintext` under the build's `mask_key` keyed on the
/// `(file, line, column, plaintext)` tuple of `span` (spec §1.5.2),
/// then emit a `{ const __LITMASK_BLOB = ...; decrypt(...) }` block
/// that returns a value of the kind-appropriate type at runtime.
///
/// Shared body for every call-site masking macro. Handles key/seed
/// loading, nonce derivation, AEAD encryption, secret zeroization,
/// and the runtime decrypt expression for the requested return type.
///
/// `plaintext` is zeroized on return; callers MUST NOT rely on
/// reading the buffer afterwards.
fn mask_plaintext(plaintext: Vec<u8>, span: proc_macro2::Span, kind: MaskKind) -> TokenStream {
    let sealed = seal_blob(plaintext, span);
    let wrapper = quote! { ::litmask::__wrapper_bytes!() };
    let seal_tier = quote! { ::litmask::__seal_tier!() };
    let decrypt = decrypt_expr(kind, &sealed.blob_ident, &wrapper, &seal_tier);
    let const_def = &sealed.const_def;

    quote! {
        {
            #const_def
            #decrypt
        }
    }
}

/// AEAD-encrypt `plaintext` under the build's `mask_key` (keyed on the
/// call site, §1.5.2) and produce the `const __LITMASK_BLOB` definition
/// plus the metadata a runtime decrypt expression needs. Shared by the
/// heap [`mask_plaintext`] and the stack [`mask_stack_str`] emitters so
/// the encryption / key-zeroization discipline lives in one place.
struct SealedBlob {
    /// Hygienic identifier the emitted `const` binds and the decrypt
    /// expression reads.
    blob_ident: syn::Ident,
    /// `const __LITMASK_BLOB: &[u8; blob_len] = b"...";`
    const_def: TokenStream,
    /// Plaintext byte length = `blob_len - NONCE_LEN - TAG_LEN`. The
    /// stack path stamps this as the `N` of its inline `[u8; N]`; the
    /// heap path never reads it, so it only exists under `stack`.
    #[cfg(feature = "stack")]
    plaintext_len: usize,
}

fn seal_blob(mut plaintext: Vec<u8>, span: proc_macro2::Span) -> SealedBlob {
    let mut mask_key = load_out_dir_artifact::<KEY_LEN>(KEY_ARTIFACT);
    let mut seed = load_out_dir_artifact::<KEY_LEN>(SEED_ARTIFACT);

    let pm_span = span.unwrap();
    let file = canonicalize_file_path(pm_span.file(), manifest_dir());
    let line = u32::try_from(pm_span.line()).unwrap_or(u32::MAX);
    let column = u32::try_from(pm_span.column()).unwrap_or(u32::MAX);
    let nonce = nonce_for_call_site(&seed, &file, line, column, &plaintext);
    seed.zeroize();

    let plaintext_len = plaintext.len();
    let ciphertext_and_tag = aead_encrypt(CURRENT_CIPHER, &mask_key, &nonce, &plaintext)
        .expect("AEAD encryption failed during litmask macro expansion");
    // The proc-macro server is a long-lived dylib; build-time key
    // material lingers in process memory if not explicitly cleared.
    // `litmask-build::emit` already zeroizes its copies — mirror
    // that discipline here for every expansion.
    mask_key.zeroize();
    plaintext.zeroize();

    let blob: Vec<u8> = [nonce.as_slice(), &ciphertext_and_tag].concat();
    let blob_lit = byte_string_literal(&blob);
    let blob_len = blob.len();
    // Wire-format contract: every blob is `nonce (NONCE_LEN) ||
    // ciphertext (plaintext_len) || tag (TAG_LEN)`. Assert the
    // relationship so future changes to the concat shape — or to the
    // `plaintext_len` the stack path stamps as `N` — trip a test-time
    // panic.
    debug_assert!(blob_len >= NONCE_LEN + TAG_LEN);
    debug_assert_eq!(blob_len, NONCE_LEN + ciphertext_and_tag.len());
    debug_assert_eq!(plaintext_len, blob_len - NONCE_LEN - TAG_LEN);
    let blob_ident = syn::Ident::new("__LITMASK_BLOB", proc_macro2::Span::mixed_site());
    let const_def = quote! { const #blob_ident: &[u8; #blob_len] = #blob_lit; };

    SealedBlob {
        blob_ident,
        const_def,
        #[cfg(feature = "stack")]
        plaintext_len,
    }
}

/// AEAD-encrypt `plaintext` and emit a `mask_stack!("...")` expansion: a
/// stack-resident [`litmask::MaskStr<N>`] decrypted in place, no heap
/// allocation. `N` is the plaintext length, fixed at expansion.
#[cfg(feature = "stack")]
pub(crate) fn mask_stack_str(span: proc_macro2::Span, plaintext: Vec<u8>) -> TokenStream {
    mask_stack_call(span, plaintext, &quote! { __decrypt_stack_str })
}

/// `mask_stack!(b"...")` counterpart of [`mask_stack_str`], emitting a
/// [`litmask::MaskBytes<N>`].
#[cfg(feature = "stack")]
pub(crate) fn mask_stack_bytes(span: proc_macro2::Span, plaintext: Vec<u8>) -> TokenStream {
    mask_stack_call(span, plaintext, &quote! { __decrypt_stack_bytes })
}

/// Shared emitter for the stack masking macros: seal the blob and call the
/// named `__decrypt_stack_*` seam with the plaintext length as the `const`
/// generic `N`. `seam` is the bare seam identifier in `::litmask::__internal`.
#[cfg(feature = "stack")]
fn mask_stack_call(span: proc_macro2::Span, plaintext: Vec<u8>, seam: &TokenStream) -> TokenStream {
    let sealed = seal_blob(plaintext, span);
    let blob_ident = &sealed.blob_ident;
    let const_def = &sealed.const_def;
    let n = sealed.plaintext_len;

    quote! {
        {
            #const_def
            ::litmask::__internal::#seam::<#n>(
                #blob_ident,
                ::litmask::__wrapper_bytes!(),
                ::litmask::__seal_tier!(),
            )
        }
    }
}

/// The runtime decrypt-and-construct expression for a [`MaskKind`].
/// Pure (no artifact loading) so the kind→seam routing is unit-testable:
/// `StrZeroizing` wraps the plain string decrypt in `Zeroizing`, the
/// others reach their plain seams.
fn decrypt_expr(
    kind: MaskKind,
    blob_ident: &syn::Ident,
    wrapper: &TokenStream,
    seal_tier: &TokenStream,
) -> TokenStream {
    match kind {
        // One opaque runtime call, no `String` in the expansion: the
        // type's rendered name in consumer-side diagnostics (`String`
        // vs the `__String` alias) varies with the consumer's dep
        // graph, which broke trybuild snapshot stability for const /
        // static misuse fixtures.
        MaskKind::Str => quote! {
            ::litmask::__internal::__decrypt_string(#blob_ident, #wrapper, #seal_tier)
        },
        // `MaskDebug` names: wrap the plain decrypt in `Zeroizing` so the
        // formatted name is overwritten when the per-`fmt` temporary
        // drops (§2.15.1.5). The wrapper derefs to `&str`, so the
        // `Formatter` builder call sites are unchanged; naming
        // `Zeroizing` (not `String`) keeps `__decrypt_string`'s
        // diagnostic-stability property intact.
        MaskKind::StrZeroizing => quote! {
            ::litmask::Zeroizing::new(
                ::litmask::__internal::__decrypt_string(#blob_ident, #wrapper, #seal_tier)
            )
        },
        MaskKind::Bytes => quote! {
            ::litmask::__internal::__decrypt(#blob_ident, #wrapper, #seal_tier)
        },
        MaskKind::CStr => quote! {
            ::litmask::__decrypt_cstring_call!(#blob_ident, #wrapper)
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::format_ident;

    fn expr_string(kind: MaskKind) -> String {
        let blob = format_ident!("__LITMASK_BLOB");
        decrypt_expr(kind, &blob, &quote! { wrapper }, &quote! { seal }).to_string()
    }

    #[test]
    fn maskdebug_kind_wraps_decrypt_in_zeroizing() {
        // StrZeroizing wraps the plain string decrypt in `Zeroizing` so
        // the name is wiped on drop — the same idiom every other wipe
        // site uses (no dedicated runtime primitive).
        let s = expr_string(MaskKind::StrZeroizing);
        assert!(s.contains("Zeroizing"), "{s}");
        assert!(s.contains("__decrypt_string"), "{s}");
    }

    #[test]
    fn plain_str_kind_is_not_zeroizing() {
        // The serde name paths (`mask_name` / `masked_static_name`) stay
        // on this kind; they `Box::leak` the name, so zeroize-on-drop is
        // meaningless and must not be emitted for them.
        let s = expr_string(MaskKind::Str);
        assert!(s.contains("__decrypt_string"));
        assert!(!s.contains("Zeroizing"), "plain Str must not be wrapped");
    }
}
