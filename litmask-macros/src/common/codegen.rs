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
/// Only `#[derive(MaskDebug)]` uses this; the serde name paths take the
/// plain [`mask_name`] (they `Box::leak` the name, so it never drops and
/// zeroize-on-drop would be meaningless).
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
fn mask_plaintext(mut plaintext: Vec<u8>, span: proc_macro2::Span, kind: MaskKind) -> TokenStream {
    let mut mask_key = load_out_dir_artifact::<KEY_LEN>(KEY_ARTIFACT);
    let mut seed = load_out_dir_artifact::<KEY_LEN>(SEED_ARTIFACT);

    let pm_span = span.unwrap();
    let file = canonicalize_file_path(pm_span.file(), manifest_dir());
    let line = u32::try_from(pm_span.line()).unwrap_or(u32::MAX);
    let column = u32::try_from(pm_span.column()).unwrap_or(u32::MAX);
    let nonce = nonce_for_call_site(&seed, &file, line, column, &plaintext);
    seed.zeroize();

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
    // ciphertext (plaintext.len()) || tag (TAG_LEN)`. plaintext was
    // zeroized above, but its prior length equals blob_len - NONCE_LEN
    // - TAG_LEN; assert the relationship so future changes to the
    // concat shape trip a test-time panic.
    debug_assert!(blob_len >= NONCE_LEN + TAG_LEN);
    debug_assert_eq!(blob_len, NONCE_LEN + ciphertext_and_tag.len());
    let blob_ident = syn::Ident::new("__LITMASK_BLOB", proc_macro2::Span::mixed_site());
    let wrapper = quote! { ::litmask::__wrapper_bytes!() };
    let seal_tier = quote! { ::litmask::__seal_tier!() };
    let decrypt = decrypt_expr(kind, &blob_ident, &wrapper, &seal_tier);

    quote! {
        {
            const #blob_ident: &[u8; #blob_len] = #blob_lit;
            #decrypt
        }
    }
}

/// The runtime decrypt-and-construct expression for a [`MaskKind`].
/// Pure (no artifact loading) so the kind→seam routing is unit-testable:
/// `StrZeroizing` must reach `__decrypt_string_zeroizing`, the others
/// their plain seams.
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
        // `MaskDebug` names: decrypt to a `Zeroizing<String>` so the
        // formatted name is overwritten when the per-`fmt` temporary
        // drops (§2.15.1.5). Derefs to `&str`, so the `Formatter`
        // builder call sites are unchanged.
        MaskKind::StrZeroizing => quote! {
            ::litmask::__internal::__decrypt_string_zeroizing(#blob_ident, #wrapper, #seal_tier)
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
    fn maskdebug_kind_routes_through_zeroizing_seam() {
        assert!(
            expr_string(MaskKind::StrZeroizing).contains("__decrypt_string_zeroizing"),
            "StrZeroizing must reach the zeroizing seam"
        );
    }

    #[test]
    fn plain_str_kind_uses_non_zeroizing_seam() {
        // The serde name paths (`mask_name` / `masked_static_name`) stay
        // on this kind; they `Box::leak` the name, so zeroize-on-drop is
        // meaningless and must not be emitted for them.
        let s = expr_string(MaskKind::Str);
        assert!(s.contains("__decrypt_string"));
        assert!(
            !s.contains("__decrypt_string_zeroizing"),
            "plain Str must not reach the zeroizing seam"
        );
    }
}
