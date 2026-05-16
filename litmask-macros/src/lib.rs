//! Internal proc-macro crate for `litmask`.
//!
//! Users add `litmask` as a dependency, never this crate directly. The
//! public `litmask` crate re-exports the macros here.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::Token;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::{LitByteStr, LitCStr, LitStr, parse_macro_input};

use litmask_internal::{
    CipherId, KEY_LEN, NONCE_LEN, NONCE_TAG_CALL_SITE, WRAPPER_LEN, aead_encrypt, xor_cycle,
};

/// Monotonic counter combined with the build seed to produce a unique
/// AEAD nonce per `mask!()` call. One counter per rustc process —
/// resets per crate compile, which is the correctness scope (each
/// crate that uses `mask!` has its own `mask_key`, so nonce uniqueness
/// only needs to hold within a single crate's expansion).
///
/// The spec-canonical derivation keys on (file, line, column), but
/// stable Rust's `proc_macro::Span` does not expose those accessors;
/// the counter preserves per-call-site uniqueness at the cost of
/// order-stability.
static CALL_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Mask a string literal, byte string literal, or C string literal at
/// compile time. The expansion is a runtime decryption call whose
/// return type depends on the literal kind:
///
/// - `mask!("...")` returns `String`.
/// - `mask!(b"...")` returns `Vec<u8>`.
/// - `mask!(c"...")` returns `CString`. Requires the `litmask` crate's
///   `std` feature — `CString` is std-only.
///
/// `mask!` additionally accepts two built-in macro invocations as
/// inputs, resolved at proc-macro time:
///
/// - `mask!(include_str!("path"))` reads the file at proc-macro time
///   and masks its contents. Paths are resolved relative to
///   `CARGO_MANIFEST_DIR`. Edits to the file do not currently trigger
///   automatic rebuilds; touch a source file or `cargo clean` to pick
///   them up.
/// - `mask!(concat!(args...))` flattens each argument at proc-macro
///   time. All arguments must be string literals; mixed literal kinds
///   are rejected at compile time.
///
/// # Panics
///
/// Panics during macro expansion (not at the user's runtime) if:
///
/// - `OUT_DIR` is unset (the caller's crate is missing a `build.rs`
///   that invokes `litmask_build::emit()`).
/// - `litmask_key.bin` or `litmask_seed.bin` cannot be read from
///   `OUT_DIR`, or have the wrong length.
/// - ChaCha20-Poly1305 encryption fails for the literal value
///   (cryptographically extraordinary; never observed in practice).
#[proc_macro]
pub fn mask(input: TokenStream) -> TokenStream {
    let kind = parse_macro_input!(input as MaskInput);
    let plaintext = kind.plaintext();

    let mask_key = load_out_dir_artifact::<KEY_LEN>("litmask_key.bin");
    let seed = load_out_dir_artifact::<KEY_LEN>("litmask_seed.bin");

    let idx = CALL_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = derive_nonce(&seed, idx);

    let ciphertext_and_tag =
        aead_encrypt(CipherId::ChaCha20Poly1305, &mask_key, &nonce, &plaintext)
            .expect("AEAD encryption failed at mask! expansion");

    let blob: Vec<u8> = [nonce.as_slice(), &ciphertext_and_tag].concat();
    let blob_lit = byte_array_token(&blob);
    let blob_len = blob.len();
    let decrypt_expr = kind.decrypt_expr(
        &quote! { __LITMASK_BLOB },
        &quote! { ::litmask::__wrapper_bytes!() },
    );

    quote! {
        {
            const __LITMASK_BLOB: &[u8; #blob_len] = &#blob_lit;
            #decrypt_expr
        }
    }
    .into()
}

/// Parsed `mask!` input. After §2.1.1.14 resolution the input always
/// reduces to one of three literal kinds — `include_str!`/`concat!`
/// expand to synthetic `LitStr` values during parsing, so the runtime
/// path is uniform across all accepted input forms.
enum MaskInput {
    Str(LitStr),
    ByteStr(LitByteStr),
    CStr(LitCStr),
}

impl MaskInput {
    fn plaintext(&self) -> Vec<u8> {
        match self {
            Self::Str(lit) => lit.value().into_bytes(),
            Self::ByteStr(lit) => lit.value(),
            // `LitCStr::value` returns a `CString`; into_bytes() drops
            // the NUL terminator. We re-add the NUL at decode time via
            // `CString::new` so the encrypted blob holds only the
            // payload, not the terminator.
            Self::CStr(lit) => lit.value().into_bytes(),
        }
    }

    /// Build the call expression that decrypts the blob to the
    /// kind-appropriate type. The c-string arm routes through a
    /// `macro_rules` dispatcher in `litmask` so a missing-`std`-feature
    /// build surfaces a clear `compile_error!` at the user's
    /// `mask!(c"...")` site instead of a "function not found" diagnostic.
    fn decrypt_expr(&self, blob: &TokenStream2, wrapper: &TokenStream2) -> TokenStream2 {
        match self {
            Self::Str(_) => quote! {
                ::litmask::__internal::__decrypt_str(#blob, #wrapper)
            },
            Self::ByteStr(_) => quote! {
                ::litmask::__internal::__decrypt_bytes(#blob, #wrapper)
            },
            Self::CStr(_) => quote! {
                ::litmask::__decrypt_cstring_call!(#blob, #wrapper)
            },
        }
    }
}

/// §1.9.6 mandates this exact substring for any rejection of `mask!`
/// input other than the two whitelisted macro invocations. Single
/// source of truth — change here and regenerate trybuild snapshots
/// with `TRYBUILD=overwrite`.
const INVALID_LITERAL_MSG: &str = "mask! accepts string, byte string, or C string literals";

/// §1.9.6 / §2.1.1.14: fired when a `concat!` argument inside `mask!`
/// is neither a supported literal kind nor a further nested
/// `concat!`/`include_str!`, or when the args mix literal kinds.
const CONCAT_ARG_MSG: &str =
    "concat! arguments inside mask! must be string, byte string, or C string literals";

impl Parse for MaskInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(LitStr) {
            return input.parse().map(Self::Str);
        }
        if input.peek(LitByteStr) {
            return input.parse().map(Self::ByteStr);
        }
        if input.peek(LitCStr) {
            return input.parse().map(Self::CStr);
        }
        if input.peek(syn::Ident) && input.peek2(Token![!]) {
            return parse_macro_input_arg(input);
        }
        Err(syn::Error::new(input.span(), INVALID_LITERAL_MSG))
    }
}

/// Resolve the `include_str!(...)` / `concat!(...)` whitelist
/// (spec §2.1.1.14). Any other macro invocation falls back to the
/// standard rejection so `mask!(println!(...))` and friends still
/// produce the §1.9.6 message.
fn parse_macro_input_arg(input: ParseStream) -> syn::Result<MaskInput> {
    let mac: syn::Macro = input.parse()?;
    let name = mac.path.get_ident().map(syn::Ident::to_string);
    match name.as_deref() {
        Some("include_str") => resolve_include_str(&mac),
        Some("concat") => resolve_concat(&mac),
        _ => Err(syn::Error::new(mac.path.span(), INVALID_LITERAL_MSG)),
    }
}

/// `mask!(include_str!("path"))` — read the file at proc-macro time
/// and treat its contents as if the user had written a string literal
/// at the call site. Path is resolved relative to the consumer crate's
/// `CARGO_MANIFEST_DIR`.
///
/// Note: spec §2.1.1.14 specifies `proc_macro::tracked_path::path` for
/// build-dependency tracking, but that API is unstable as of Rust
/// 1.88. On stable, edits to the file do NOT trigger an automatic
/// rebuild — users must `cargo clean` or touch a tracked source file.
fn resolve_include_str(mac: &syn::Macro) -> syn::Result<MaskInput> {
    let path_lit: LitStr = mac.parse_body()?;
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| {
        syn::Error::new(
            path_lit.span(),
            "mask!(include_str!(...)): CARGO_MANIFEST_DIR is not set",
        )
    })?;
    let user_path = path_lit.value();
    let resolved = PathBuf::from(manifest_dir).join(&user_path);
    // Error message echoes the user's literal path, not the resolved
    // absolute path. Resolved paths embed the user's home directory
    // and the consumer crate's checkout location, both of which break
    // trybuild snapshot portability and leak local FS layout into
    // diagnostics.
    let content = fs::read_to_string(&resolved).map_err(|e| {
        syn::Error::new(
            path_lit.span(),
            format!("mask!(include_str!(\"{user_path}\")): {e}"),
        )
    })?;
    Ok(MaskInput::Str(LitStr::new(&content, path_lit.span())))
}

/// `mask!(concat!(args...))` — recursively resolve each argument as a
/// `MaskInput`, reject mixed literal kinds, and emit a synthetic
/// literal of the unified kind. Currently only string-literal concat is
/// reachable from the documented acceptance criteria; byte/c-string
/// concat is rejected with [`CONCAT_ARG_MSG`] until a user need lands
/// (spec §2.1.1.14 permits them but std `concat!` does not).
fn resolve_concat(mac: &syn::Macro) -> syn::Result<MaskInput> {
    let span = mac.path.span();
    let args: Punctuated<MaskInput, Token![,]> = mac.parse_body_with(|input: ParseStream| {
        Punctuated::parse_terminated_with(input, |arg_input| {
            // The "argument is neither a supported literal nor a
            // whitelisted macro" case surfaces from inner parsing as
            // INVALID_LITERAL_MSG. Inside `concat!` the spec mandates
            // CONCAT_ARG_MSG for that case — but downstream errors
            // (file-not-found from include_str!, nested concat
            // failures with their own context) must reach the user
            // unchanged, otherwise diagnostics like "failed to read
            // /path/to/missing.txt" get masked behind the generic
            // concat substring.
            //
            // Equality (not `contains`) is intentional: it locks the
            // rewrite to the one well-defined catch-all branch of
            // MaskInput::parse and avoids false-firing on downstream
            // errors whose messages happen to embed the substring.
            // If MaskInput::parse ever decorates this error with
            // span hints or extra notes, this comparison flips
            // silently to false — update both sites in lockstep.
            MaskInput::parse(arg_input).map_err(|e| {
                if e.to_string() == INVALID_LITERAL_MSG {
                    syn::Error::new(e.span(), CONCAT_ARG_MSG)
                } else {
                    e
                }
            })
        })
    })?;

    let mut acc = String::new();
    for arg in &args {
        match arg {
            MaskInput::Str(s) => acc.push_str(&s.value()),
            _ => return Err(syn::Error::new(span, CONCAT_ARG_MSG)),
        }
    }
    Ok(MaskInput::Str(LitStr::new(&acc, span)))
}

/// Identity macro that accepts one string, byte string, or C string
/// literal and expands to that literal unchanged. Exists so
/// `#[mask_all]` (Task 12) and `#[mask_all(strict)]` (Task 14) can
/// recognize it as an explicit opt-out marker — a literal wrapped
/// in `unmasked!` is left alone by the deep-rewriting attribute.
///
/// Zero runtime overhead: the expansion is the bare literal token,
/// so the result is `&'static str` / `&'static [u8; N]` /
/// `&'static CStr` exactly as if the wrapper macro were absent.
#[proc_macro]
pub fn unmasked(input: TokenStream) -> TokenStream {
    let kind = parse_macro_input!(input as UnmaskedInput);
    quote!(#kind).into()
}

/// Parsed `unmasked!` input. Mirrors `MaskInput`'s grammar (string /
/// byte string / C string literal) but emits the literal verbatim
/// instead of running the encryption pipeline. The `ToTokens` impl
/// delegates to the inner literal so `quote!(#kind)` produces the
/// same token the caller wrote.
enum UnmaskedInput {
    Str(LitStr),
    ByteStr(LitByteStr),
    CStr(LitCStr),
}

impl quote::ToTokens for UnmaskedInput {
    fn to_tokens(&self, tokens: &mut TokenStream2) {
        match self {
            Self::Str(lit) => lit.to_tokens(tokens),
            Self::ByteStr(lit) => lit.to_tokens(tokens),
            Self::CStr(lit) => lit.to_tokens(tokens),
        }
    }
}

impl Parse for UnmaskedInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(LitStr) {
            return input.parse().map(Self::Str);
        }
        if input.peek(LitByteStr) {
            return input.parse().map(Self::ByteStr);
        }
        if input.peek(LitCStr) {
            return input.parse().map(Self::CStr);
        }
        Err(syn::Error::new(
            input.span(),
            "unmasked! accepts string, byte string, or C string literals",
        ))
    }
}

/// Obfuscate a string literal at compile time using XOR against the
/// per-build encrypted-`mask_key` wrapper bytes. Expand to code that
/// decodes back to `&'static str` on first runtime access and caches
/// the result for the program's lifetime.
///
/// `weak_mask!()` is weaker than [`mask!`]: there is no AEAD
/// authentication, and both ciphertext and key material live in the
/// same compiled binary, so a Level-2 attacker (disassembler + manual
/// decode) can recover the plaintext. Use `weak_mask!()` only for
/// non-secret strings that need anti-`strings(1)` protection and
/// cannot wait for `init!()` to run (env-var names, default file
/// paths, etc.). Real secrets always go through [`mask!`].
///
/// # Panics
///
/// Panics at proc-macro expansion time if `OUT_DIR` is unset or
/// `litmask_wrapper.bin` cannot be read; these indicate a missing
/// `build.rs` invoking `litmask_build::emit()`.
#[proc_macro]
pub fn weak_mask(input: TokenStream) -> TokenStream {
    let value = parse_macro_input!(input as LitStr).value();

    // The wrapper is per-build random ciphertext; using it as the XOR
    // key removes any fixed litmask byte signature from the encoded
    // output.
    let wrapper = load_out_dir_artifact::<WRAPPER_LEN>("litmask_wrapper.bin");
    let encoded = xor_cycle(value.as_bytes(), &wrapper);
    let encoded_lit = byte_array_token(&encoded);
    let encoded_len = encoded.len();

    quote! {
        {
            const __WEAK_OBF: &[u8; #encoded_len] = &#encoded_lit;
            static __WEAK_CACHE: ::std::sync::OnceLock<::std::string::String> =
                ::std::sync::OnceLock::new();
            ::litmask::__internal::__weak_decode(
                __WEAK_OBF,
                ::litmask::__wrapper_bytes!(),
                &__WEAK_CACHE,
            )
        }
    }
    .into()
}

/// Load a fixed-size build artifact from the caller crate's `OUT_DIR`.
/// Cached per `name` for the lifetime of the proc-macro process — the
/// same file is read at most once per crate compile, regardless of how
/// many `mask!()` / `weak_mask!()` invocations the crate contains.
///
/// Panics at proc-macro expansion time with a diagnostic message if
/// `OUT_DIR` is unset, the file is missing or unreadable, or its
/// length differs from `N` — each of which indicates a missing or
/// out-of-date `litmask_build::emit()` invocation in the caller's
/// `build.rs`.
fn load_out_dir_artifact<const N: usize>(name: &'static str) -> [u8; N] {
    static CACHE: OnceLock<Mutex<HashMap<&'static str, Vec<u8>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().expect("artifact cache mutex poisoned");
    let bytes = map.entry(name).or_insert_with(|| read_out_dir_file(name));
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("litmask: {name} expected {N} bytes, found {}", bytes.len()))
}

fn read_out_dir_file(name: &str) -> Vec<u8> {
    let out_dir = std::env::var_os("OUT_DIR")
        .expect("litmask: OUT_DIR not set; did you add a build.rs running litmask_build::emit()?");
    let path = PathBuf::from(out_dir).join(name);
    fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "litmask: failed to read {name} from OUT_DIR ({}): {e}; did your build.rs run litmask_build::emit()?",
            path.display(),
        )
    })
}

/// Derive the 12-byte AEAD nonce embedded at the head of every blob.
///
/// Keys the BLAKE3 hash on the build seed and tags the message with
/// [`NONCE_TAG_CALL_SITE`] so the call-site nonce space is disjoint
/// from the wrapper nonce space at the same seed.
///
/// The counter alone is sufficient for AEAD nonce uniqueness within a
/// crate compile: `mask_key` is per-crate (each consumer crate has its
/// own `build.rs`/`OUT_DIR`), so the `(key, nonce)` pair only needs to
/// stay unique inside one rustc invocation, and `CALL_COUNTER` is
/// fresh per rustc process. The seed-keyed hash is kept solely so
/// nonces don't appear as `0, 1, 2, …` little-endian patterns in the
/// compiled binary.
fn derive_nonce(seed: &[u8; KEY_LEN], idx: u64) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(NONCE_TAG_CALL_SITE);
    hasher.update(&idx.to_le_bytes());
    let digest = hasher.finalize();
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    out
}

fn byte_array_token(bytes: &[u8]) -> proc_macro2::TokenStream {
    quote! { [ #(#bytes),* ] }
}
