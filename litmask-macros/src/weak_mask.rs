//! `weak_mask!` proc-macro: pre-`init!()` obfuscation for string,
//! byte-string, and C-string literals.
//!
//! XOR a literal against the per-build wrapper bytes at compile time
//! and expand to a cached-on-first-use decode. Return types:
//! - `"..."` → `&'static str`
//! - `b"..."` → `&'static [u8]`
//! - `c"..."` → `&'static CStr` (requires `std` feature)
//!
//! Intended exclusively for the pre-`init!()` bootstrap window —
//! env-var names, default file paths, and other non-secret metadata
//! that must be readable before the AEAD mask-key cell is populated.
//!
//! Weaker than [`crate::mask::expand`]: no AEAD, and the XOR key
//! (the wrapper) lives in the same binary as the obfuscated bytes, so
//! a disassembler-equipped attacker recovers the plaintext trivially.
//!
//! Works under `no_std + alloc` for `str` and `[u8]` literals. The
//! `c"..."` variant delegates to `__weak_decode_cstr_call!` which
//! emits a `compile_error!` under `no_std`.

use proc_macro::TokenStream;
use quote::quote;
use zeroize::Zeroize;

use litmask_internal::{WRAPPER_LEN, derive_weak_xor_key, xor_cycle};

use crate::common::{
    StringLiteral, byte_string_literal, load_out_dir_artifact, parse_string_literal,
};

const MACRO_NAME: &str = "weak_mask";

enum WeakKind {
    Str,
    Bytes,
    CStr,
}

/// Implementation of the `#[proc_macro] weak_mask` entry point.
///
/// # Panics
///
/// Panics at proc-macro expansion time if `OUT_DIR` is unset or
/// `litmask_wrapper.bin` cannot be read; these indicate a missing
/// `build.rs` invoking `litmask_build::emit()`.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let lit = match parse_string_literal(input, MACRO_NAME) {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };

    let (plaintext, kind) = match lit {
        StringLiteral::Str(s) => (s.value().into_bytes(), WeakKind::Str),
        StringLiteral::ByteStr(b) => (b.value(), WeakKind::Bytes),
        StringLiteral::CStr(c) => (c.value().into_bytes(), WeakKind::CStr),
    };

    let mut wrapper = load_out_dir_artifact::<WRAPPER_LEN>("litmask_wrapper.bin");
    let mut weak_key = derive_weak_xor_key(&wrapper);
    wrapper.zeroize();
    let encoded = xor_cycle(&plaintext, &weak_key);
    weak_key.zeroize();
    let encoded_lit = byte_string_literal(&encoded);
    let encoded_len = encoded.len();

    let obf_ident = syn::Ident::new("__WEAK_OBF", proc_macro2::Span::mixed_site());
    let cache_ident = syn::Ident::new("__WEAK_CACHE", proc_macro2::Span::mixed_site());

    match kind {
        WeakKind::Str => quote! {
            {
                const #obf_ident: &[u8; #encoded_len] = #encoded_lit;
                static #cache_ident: ::litmask::__internal::WeakCell =
                    ::litmask::__internal::WeakCell::new();
                ::litmask::__internal::__weak_decode(
                    #obf_ident,
                    ::litmask::__wrapper_bytes!(),
                    &#cache_ident,
                )
            }
        },
        WeakKind::Bytes => quote! {
            {
                const #obf_ident: &[u8; #encoded_len] = #encoded_lit;
                static #cache_ident: ::litmask::__internal::WeakByteCell =
                    ::litmask::__internal::WeakByteCell::new();
                ::litmask::__internal::__weak_decode_bytes(
                    #obf_ident,
                    ::litmask::__wrapper_bytes!(),
                    &#cache_ident,
                )
            }
        },
        WeakKind::CStr => quote! {
            {
                const #obf_ident: &[u8; #encoded_len] = #encoded_lit;
                ::litmask::__weak_decode_cstr_call!(#obf_ident, ::litmask::__wrapper_bytes!())
            }
        },
    }
    .into()
}
