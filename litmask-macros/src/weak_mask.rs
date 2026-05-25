//! `weak_mask!` proc-macro: XOR a string literal against the per-build
//! encrypted-`mask_key` wrapper bytes at compile time and expand to a
//! cached-on-first-use decode that returns `&'static str`.
//!
//! Weaker than [`crate::mask::expand`]: no AEAD, and the XOR key
//! (the wrapper) lives in the same binary as the obfuscated bytes, so a
//! disassembler-equipped attacker recovers the plaintext trivially.
//! Use only for non-secret strings that need `strings(1)` protection
//! and must be readable before `init!()` runs (env-var names,
//! default file paths).
//!
//! Works under `no_std + alloc`. The per-call-site cache is the
//! `litmask::__internal::WeakCell` shim, which resolves to
//! `std::sync::OnceLock<String>` under the `std` feature and
//! `once_cell::race::OnceBox<String>` under `no_std + alloc`. Same
//! observable contract either way; the macro emits one shape.

use proc_macro::TokenStream;
use quote::quote;
use syn::{LitStr, parse_macro_input};
use zeroize::Zeroize;

use litmask_internal::{WRAPPER_LEN, xor_cycle};

use crate::common::{byte_array_token, load_out_dir_artifact};

/// Implementation of the `#[proc_macro] weak_mask` entry point.
///
/// # Panics
///
/// Panics at proc-macro expansion time if `OUT_DIR` is unset or
/// `litmask_wrapper.bin` cannot be read; these indicate a missing
/// `build.rs` invoking `litmask_build::emit()`.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let value = parse_macro_input!(input as LitStr).value();

    // The wrapper is per-build random ciphertext; using it as the XOR
    // key removes any fixed litmask byte signature from the encoded
    // output.
    let mut wrapper = load_out_dir_artifact::<WRAPPER_LEN>("litmask_wrapper.bin");
    let encoded = xor_cycle(value.as_bytes(), &wrapper);
    wrapper.zeroize();
    let encoded_lit = byte_array_token(&encoded);
    let encoded_len = encoded.len();

    // Hygienic identifiers — `mixed_site` keeps the const + static
    // invisible to the caller's identifier namespace, so a user with
    // their own `__WEAK_OBF` or `__WEAK_CACHE` in scope doesn't
    // collide.
    let obf_ident = syn::Ident::new("__WEAK_OBF", proc_macro2::Span::mixed_site());
    let cache_ident = syn::Ident::new("__WEAK_CACHE", proc_macro2::Span::mixed_site());

    quote! {
        {
            const #obf_ident: &[u8; #encoded_len] = &#encoded_lit;
            static #cache_ident: ::litmask::__internal::WeakCell =
                ::litmask::__internal::WeakCell::new();
            ::litmask::__internal::__weak_decode(
                #obf_ident,
                ::litmask::__wrapper_bytes!(),
                &#cache_ident,
            )
        }
    }
    .into()
}
