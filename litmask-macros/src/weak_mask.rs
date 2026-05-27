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
use syn::parse::{Parse, ParseStream};
use syn::{LitByteStr, LitCStr, LitStr};
use zeroize::Zeroize;

use litmask_internal::{WRAPPER_LEN, xor_cycle};

use crate::common::{FailTag, byte_array_token, compile_error, load_out_dir_artifact};

const MACRO_NAME: &str = "weak_mask";
const INVALID_LITERAL_DETAIL: &str = "accepts string, byte string, or C string literals";

enum WeakMaskInput {
    Str(Vec<u8>),
    Bytes(Vec<u8>),
    CStr(Vec<u8>),
}

impl Parse for WeakMaskInput {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        if input.peek(LitStr) {
            let lit: LitStr = input.parse()?;
            return Ok(Self::Str(lit.value().into_bytes()));
        }
        if input.peek(LitByteStr) {
            let lit: LitByteStr = input.parse()?;
            return Ok(Self::Bytes(lit.value()));
        }
        if input.peek(LitCStr) {
            let lit: LitCStr = input.parse()?;
            return Ok(Self::CStr(lit.value().into_bytes()));
        }
        Err(compile_error(
            input.span(),
            MACRO_NAME,
            FailTag::NonLiteral,
            INVALID_LITERAL_DETAIL,
        ))
    }
}

/// Implementation of the `#[proc_macro] weak_mask` entry point.
///
/// # Panics
///
/// Panics at proc-macro expansion time if `OUT_DIR` is unset or
/// `litmask_wrapper.bin` cannot be read; these indicate a missing
/// `build.rs` invoking `litmask_build::emit()`.
pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let parsed = syn::parse_macro_input!(input as WeakMaskInput);

    let plaintext = match &parsed {
        WeakMaskInput::Str(b) | WeakMaskInput::Bytes(b) | WeakMaskInput::CStr(b) => b,
    };

    let mut wrapper = load_out_dir_artifact::<WRAPPER_LEN>("litmask_wrapper.bin");
    let encoded = xor_cycle(plaintext, &wrapper);
    wrapper.zeroize();
    let encoded_lit = byte_array_token(&encoded);
    let encoded_len = encoded.len();

    let obf_ident = syn::Ident::new("__WEAK_OBF", proc_macro2::Span::mixed_site());
    let cache_ident = syn::Ident::new("__WEAK_CACHE", proc_macro2::Span::mixed_site());

    match parsed {
        WeakMaskInput::Str(_) => quote! {
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
        },
        WeakMaskInput::Bytes(_) => quote! {
            {
                const #obf_ident: &[u8; #encoded_len] = &#encoded_lit;
                static #cache_ident: ::litmask::__internal::WeakByteCell =
                    ::litmask::__internal::WeakByteCell::new();
                ::litmask::__internal::__weak_decode_bytes(
                    #obf_ident,
                    ::litmask::__wrapper_bytes!(),
                    &#cache_ident,
                )
            }
        },
        WeakMaskInput::CStr(_) => quote! {
            {
                const #obf_ident: &[u8; #encoded_len] = &#encoded_lit;
                ::litmask::__weak_decode_cstr_call!(#obf_ident, ::litmask::__wrapper_bytes!())
            }
        },
    }
    .into()
}
