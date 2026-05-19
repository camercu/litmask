//! `mask_include_str!` proc-macro: read a UTF-8 file at proc-macro
//! time, AEAD-encrypt the contents, and expand to a runtime decrypt
//! call returning `String`. Path resolution is relative to the
//! consumer crate's `CARGO_MANIFEST_DIR`, matching the existing
//! `mask!(include_str!(...))` shim's behaviour.

use std::fs;
use std::path::PathBuf;

use proc_macro::TokenStream;
use syn::LitStr;

use crate::common::{MaskKind, mask_plaintext};

const NON_LITERAL_MSG: &str = "mask_include_str! requires a string literal path";
const READ_FAILURE_PREFIX: &str = "mask_include_str!: could not read";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let path_lit: LitStr = match syn::parse(input) {
        Ok(lit) => lit,
        Err(e) => {
            return syn::Error::new(e.span(), NON_LITERAL_MSG)
                .to_compile_error()
                .into();
        }
    };
    let path_str = path_lit.value();
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("mask_include_str!: CARGO_MANIFEST_DIR not set");
    let resolved = PathBuf::from(manifest_dir).join(&path_str);
    let content = match fs::read_to_string(&resolved) {
        Ok(c) => c,
        Err(e) => {
            // Error message echoes the user's literal path, not the
            // resolved absolute path, so trybuild snapshots stay
            // portable and local FS layout doesn't leak into
            // diagnostics.
            return syn::Error::new(
                path_lit.span(),
                format!("{READ_FAILURE_PREFIX} `{path_str}`: {e}"),
            )
            .to_compile_error()
            .into();
        }
    };
    mask_plaintext(content.into_bytes(), path_lit.span(), MaskKind::Str).into()
}
