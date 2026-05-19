//! `mask_include_bytes!` proc-macro: read a file as raw bytes at
//! proc-macro time, AEAD-encrypt the contents, and expand to a
//! runtime decrypt call returning `Vec<u8>`. Path resolution
//! mirrors `mask_include_str!` — relative to the consumer crate's
//! `CARGO_MANIFEST_DIR`.

use std::fs;
use std::path::PathBuf;

use proc_macro::TokenStream;
use syn::LitStr;
use syn::spanned::Spanned;

use crate::common::{MaskKind, mask_plaintext};

const NON_LITERAL_MSG: &str = "mask_include_bytes! requires a string literal path";
const READ_FAILURE_PREFIX: &str = "mask_include_bytes!: could not read";

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
        .expect("mask_include_bytes!: CARGO_MANIFEST_DIR not set");
    let resolved = PathBuf::from(manifest_dir).join(&path_str);
    let content = match fs::read(&resolved) {
        Ok(c) => c,
        Err(e) => {
            return syn::Error::new(
                path_lit.span(),
                format!("{READ_FAILURE_PREFIX} `{path_str}`: {e}"),
            )
            .to_compile_error()
            .into();
        }
    };
    mask_plaintext(content, path_lit.span(), MaskKind::Bytes).into()
}
