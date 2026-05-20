//! `mask_include_bytes!` proc-macro: read a file as raw bytes at
//! proc-macro time, AEAD-encrypt the contents, and expand to a
//! runtime decrypt call returning `Vec<u8>`. Path resolution
//! mirrors `mask_include_str!` — relative to the consumer crate's
//! `CARGO_MANIFEST_DIR`.

use std::fs;
use std::path::PathBuf;

use proc_macro::TokenStream;

use crate::common::{FailTag, compile_error, mask_bytes, require_lit_str};

const MACRO_NAME: &str = "mask_include_bytes";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let path_lit = match require_lit_str(input, MACRO_NAME, "requires a string literal path") {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };
    let path_str = path_lit.value();
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("mask_include_bytes!: CARGO_MANIFEST_DIR not set");
    let resolved = PathBuf::from(manifest_dir).join(&path_str);
    let content = match fs::read(&resolved) {
        Ok(c) => c,
        Err(e) => {
            return compile_error(
                path_lit.span(),
                MACRO_NAME,
                FailTag::ReadFailure,
                &format!("could not read `{path_str}`: {e}"),
            )
            .to_compile_error()
            .into();
        }
    };
    mask_bytes(path_lit.span(), content).into()
}
