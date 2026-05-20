//! `mask_include_bytes!` proc-macro: read a file as raw bytes at
//! proc-macro time, AEAD-encrypt the contents, and expand to a
//! runtime decrypt call returning `Vec<u8>`. Path resolution
//! mirrors `mask_include_str!` — relative to the consumer crate's
//! `CARGO_MANIFEST_DIR`.

use std::fs;

use proc_macro::TokenStream;

use crate::common::{mask_bytes, read_lit_str_path};

const MACRO_NAME: &str = "mask_include_bytes";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    match read_lit_str_path(input, MACRO_NAME, |p| fs::read(p)) {
        Ok((path_lit, content)) => mask_bytes(path_lit.span(), content).into(),
        Err(e) => e.to_compile_error().into(),
    }
}
