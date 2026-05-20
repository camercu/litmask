//! `mask_include_str!` proc-macro: read a UTF-8 file at proc-macro
//! time, AEAD-encrypt the contents, and expand to a runtime decrypt
//! call returning `String`. Path resolution is relative to the
//! consumer crate's `CARGO_MANIFEST_DIR`, matching the existing
//! `mask!(include_str!(...))` shim's behaviour.

use std::fs;

use proc_macro::TokenStream;

use crate::common::{mask_str, read_lit_str_path};

const MACRO_NAME: &str = "mask_include_str";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    match read_lit_str_path(input, MACRO_NAME, |p| fs::read_to_string(p)) {
        Ok((path_lit, content)) => mask_str(path_lit.span(), content.into_bytes()).into(),
        Err(e) => e.to_compile_error().into(),
    }
}
