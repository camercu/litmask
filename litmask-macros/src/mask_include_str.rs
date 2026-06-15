//! `mask_include_str!` proc-macro: read a UTF-8 file at proc-macro
//! time, AEAD-encrypt the contents, and expand to a runtime decrypt
//! call returning `String`. Path resolution is relative to the source
//! file containing the invocation, matching stdlib `include_str!`.

use std::fs;

use proc_macro::TokenStream;

use crate::common::{mask_str, read_lit_str_path};

const MACRO_NAME: &str = "mask_include_str";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    // Closure (not bare `fs::read_to_string`) is load-bearing: the
    // bare fn item monomorphizes to one concrete lifetime and fails
    // the higher-ranked `for<'a> Fn(&'a Path)` bound on `reader`.
    match read_lit_str_path(input, MACRO_NAME, |p| fs::read_to_string(p)) {
        Ok((path_lit, content)) => mask_str(path_lit.span(), content.into_bytes()).into(),
        Err(e) => e.to_compile_error().into(),
    }
}
