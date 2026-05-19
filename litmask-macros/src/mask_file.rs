//! `mask_file!` proc-macro: read the call site's source path via
//! `proc_macro::Span::call_site().file()` at proc-macro time,
//! canonicalize against `CARGO_MANIFEST_DIR`, AEAD-encrypt, and
//! expand to a runtime decrypt call returning `String`.
//!
//! Mirrors stdlib `file!()` but produces a masked output: the raw
//! source path never lands in `.rodata` as plaintext.

use proc_macro::TokenStream;

use crate::common::{MaskKind, canonicalize_file_path, mask_plaintext};

const ARGS_MSG: &str = "mask_file! takes no arguments";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    if input.into_iter().next().is_some() {
        return syn::Error::new(proc_macro2::Span::call_site(), ARGS_MSG)
            .to_compile_error()
            .into();
    }
    let pm_span = proc_macro::Span::call_site();
    let raw_file = pm_span.file();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok();
    let file = canonicalize_file_path(raw_file, manifest_dir.as_deref());
    mask_plaintext(
        file.into_bytes(),
        proc_macro2::Span::call_site(),
        MaskKind::Str,
    )
    .into()
}
