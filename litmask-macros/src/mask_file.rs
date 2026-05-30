//! `mask_file!` proc-macro: read the call site's source path via
//! `proc_macro::Span::call_site().file()` at proc-macro time,
//! AEAD-encrypt, and expand to a runtime decrypt call returning
//! `String`.
//!
//! The returned value mirrors stdlib `file!()` exactly — `Span::file()`
//! yields the same path `file!()` would at the same span — but masked
//! so the source path never lands in `.rodata` as plaintext. The
//! `CARGO_MANIFEST_DIR`-stripping in [`crate::common::mask_str`]'s
//! nonce derivation is a separate, reproducibility-only concern and
//! does not touch the value handed back to the caller.

use proc_macro::TokenStream;

use crate::common::{FailTag, compile_error, mask_str};

const MACRO_NAME: &str = "mask_file";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    if let Some(tt) = input.into_iter().next() {
        // Anchor the diagnostic at the offending token so the user
        // sees the unwanted argument underlined, not the macro name.
        return compile_error(
            tt.span().into(),
            MACRO_NAME,
            FailTag::ArgsNotAllowed,
            "takes no arguments",
        )
        .to_compile_error()
        .into();
    }
    let file = proc_macro::Span::call_site().file();
    mask_str(proc_macro2::Span::call_site(), file.into_bytes()).into()
}
