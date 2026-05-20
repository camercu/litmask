//! `mask_include_str!` proc-macro: read a UTF-8 file at proc-macro
//! time, AEAD-encrypt the contents, and expand to a runtime decrypt
//! call returning `String`. Path resolution is relative to the
//! consumer crate's `CARGO_MANIFEST_DIR`, matching the existing
//! `mask!(include_str!(...))` shim's behaviour.

use std::fs;
use std::path::PathBuf;

use proc_macro::TokenStream;

use crate::common::{FailTag, MaskKind, compile_error, mask_plaintext, require_lit_str};

const MACRO_NAME: &str = "mask_include_str";

pub(crate) fn expand(input: TokenStream) -> TokenStream {
    let path_lit = match require_lit_str(input, MACRO_NAME, "requires a string literal path") {
        Ok(lit) => lit,
        Err(e) => return e.to_compile_error().into(),
    };
    let path_str = path_lit.value();
    let manifest_dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .expect("mask_include_str!: CARGO_MANIFEST_DIR not set");
    let resolved = PathBuf::from(manifest_dir).join(&path_str);
    // Error detail echoes the user's literal path, not the resolved
    // absolute path, so trybuild snapshots stay portable and local FS
    // layout doesn't leak into diagnostics.
    let content = match fs::read_to_string(&resolved) {
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
    mask_plaintext(content.into_bytes(), path_lit.span(), MaskKind::Str).into()
}
