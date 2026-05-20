//! `mask_format!` placeholder headers that aren't valid Rust identifiers
//! produce a typed compile error. Pre-fix, the proc-macro called
//! `syn::Ident::new("1abc", ...)` which panics, surfacing as an
//! opaque "proc-macro panicked" diagnostic instead of a helpful
//! "not a valid identifier" message.

use litmask::mask_format;

fn main() {
    let _ = mask_format!("{1abc}");
}
