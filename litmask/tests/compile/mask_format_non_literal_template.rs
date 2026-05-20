//! `mask_format!`'s first argument must be a string literal. The
//! compile error message must include the substring "mask_format!
//! requires a string literal template at the call site; use `mask!`
//! to decrypt a runtime string".

use litmask::mask_format;

fn main() {
    let template = "x={}";
    let _ = mask_format!(template, 1);
}
