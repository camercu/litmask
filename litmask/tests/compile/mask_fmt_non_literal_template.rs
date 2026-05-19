//! `mask_fmt!`'s first argument must be a string literal. The
//! compile error message must include the substring "mask_fmt!
//! requires a string literal template at the call site; use `mask!`
//! to decrypt a runtime string".

use litmask::mask_fmt;

fn main() {
    let template = "x={}";
    let _ = mask_fmt!(template, 1);
}
