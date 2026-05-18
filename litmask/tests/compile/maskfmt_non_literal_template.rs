//! `maskfmt!`'s first argument must be a string literal. The
//! compile error message must include the substring "maskfmt!
//! requires a string literal template at the call site; use `mask!`
//! to decrypt a runtime string".

use litmask::maskfmt;

fn main() {
    let template = "x={}";
    let _ = maskfmt!(template, 1);
}
