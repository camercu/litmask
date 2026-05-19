//! `mask_fmt!` mirrors `format!`'s check that each named argument's
//! name appears at most once. The rejection surfaces the duplicate
//! name in the diagnostic so the caller can spot it, rather than
//! leaking proc-macro-internal `mask_fmt_arg_N` identifier names
//! through `unused_variables`.

use litmask::mask_fmt;

fn main() {
    let _ = mask_fmt!("{x}", x = 1, x = 2);
}
