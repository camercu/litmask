//! §2.2.3.2: `maskfmt!` mirrors `format!`'s check that each named
//! argument's name appears at most once. The rejection surfaces the
//! duplicate name in the diagnostic so the caller can spot it,
//! rather than leaking proc-macro-internal `maskfmt_arg_N`
//! identifier names through `unused_variables`.

use litmask::maskfmt;

fn main() {
    let _ = maskfmt!("{x}", x = 1, x = 2);
}
