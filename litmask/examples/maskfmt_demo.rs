//! Demonstrates `maskfmt!`. The fragment phrases between the
//! placeholders are unique enough that the integration test scrub
//! can assert they are absent from the compiled release binary.

use litmask::maskfmt;

fn main() {
    let user_id = 42;
    let amount = 99.95;
    let s = maskfmt!(
        "saffron-koala-2b8e1c={} amber-otter-4f3d27={:.2}",
        user_id,
        amount
    );
    println!("{s}");
}
