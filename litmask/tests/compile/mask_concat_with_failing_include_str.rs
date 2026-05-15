//! When an `include_str!` nested inside `concat!` fails to read the
//! file, the user must see the underlying file-not-found message —
//! NOT the generic "concat! arguments must be..." substring. Locks
//! the resolve_concat error pass-through behavior.

use litmask::mask;

fn main() {
    let _ = mask!(concat!(
        include_str!("examples/fixtures/does_not_exist.txt"),
        "tail"
    ));
}
