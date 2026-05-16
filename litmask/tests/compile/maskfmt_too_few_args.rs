//! §2.2.3.2: `maskfmt!` rejects placeholders that reference an
//! argument index beyond the supplied positional list.

use litmask::maskfmt;

fn main() {
    let _ = maskfmt!("{} {} {}", "only-one");
}
