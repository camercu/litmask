//! E2E fixture for `mask_eprint!` / `mask_eprintln!` stderr capture tests.
//!
//! Each line is a known fixture string; the integration test in
//! `tests/mask_eprint.rs` runs this binary and asserts exact stderr match.

use litmask::{mask_eprint, mask_eprintln};

fn main() {
    mask_eprintln!("nothing-to-see-here-officer");
    mask_eprintln!("secret-level-{}", 7u32);
    mask_eprint!("end-of-transmission");
}
