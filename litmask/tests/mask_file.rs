//! `mask_file!()` masks the call site's source-file path at
//! proc-macro time, returning the same value stdlib `file!()` would
//! at the same span — only masked so the path never lands in
//! `.rodata` as plaintext. The scrub test in `tests/example_scrub.rs`
//! locks the absence half; here we lock exact stdlib parity.

mod common;

use litmask::mask_file;

#[test]
fn mask_file_matches_stdlib_file() {
    let s: String = mask_file!();
    assert_eq!(s, file!());
}
