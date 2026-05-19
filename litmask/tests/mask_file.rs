//! `mask_file!()` masks the canonicalized source-file path
//! (`CARGO_MANIFEST_DIR`-relative) at proc-macro time. Verifying
//! reproducibility across filesystem checkouts is a property of
//! the canonicalization tests in `litmask-macros/src/common.rs`;
//! here we just confirm the round-trip and the canonicalized
//! shape.

mod common;

use litmask::mask_file;

#[test]
fn mask_file_returns_canonicalized_path() {
    common::init_once();
    let s: String = mask_file!();
    assert!(
        s.ends_with("tests/mask_file.rs"),
        "expected canonicalized path ending with tests/mask_file.rs, got {s:?}",
    );
    // Canonicalization stripped CARGO_MANIFEST_DIR, so the result
    // is relative — no leading absolute path.
    assert!(
        !s.starts_with('/'),
        "expected manifest-dir-relative path, got {s:?}",
    );
}
