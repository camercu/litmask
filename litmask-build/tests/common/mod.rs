//! Shared helpers for integration tests under `litmask-build/tests/`.
//!
//! Cargo treats `tests/common/mod.rs` specially: it is NOT compiled as
//! its own test binary, only `pub use`-able from sibling tests via
//! `mod common;`.

#![allow(dead_code)] // Some helpers are used by only a subset of integration tests.

use std::path::PathBuf;

/// The workspace root, derived from this crate's manifest directory.
///
/// The repo-hygiene guards in this directory read files outside their
/// own crate (the justfile, the CI workflow, other crates' sources), so
/// they all need it.
pub fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <root>/litmask-build
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}
