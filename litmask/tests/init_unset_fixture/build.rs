//! Intentionally does NOT run `litmask_build::emit()`, so
//! `LITMASK_SEAL_TIER` stays unset and the `init!()` in `main.rs` must
//! emit the §1.9.6 "unset" compile error.
//!
//! The `rerun-if-env-changed` line makes cargo treat `LITMASK_SEAL_TIER`
//! as a tracked input to this crate's compilation. A proc-macro's
//! `std::env::var` read is otherwise invisible to cargo's fingerprint, so
//! without this an artifact compiled once while the tag happened to leak
//! in from a parent build would be served stale instead of re-expanding
//! `init!()` against the (now absent) tag.

fn main() {
    println!("cargo:rerun-if-env-changed=LITMASK_SEAL_TIER");
}
