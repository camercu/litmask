//! Unset-tier fixture: calls `init!()` in a crate whose build.rs never
//! runs `litmask_build::emit()`, so `LITMASK_SEAL_TIER` is absent. The
//! `init!` proc-macro emits a §1.9.6 compile error naming the unset tag,
//! so this crate is expected NOT to compile. The tier check
//! short-circuits before any `OUT_DIR` wrapper artifact is needed.

fn main() {
    let _ = litmask::init!();
}
