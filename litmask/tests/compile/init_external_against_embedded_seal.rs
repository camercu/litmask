//! `init!(<provider>)` is the External-tier form. It is valid only when
//! the build sealed the `external` tier. The litmask crate's own
//! `build.rs` seals the default `embedded` tier, and that
//! `LITMASK_SEAL_TIER` rustc-env leaks into the trybuild subprocess, so
//! the External form here mismatches the sealed tier and fails at
//! expansion with a §1.9.6 `init! tier-mismatch` — before `some_provider`
//! is ever resolved. The matching positive (`external` seal accepts the
//! form) is exercised by the e2e fixture crate, not here.

use litmask::init;

fn main() {
    let _ = init!(some_provider);
}
