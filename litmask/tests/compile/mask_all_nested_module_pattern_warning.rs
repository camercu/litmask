//! A pattern-position literal inside a *nested* `mod` under
//! `#[mask_all]` emits its deprecation warning through the **inner**
//! module's `__litmask_skips` submodule, not the outer module's. The
//! anchor path follows the originating mod so a `cargo build` line
//! number lands the reader near the offending literal.
//!
//! `#![deny(deprecated)]` upgrades the warning to an error so
//! trybuild snapshots the path. Pre-fix the walker pooled every skip
//! into the outer module, so the constant resolved at
//! `fixture::__litmask_skips::_LITMASK_SKIP_0` instead of
//! `fixture::inner::__litmask_skips::_LITMASK_SKIP_0`.

#![deny(deprecated)]

use litmask::mask_all;

#[mask_all]
mod fixture {
    pub mod inner {
        pub fn classify(x: &str) -> u32 {
            match x {
                "trigger" => 1,
                _ => 0,
            }
        }
    }
}

fn main() {
    let _ = fixture::inner::classify("trigger");
}
