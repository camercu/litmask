//! Benchmark fixture: 10 `mask!` call sites and a plain-literal twin,
//! sealed under the External tier (`build.rs` + `LITMASK_UNLOCK_KEY`).
//!
//! The runtime benchmarks drive [`masked`]; [`PLAINTEXTS`] is the
//! `~0`-cost baseline (plain `&'static str`) and the oracle the roundtrip
//! test checks against. Keep the two in lock-step order.

use litmask::mask;

/// The plaintexts behind each masked literal, same order as [`masked`].
/// Doubles as the plain-literal baseline for the benchmarks.
pub const PLAINTEXTS: [&str; 10] = [
    "alpha-roundtrip-canary-0",
    "bravo-roundtrip-canary-1",
    "charlie-roundtrip-canary-2",
    "delta-roundtrip-canary-3",
    "echo-roundtrip-canary-4",
    "foxtrot-roundtrip-canary-5",
    "golf-roundtrip-canary-6",
    "hotel-roundtrip-canary-7",
    "india-roundtrip-canary-8",
    "juliet-roundtrip-canary-9",
];

/// Decrypt all 10 masked literals. `mask!` returns an owned `String`
/// (AEAD-open into a heap buffer — that allocation is intrinsic to every
/// access and is part of litmask's real cost), so these are collected
/// directly with no extra copy. Exercises every call site for the
/// roundtrip test; the benchmark times a single `mask!` instead.
#[must_use]
pub fn masked() -> Vec<String> {
    vec![
        mask!("alpha-roundtrip-canary-0"),
        mask!("bravo-roundtrip-canary-1"),
        mask!("charlie-roundtrip-canary-2"),
        mask!("delta-roundtrip-canary-3"),
        mask!("echo-roundtrip-canary-4"),
        mask!("foxtrot-roundtrip-canary-5"),
        mask!("golf-roundtrip-canary-6"),
        mask!("hotel-roundtrip-canary-7"),
        mask!("india-roundtrip-canary-8"),
        mask!("juliet-roundtrip-canary-9"),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use litmask::{EnvVarProvider, init};

    // Proves the new bench workspace seals + unlocks the External tier
    // correctly before any timing number is trusted. Requires the same
    // `LITMASK_UNLOCK_KEY` at build (seal) and run (EnvVarProvider).
    #[test]
    fn masked_roundtrips_to_plaintexts() {
        init!(EnvVarProvider::default()).expect("External-tier unlock");
        assert_eq!(masked(), PLAINTEXTS);
    }
}
