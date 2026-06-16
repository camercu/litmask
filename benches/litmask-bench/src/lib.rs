//! Benchmark fixture, sealed under the External tier (`build.rs` +
//! `LITMASK_UNLOCK_KEY`).
//!
//! Three plaintext sizes (16 / 256 / 4096 bytes) let the runtime
//! benchmarks plot decrypt cost against payload size. Each `masked_*`
//! returns the owned `String` that `mask_include_str!` produces — the
//! AEAD open *and* its heap allocation, both real per-access costs. The
//! `PLAIN_*` constants are the matching `&'static str` a no-litmask user
//! would write (zero work, zero alloc) and the oracle the roundtrip test
//! checks against.

use litmask::mask_include_str;

/// Decrypt the 16-byte masked payload. See module docs for what the
/// returned `String` includes.
#[must_use]
pub fn masked_16() -> String {
    mask_include_str!("../fixtures/lit_16.txt")
}

/// Decrypt the 256-byte masked payload.
#[must_use]
pub fn masked_256() -> String {
    mask_include_str!("../fixtures/lit_256.txt")
}

/// Decrypt the 4096-byte masked payload.
#[must_use]
pub fn masked_4096() -> String {
    mask_include_str!("../fixtures/lit_4096.txt")
}

/// Plain 16-byte baseline — what a no-litmask user writes.
pub const PLAIN_16: &str = include_str!("../fixtures/lit_16.txt");
/// Plain 256-byte baseline.
pub const PLAIN_256: &str = include_str!("../fixtures/lit_256.txt");
/// Plain 4096-byte baseline.
pub const PLAIN_4096: &str = include_str!("../fixtures/lit_4096.txt");

#[cfg(test)]
mod tests {
    use super::*;
    use litmask::{EnvVarProvider, init};

    // Proves the External-tier seal/unlock works for every payload size
    // before any timing number is trusted. Requires the same
    // `LITMASK_UNLOCK_KEY` at build (seal) and run (EnvVarProvider).
    #[test]
    fn masked_sizes_roundtrip_to_plaintext() {
        init!(EnvVarProvider::default()).expect("External-tier unlock");
        assert_eq!(masked_16(), PLAIN_16);
        assert_eq!(masked_256(), PLAIN_256);
        assert_eq!(masked_4096(), PLAIN_4096);
    }
}
