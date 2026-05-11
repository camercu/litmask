//! Deterministic nonce derivation (BLAKE3-keyed-hash, first 12 bytes).
//!
//! The functions here implement the spec-canonical algorithms (§1.5.2,
//! §1.7.3). Task 5's proc-macro uses a counter-based variant in
//! `litmask-macros` because stable Rust's `proc_macro::Span` doesn't
//! expose file/line/column accessors; the algorithms here remain the
//! authoritative reference for the runtime decrypt path (wrapper) and
//! for unit-test coverage of the call-site form.
#![allow(dead_code)]
//!
//! Two derivations exist (§1.5.2 and §1.7.3):
//!
//! - [`call_site`] — for per-string ciphertext blobs. Keyed by the
//!   build seed, message is `"litmask-nonce" || file || ":" || line ||
//!   ":" || column`. Distinct call sites get distinct nonces with
//!   overwhelming probability; same source layout + same seed reproduces
//!   the same nonces exactly.
//! - [`wrapper`] — for the encrypted `mask_key` wrapper. Keyed by the
//!   build seed, message is the fixed string `"litmask-mask-key-nonce"`.
//!
//! BLAKE3 is used as a keyed PRF here. The 32-byte seed becomes the
//! key; the message domain-separator strings make the two derivations
//! independent even when the same seed is used.

use alloc::string::ToString;
use core::convert::TryInto;

/// Output length: 12 bytes — the AEAD nonce size shared by
/// ChaCha20-Poly1305 and AES-256-GCM.
pub const NONCE_LEN: usize = 12;

/// Domain-separator prefix for per-call-site nonces (§1.5.2).
const CALL_SITE_TAG: &[u8] = b"litmask-nonce";

/// Domain-separator string for the wrapper nonce (§1.7.3).
const WRAPPER_TAG: &[u8] = b"litmask-mask-key-nonce";

/// Derive the per-call-site nonce. `seed` is the 32-byte build seed.
///
/// # Panics
///
/// Never panics for any inputs; the BLAKE3 output is always ≥12 bytes.
#[must_use]
pub fn call_site(seed: &[u8; 32], file: &str, line: u32, column: u32) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(CALL_SITE_TAG);
    hasher.update(file.as_bytes());
    hasher.update(b":");
    hasher.update(line.to_string().as_bytes());
    hasher.update(b":");
    hasher.update(column.to_string().as_bytes());
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    bytes[..NONCE_LEN]
        .try_into()
        .expect("blake3 output ≥12 bytes")
}

/// Derive the encrypted-`mask_key`-wrapper nonce. `seed` is the 32-byte
/// build seed.
///
/// # Panics
///
/// Never panics for any inputs.
#[must_use]
pub fn wrapper(seed: &[u8; 32]) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(WRAPPER_TAG);
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    bytes[..NONCE_LEN]
        .try_into()
        .expect("blake3 output ≥12 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::collections::BTreeSet;

    const SEED_A: [u8; 32] = [0xaa; 32];
    const SEED_B: [u8; 32] = [0xbb; 32];

    #[test]
    fn determinism_same_inputs_same_nonce() {
        let a = call_site(&SEED_A, "src/lib.rs", 42, 7);
        let b = call_site(&SEED_A, "src/lib.rs", 42, 7);
        assert_eq!(a, b);
    }

    #[test]
    fn uniqueness_across_locations() {
        // Distinct file/line/column triples should produce distinct nonces
        // across a moderate sample. With BLAKE3's 96-bit output any
        // collision in a sample of 1024 is astronomically unlikely.
        let mut seen = BTreeSet::new();
        let mut total = 0;
        for line in 0..32u32 {
            for column in 0..32u32 {
                let nonce = call_site(&SEED_A, "src/lib.rs", line, column);
                seen.insert(nonce);
                total += 1;
            }
        }
        assert_eq!(
            seen.len(),
            total,
            "found a nonce collision in {total} sites"
        );
    }

    #[test]
    fn independence_seed_change_changes_nonce() {
        let a = call_site(&SEED_A, "src/lib.rs", 1, 0);
        let b = call_site(&SEED_B, "src/lib.rs", 1, 0);
        assert_ne!(a, b);
    }

    #[test]
    fn independence_call_sites_do_not_affect_each_other() {
        // Adding code AFTER line 10 only shifts line numbers for code
        // AFTER. The nonce at (file, 5, 0) is unchanged regardless of
        // how many sites at lines 11+ exist. This test mirrors that
        // semantics by demonstrating call_site(...) at (5, 0) is the
        // same regardless of what other inputs the caller derives.
        let pinned = call_site(&SEED_A, "src/lib.rs", 5, 0);
        for line in 11..100u32 {
            let _ignored = call_site(&SEED_A, "src/lib.rs", line, 0);
        }
        let pinned_again = call_site(&SEED_A, "src/lib.rs", 5, 0);
        assert_eq!(pinned, pinned_again);
    }

    #[test]
    fn wrapper_nonce_is_deterministic_and_seed_dependent() {
        let a = wrapper(&SEED_A);
        let aa = wrapper(&SEED_A);
        let b = wrapper(&SEED_B);
        assert_eq!(a, aa);
        assert_ne!(a, b);
    }

    #[test]
    fn wrapper_nonce_differs_from_call_site_nonce() {
        // Domain separators guarantee independence even at the same seed.
        let w = wrapper(&SEED_A);
        let cs = call_site(&SEED_A, "litmask-mask-key-nonce", 0, 0);
        assert_ne!(w, cs);
    }
}
