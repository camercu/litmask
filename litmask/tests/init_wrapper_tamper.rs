//! Verifies that init-time AEAD authentication failure surfaces as
//! `Err(InitError::Decryption)` rather than panicking. Lives in its own
//! integration-test binary so the process-global mask-key store starts
//! empty; a binary that already cached this wrapper (via a `mask!()` or a
//! govern `init!`) would short-circuit `__init_with_wrapper`'s
//! already-cached early return before the tampered path runs.

mod common;

use litmask::__internal::__init_with_wrapper;
use litmask::InitError;
use litmask_internal::test_util::build_wrapper;
use litmask_internal::{KEY_LEN, base64url};

/// Self-contained test unlock key — the wrapper is forged under it and
/// the provider returns it, so the only cause of failure is the tamper.
const TEST_UNLOCK_KEY: [u8; KEY_LEN] = [0x5Au8; KEY_LEN];

#[test]
fn init_returns_decryption_error_on_tampered_wrapper() {
    // A valid wrapper (`nonce(12) || AEAD(version || mask_key)`) sealed
    // under TEST_UNLOCK_KEY, with one byte inside the AEAD body flipped
    // (index 20, past the 12-byte cleartext nonce). The header still
    // parses, so AEAD authentication is what fails under the correct
    // key — the very signal Decryption is meant to surface.
    let mut tampered = build_wrapper(&TEST_UNLOCK_KEY, &[0x22u8; KEY_LEN], &[0x33u8; KEY_LEN]);
    tampered[20] ^= 0x01;

    let provider = common::TestKeyProvider {
        key_b64: base64url::encode(&TEST_UNLOCK_KEY),
    };

    let result = __init_with_wrapper(provider, &tampered);
    assert!(
        matches!(result, Err(InitError::Decryption)),
        "expected Err(InitError::Decryption), got {result:?}"
    );
}
