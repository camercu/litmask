//! Verifies that init-time AEAD authentication failure surfaces as
//! `Err(InitError::Decryption)` rather than panicking. Lives in its own
//! integration-test binary so the process-global mask-key store starts
//! empty; a binary that already cached this wrapper (via a `mask!()` or a
//! govern `init!`) would short-circuit `__init_with_wrapper`'s
//! already-cached early return before the tampered path runs.

mod common;

use litmask::__internal::__init_with_wrapper;
use litmask::{__wrapper_bytes, InitError};

#[test]
fn init_returns_decryption_error_on_tampered_wrapper() {
    // Wrapper layout: byte 0 = format version, byte 1 = cipher id,
    // bytes 2..14 = nonce, bytes 14..62 = AEAD body. Flipping a byte
    // inside the body keeps the header valid, so the parse step
    // succeeds and AEAD authentication is what fails — the very
    // signal Decryption is meant to surface.
    let mut tampered = *__wrapper_bytes!();
    tampered[20] ^= 0x01;

    let key = common::read_unlock_key(&common::self_config_path());
    let provider = common::TestKeyProvider { key_b64: key };

    let result = __init_with_wrapper(provider, &tampered);
    assert!(
        matches!(result, Err(InitError::Decryption)),
        "expected Err(InitError::Decryption), got {result:?}"
    );
}
