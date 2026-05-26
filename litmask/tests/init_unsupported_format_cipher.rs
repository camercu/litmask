//! Init-time format-version / cipher-id checks (§1.9.2, §1.12.2,
//! §2.7.1). A wrapper whose header byte 0 isn't `0x01` MUST surface
//! as `InitError::UnsupportedFormat`; a wrapper whose cipher-id
//! byte doesn't match the runtime's compiled cipher MUST surface
//! as `InitError::UnsupportedCipher`. Both checks happen BEFORE
//! AEAD decryption so a fabricated header byte does not get
//! swallowed as the generic `Decryption` variant.
//!
//! Lives in a dedicated integration-test binary so the
//! process-global `mask_key` cell starts unset on every test run —
//! see the sibling `init_wrapper_tamper` rationale.

mod common;

use litmask::__internal::__init_with_wrapper;
use litmask::{__wrapper_bytes, InitError};

#[test]
fn init_returns_unsupported_format_for_byte_0x99_at_offset_0() {
    let mut fabricated = *__wrapper_bytes!();
    fabricated[0] = 0x99; // format byte (offset 0) — unknown version

    let key = common::read_unlock_key(&common::self_config_path());
    let provider = common::TestKeyProvider { key_b64: key };
    let result = __init_with_wrapper(provider, &fabricated);
    assert!(
        matches!(result, Err(InitError::UnsupportedFormat)),
        "expected Err(InitError::UnsupportedFormat), got {result:?}",
    );
}

#[test]
#[cfg_attr(
    all(feature = "chacha20-poly1305", feature = "aes-gcm"),
    ignore = "dual-cipher build accepts both cipher bytes; mismatch only testable in single-cipher mode"
)]
fn init_returns_unsupported_cipher_for_mismatched_cipher_byte() {
    let mut fabricated = *__wrapper_bytes!();
    // Flip the cipher byte to the OPPOSITE of what the runtime
    // expects. Under chacha-only: flip to 0x02. Under aes-only:
    // flip to 0x01.
    #[cfg(feature = "chacha20-poly1305")]
    {
        fabricated[1] = 0x02;
    }
    #[cfg(feature = "aes-gcm")]
    {
        fabricated[1] = 0x01;
    }
    let key = common::read_unlock_key(&common::self_config_path());
    let provider = common::TestKeyProvider { key_b64: key };
    let result = __init_with_wrapper(provider, &fabricated);
    assert!(
        matches!(result, Err(InitError::UnsupportedCipher)),
        "expected Err(InitError::UnsupportedCipher), got {result:?}",
    );
}

#[test]
fn init_returns_unsupported_format_for_unknown_byte_0xfe() {
    // Two distinct values both unknown to FormatVersion — pin the
    // entire byte space, not just one value.
    let mut fabricated = *__wrapper_bytes!();
    fabricated[0] = 0xFE;
    let key = common::read_unlock_key(&common::self_config_path());
    let provider = common::TestKeyProvider { key_b64: key };
    let result = __init_with_wrapper(provider, &fabricated);
    assert!(matches!(result, Err(InitError::UnsupportedFormat)));
}

#[test]
fn matching_format_and_cipher_continues_to_succeed() {
    // The unmodified wrapper of the build is, by construction,
    // valid for the build's runtime. Calling init on it must
    // succeed (or be idempotent if a previous test in this binary
    // already initialized).
    let key = common::read_unlock_key(&common::self_config_path());
    let provider = common::TestKeyProvider { key_b64: key };
    let result = __init_with_wrapper(provider, __wrapper_bytes!());
    assert!(result.is_ok(), "valid wrapper must init, got {result:?}");
}
