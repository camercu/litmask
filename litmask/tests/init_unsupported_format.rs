//! Init-time authenticated-format-version check (§1.9.2, §2.7.1). The
//! wrapper's format-version byte lives inside the AEAD plaintext
//! (`version_byte || mask_key`), so it is validated only AFTER the tag
//! verifies. A wrapper that decrypts cleanly but carries an unknown
//! version byte MUST surface as `InitError::UnsupportedFormat`, not be
//! swallowed as the generic `Decryption` variant.
//!
//! There is no cipher-id byte on the wire — the cipher is selected at
//! compile time (`CURRENT_CIPHER`), so a cipher mismatch is not
//! representable and has no runtime check.
//!
//! Lives in a dedicated integration-test binary, and every test here
//! expects an `Err`, so none calls `try_set` — the process-global
//! `mask_key` cell stays unset across the whole binary and the
//! `is_set` early-return in `__init_with_wrapper` never masks a
//! rejection as an idempotent `Ok(())`. The happy path is covered by
//! other integration binaries (e.g. `file_provider`).

mod common;

use litmask::__internal::__init_with_wrapper;
use litmask::{__wrapper_bytes, InitError};
use litmask_internal::{
    CURRENT_CIPHER, KEY_LEN, NONCE_LEN, WRAPPER_BODY_LEN, WRAPPER_LEN, WRAPPER_PLAINTEXT_LEN,
    aead_encrypt, assemble_wrapper, base64url,
};

/// Forge a wrapper that AEAD-authenticates under the build's
/// `unlock_key` but seals `version_byte || mask_key` with an arbitrary
/// `version_byte`. Used to exercise the post-decrypt version check in
/// isolation from tag verification.
fn forge_wrapper_with_version(version_byte: u8) -> [u8; WRAPPER_LEN] {
    let key_b64 = common::read_unlock_key(&common::self_config_path());
    let unlock_key: [u8; KEY_LEN] = base64url::decode(&key_b64)
        .expect("unlock_key is base64url")
        .try_into()
        .expect("unlock_key is KEY_LEN bytes");

    let nonce = [0x42u8; NONCE_LEN];
    let mut plaintext = [0u8; WRAPPER_PLAINTEXT_LEN];
    plaintext[0] = version_byte;
    // The masked-key payload is irrelevant to the version check.

    let body_vec = aead_encrypt(CURRENT_CIPHER, &unlock_key, &nonce, &plaintext)
        .expect("aead_encrypt under unlock_key");
    let body: &[u8; WRAPPER_BODY_LEN] = body_vec.as_slice().try_into().expect("body length");
    assemble_wrapper(&nonce, body)
}

#[test]
fn init_returns_unsupported_format_for_authenticated_unknown_version_0x99() {
    let fabricated = forge_wrapper_with_version(0x99);
    let key = common::read_unlock_key(&common::self_config_path());
    let provider = common::TestKeyProvider { key_b64: key };
    let result = __init_with_wrapper(provider, &fabricated);
    assert!(
        matches!(result, Err(InitError::UnsupportedFormat)),
        "expected Err(InitError::UnsupportedFormat), got {result:?}",
    );
}

#[test]
fn init_returns_unsupported_format_for_authenticated_unknown_version_0xfe() {
    // A second unknown value pins the whole byte space, not one value.
    let fabricated = forge_wrapper_with_version(0xFE);
    let key = common::read_unlock_key(&common::self_config_path());
    let provider = common::TestKeyProvider { key_b64: key };
    let result = __init_with_wrapper(provider, &fabricated);
    assert!(matches!(result, Err(InitError::UnsupportedFormat)));
}

#[test]
fn init_returns_decryption_for_tampered_nonce() {
    // Flipping the cleartext nonce breaks AEAD authentication, so the
    // version byte is never reached — this is the generic `Decryption`
    // path, distinct from `UnsupportedFormat`.
    let mut fabricated = *__wrapper_bytes!();
    fabricated[0] ^= 0xFF;
    let key = common::read_unlock_key(&common::self_config_path());
    let provider = common::TestKeyProvider { key_b64: key };
    let result = __init_with_wrapper(provider, &fabricated);
    assert!(
        matches!(result, Err(InitError::Decryption)),
        "expected Err(InitError::Decryption), got {result:?}",
    );
}
