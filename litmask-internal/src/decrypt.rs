//! AEAD decrypt path (functional core).
//!
//! Stateless decrypt operations plus higher-level pure helpers that
//! validate the wrapper format. Encryption is performed only at build
//! time (in the build-script helper) and at proc-macro expansion time;
//! the runtime crate decrypts only.

use core::fmt;

#[cfg(any(feature = "chacha20-poly1305", feature = "aes-gcm"))]
use zeroize::Zeroizing;

use crate::AeadError;
#[cfg(any(feature = "chacha20-poly1305", feature = "aes-gcm"))]
use crate::{FormatVersion, KEY_LEN, NONCE_LEN, TAG_LEN, WRAPPER_LEN, aead_decrypt, parse_wrapper};

/// Errors surfaced by pure decryption helpers. Converted to panics by
/// the runtime imperative shell; the typed form here lets unit tests
/// assert specific failure modes without `panic::catch_unwind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecryptError {
    /// The authenticated format-version byte (recovered from the AEAD
    /// plaintext) is not a version this build supports.
    UnsupportedFormat,
    /// Per-string blob is shorter than `NONCE_LEN + TAG_LEN`.
    BlobTooShort,
    /// AEAD authentication failed (wrong unlock or mask key, or
    /// tampered ciphertext).
    AuthenticationFailed,
    /// Decrypted payload length does not match the expected key size.
    InvalidPayloadLength,
}

impl fmt::Display for DecryptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormat => f.write_str("unsupported format version"),
            Self::BlobTooShort => f.write_str("encrypted data too short"),
            Self::AuthenticationFailed => f.write_str("authentication failed"),
            Self::InvalidPayloadLength => f.write_str("invalid decrypted payload length"),
        }
    }
}

impl From<AeadError> for DecryptError {
    fn from(_: AeadError) -> Self {
        Self::AuthenticationFailed
    }
}

/// Decrypt the embedded encrypted-`mask_key` wrapper.
///
/// Splits the cleartext nonce from the AEAD body, decrypts the body
/// with the build's compiled cipher ([`crate::CURRENT_CIPHER`]),
/// validates the authenticated format-version byte, and returns the
/// recovered `mask_key` bytes.
///
/// The cipher is not recorded on the wire: every wrapper in a binary is
/// sealed with the single cipher the build was compiled for, so a
/// wrapper produced under a different cipher fails the AEAD tag check
/// and surfaces as [`DecryptError::AuthenticationFailed`].
///
/// # Errors
///
/// Returns [`DecryptError::AuthenticationFailed`] when the AEAD tag
/// check fails (wrong `unlock_key`, tampered bytes, or cipher
/// mismatch), and [`DecryptError::UnsupportedFormat`] when the
/// authenticated version byte is unrecognized.
#[cfg(any(feature = "chacha20-poly1305", feature = "aes-gcm"))]
pub fn decrypt_wrapper(
    unlock_key: &[u8; KEY_LEN],
    wrapper: &[u8; WRAPPER_LEN],
) -> Result<[u8; KEY_LEN], DecryptError> {
    let parsed = parse_wrapper(wrapper);
    let plaintext = Zeroizing::new(aead_decrypt(
        crate::CURRENT_CIPHER,
        unlock_key,
        parsed.nonce,
        parsed.body,
    )?);
    // The AEAD plaintext is `version_byte || mask_key`. Validate the
    // authenticated version before trusting the key bytes.
    let (version_byte, key_bytes) = plaintext
        .split_first()
        .ok_or(DecryptError::InvalidPayloadLength)?;
    FormatVersion::try_from(*version_byte).map_err(|_| DecryptError::UnsupportedFormat)?;
    key_bytes
        .try_into()
        .map_err(|_| DecryptError::InvalidPayloadLength)
}

/// Decrypt a per-string blob.
///
/// `blob` is `nonce (12) || ciphertext (n) || tag (16)`. The blob
/// format does not record its own cipher id; every per-string blob
/// in a binary uses the same cipher as the wrapper, fixed at build
/// time to the value [`crate::CURRENT_CIPHER`] resolves to.
///
/// Not available under `all-ciphers` alone — that feature compiles
/// both backends without selecting `CURRENT_CIPHER`.
///
/// # Errors
///
/// Returns [`DecryptError::BlobTooShort`] when `blob` is shorter than
/// `NONCE_LEN + TAG_LEN`, and [`DecryptError::AuthenticationFailed`]
/// when the AEAD tag check fails.
#[cfg(any(feature = "chacha20-poly1305", feature = "aes-gcm"))]
pub fn decrypt_blob(
    mask_key: &[u8; KEY_LEN],
    blob: &[u8],
) -> Result<alloc::vec::Vec<u8>, DecryptError> {
    let (nonce, body) = blob
        .split_first_chunk::<NONCE_LEN>()
        .filter(|(_, body)| body.len() >= TAG_LEN)
        .ok_or(DecryptError::BlobTooShort)?;
    // The filter above guarantees `body` is at least TAG_LEN; assert
    // this so future changes to the split that drop the filter trip
    // a test-time panic instead of silently feeding a too-short body
    // to the AEAD primitive.
    debug_assert!(body.len() >= TAG_LEN);
    aead_decrypt(crate::CURRENT_CIPHER, mask_key, nonce, body).map_err(DecryptError::from)
}

#[cfg(all(test, feature = "chacha20-poly1305"))]
mod tests {
    use super::*;
    use crate::{
        CURRENT_CIPHER, CipherId, WRAPPER_BODY_LEN, WRAPPER_PLAINTEXT_LEN, aead_encrypt,
        assemble_wrapper, nonce_for_wrapper,
    };

    /// Encrypt `version_byte || mask_key` under `unlock_key` and
    /// assemble the wrapper. Mirrors what the build-script helper does,
    /// but stays purely in-memory so tests run sub-millisecond.
    fn build_wrapper(
        unlock_key: &[u8; KEY_LEN],
        mask_key: &[u8; KEY_LEN],
        seed: &[u8; KEY_LEN],
    ) -> [u8; WRAPPER_LEN] {
        let nonce = nonce_for_wrapper(seed);
        let mut plaintext = [0u8; WRAPPER_PLAINTEXT_LEN];
        plaintext[0] = FormatVersion::CURRENT.to_byte();
        plaintext[1..].copy_from_slice(mask_key);
        let body = aead_encrypt(CURRENT_CIPHER, unlock_key, &nonce, &plaintext).expect("encrypt");
        let body: &[u8; WRAPPER_BODY_LEN] = body
            .as_slice()
            .try_into()
            .expect("AEAD output of WRAPPER_PLAINTEXT_LEN plaintext is WRAPPER_BODY_LEN bytes");
        assemble_wrapper(&nonce, body)
    }

    fn build_blob(
        mask_key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> alloc::vec::Vec<u8> {
        let body = aead_encrypt(CURRENT_CIPHER, mask_key, nonce, plaintext).expect("encrypt");
        let mut blob = alloc::vec::Vec::with_capacity(NONCE_LEN + body.len());
        blob.extend_from_slice(nonce);
        blob.extend_from_slice(&body);
        blob
    }

    #[test]
    fn wrapper_round_trip_succeeds() {
        let unlock_key = [0x11u8; KEY_LEN];
        let mask_key = [0x22u8; KEY_LEN];
        let seed = [0x33u8; KEY_LEN];

        let wrapper = build_wrapper(&unlock_key, &mask_key, &seed);
        let recovered = decrypt_wrapper(&unlock_key, &wrapper).expect("round-trip");
        assert_eq!(recovered, mask_key);
    }

    #[test]
    fn wrapper_decrypt_rejects_wrong_unlock_key() {
        let unlock_key = [0x11u8; KEY_LEN];
        let mask_key = [0x22u8; KEY_LEN];
        let seed = [0x33u8; KEY_LEN];
        let wrapper = build_wrapper(&unlock_key, &mask_key, &seed);

        let wrong_unlock = [0x99u8; KEY_LEN];
        let err = decrypt_wrapper(&wrong_unlock, &wrapper).unwrap_err();
        assert_eq!(err, DecryptError::AuthenticationFailed);
    }

    #[test]
    fn wrapper_decrypt_rejects_tampered_ciphertext_byte() {
        let unlock_key = [0x11u8; KEY_LEN];
        let mask_key = [0x22u8; KEY_LEN];
        let seed = [0x33u8; KEY_LEN];
        let mut wrapper = build_wrapper(&unlock_key, &mask_key, &seed);

        // Flip a byte inside the ciphertext region (past the 12-byte
        // cleartext nonce prefix).
        wrapper[20] ^= 0x01;
        let err = decrypt_wrapper(&unlock_key, &wrapper).unwrap_err();
        assert_eq!(err, DecryptError::AuthenticationFailed);
    }

    /// An unknown authenticated version byte must surface as
    /// `UnsupportedFormat`, not `AuthenticationFailed`. Built by sealing
    /// a plaintext whose leading byte is an unknown version so the AEAD
    /// tag still verifies and the version check is what rejects it.
    #[test]
    fn wrapper_decrypt_rejects_unsupported_version_byte() {
        let unlock_key = [0x11u8; KEY_LEN];
        let mask_key = [0x22u8; KEY_LEN];
        let seed = [0x33u8; KEY_LEN];
        let nonce = nonce_for_wrapper(&seed);
        let mut plaintext = [0u8; WRAPPER_PLAINTEXT_LEN];
        plaintext[0] = 0xFE; // unknown version
        plaintext[1..].copy_from_slice(&mask_key);
        let body = aead_encrypt(CURRENT_CIPHER, &unlock_key, &nonce, &plaintext).expect("encrypt");
        let body: &[u8; WRAPPER_BODY_LEN] = body.as_slice().try_into().expect("body len");
        let wrapper = assemble_wrapper(&nonce, body);
        assert_eq!(
            decrypt_wrapper(&unlock_key, &wrapper),
            Err(DecryptError::UnsupportedFormat),
        );
    }

    #[test]
    fn blob_round_trip_succeeds() {
        let mask_key = [0x55u8; KEY_LEN];
        let nonce = [0x66u8; NONCE_LEN];
        let plaintext = b"the quick brown fox";
        let blob = build_blob(&mask_key, &nonce, plaintext);
        let recovered = decrypt_blob(&mask_key, &blob).expect("round-trip");
        assert_eq!(recovered.as_slice(), plaintext.as_slice());
    }

    #[test]
    fn blob_decrypt_rejects_wrong_mask_key() {
        let mask_key = [0x55u8; KEY_LEN];
        let nonce = [0x66u8; NONCE_LEN];
        let plaintext = b"secret";
        let blob = build_blob(&mask_key, &nonce, plaintext);
        let wrong = [0xAAu8; KEY_LEN];
        assert_eq!(
            decrypt_blob(&wrong, &blob),
            Err(DecryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn blob_decrypt_rejects_tampered_byte() {
        let mask_key = [0x55u8; KEY_LEN];
        let nonce = [0x66u8; NONCE_LEN];
        let plaintext = b"secret";
        let mut blob = build_blob(&mask_key, &nonce, plaintext);
        // Flip a byte inside the ciphertext (past the 12-byte nonce
        // prefix; first plaintext-byte ciphertext is at index 12).
        blob[12] ^= 0x01;
        assert_eq!(
            decrypt_blob(&mask_key, &blob),
            Err(DecryptError::AuthenticationFailed)
        );
    }

    #[test]
    fn blob_decrypt_rejects_too_short_input() {
        let mask_key = [0x55u8; KEY_LEN];
        let blob = alloc::vec![0u8; NONCE_LEN + TAG_LEN - 1];
        assert_eq!(
            decrypt_blob(&mask_key, &blob),
            Err(DecryptError::BlobTooShort)
        );
    }

    #[test]
    fn blob_empty_plaintext_round_trips() {
        // mask!("") encrypts to a 0-byte ciphertext + 16-byte tag; the
        // total blob is exactly NONCE_LEN + TAG_LEN bytes. Must be
        // accepted.
        let mask_key = [0x55u8; KEY_LEN];
        let nonce = [0x66u8; NONCE_LEN];
        let blob = build_blob(&mask_key, &nonce, b"");
        assert_eq!(blob.len(), NONCE_LEN + TAG_LEN);
        let recovered = decrypt_blob(&mask_key, &blob).expect("round-trip");
        assert!(recovered.is_empty());
    }

    proptest::proptest! {
        // AEAD round-trip across a broad (key, nonce, plaintext) space.
        // Catches future cipher-impl changes that silently corrupt
        // either direction. Plaintext capped at 1 KiB so the test suite
        // stays fast.
        #[test]
        fn proptest_aead_round_trip(
            key in proptest::array::uniform32(proptest::num::u8::ANY),
            nonce in proptest::array::uniform12(proptest::num::u8::ANY),
            plaintext in proptest::collection::vec(proptest::num::u8::ANY, 0..=1024),
        ) {
            let body = aead_encrypt(CipherId::ChaCha20Poly1305, &key, &nonce, &plaintext)
                .expect("AEAD encrypt does not fail for ChaCha20Poly1305");
            let recovered = aead_decrypt(CipherId::ChaCha20Poly1305, &key, &nonce, &body)
                .expect("decrypt under the same key must succeed");
            proptest::prop_assert_eq!(recovered, plaintext);
        }

        // Tamper detection: flipping any single bit anywhere in
        // `ciphertext || tag` must produce AuthenticationFailed.
        // `bit` selects (byte_index * 8 + bit_index) within the body.
        #[test]
        fn proptest_aead_rejects_single_bit_flip(
            key in proptest::array::uniform32(proptest::num::u8::ANY),
            nonce in proptest::array::uniform12(proptest::num::u8::ANY),
            plaintext in proptest::collection::vec(proptest::num::u8::ANY, 1..=256),
            bit in 0usize..(8 * 1024),
        ) {
            let mut body = aead_encrypt(CipherId::ChaCha20Poly1305, &key, &nonce, &plaintext)
                .expect("AEAD encrypt");
            let bit = bit % (body.len() * 8);
            body[bit / 8] ^= 1u8 << (bit % 8);
            proptest::prop_assert_eq!(
                aead_decrypt(CipherId::ChaCha20Poly1305, &key, &nonce, &body),
                Err(AeadError::AuthenticationFailed),
            );
        }

        // Blob round-trip + tamper detection layered on top of
        // decrypt_blob's nonce-split contract.
        #[test]
        fn proptest_blob_round_trip(
            mask_key in proptest::array::uniform32(proptest::num::u8::ANY),
            nonce in proptest::array::uniform12(proptest::num::u8::ANY),
            plaintext in proptest::collection::vec(proptest::num::u8::ANY, 0..=1024),
        ) {
            let blob = build_blob(&mask_key, &nonce, &plaintext);
            let recovered = decrypt_blob(&mask_key, &blob).expect("blob decrypts");
            proptest::prop_assert_eq!(recovered, plaintext);
        }
    }
}
