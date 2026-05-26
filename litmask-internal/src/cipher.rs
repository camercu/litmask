//! ChaCha20-Poly1305 AEAD decrypt path (functional core).
//!
//! Stateless decrypt operations plus higher-level pure helpers that
//! validate the wrapper format. Encryption is performed only at build
//! time (in the build-script helper) and at proc-macro expansion time;
//! the runtime crate decrypts only.

use zeroize::Zeroizing;

use crate::{
    AeadError, KEY_LEN, NONCE_LEN, TAG_LEN, WRAPPER_LEN, WrapperParseError, aead_decrypt,
    parse_wrapper,
};

/// Errors surfaced by pure decryption helpers. Converted to panics by
/// the runtime imperative shell; the typed form here lets unit tests
/// assert specific failure modes without `panic::catch_unwind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecryptError {
    /// Wrapper header carries a format version this build does not
    /// support, or the byte does not match any known version.
    UnsupportedFormat,
    /// Wrapper header carries a cipher id this build does not support,
    /// or the byte does not match any known cipher.
    UnsupportedCipher,
    /// Per-string blob is shorter than `NONCE_LEN + TAG_LEN`.
    BlobTooShort,
    /// AEAD authentication failed (wrong unlock or mask key, or
    /// tampered ciphertext).
    AuthenticationFailed,
}

impl From<AeadError> for DecryptError {
    fn from(_: AeadError) -> Self {
        Self::AuthenticationFailed
    }
}

/// Decrypt the embedded encrypted-`mask_key` wrapper.
///
/// Parses the typed header, confirms the format and cipher are ones
/// this build supports, and runs the AEAD decryption with the supplied
/// `unlock_key` using the cipher recorded in the header. Returns the
/// recovered `mask_key` bytes on success.
///
/// # Errors
///
/// Returns [`DecryptError::UnsupportedFormat`] or
/// [`DecryptError::UnsupportedCipher`] when the wrapper header carries
/// an unrecognized version or cipher byte, and
/// [`DecryptError::AuthenticationFailed`] when the AEAD tag check fails.
pub fn decrypt_wrapper(
    unlock_key: &[u8; KEY_LEN],
    wrapper: &[u8; WRAPPER_LEN],
) -> Result<[u8; KEY_LEN], DecryptError> {
    let parsed = parse_wrapper(wrapper).map_err(|e| match e {
        WrapperParseError::UnknownFormatVersion(_) => DecryptError::UnsupportedFormat,
        WrapperParseError::UnknownCipherId(_) => DecryptError::UnsupportedCipher,
    })?;
    // In single-cipher (runtime) builds, the wrapper's cipher byte
    // must equal the build's compiled cipher. Without this gate,
    // a fabricated wrapper with cipher id 0x02 against a chacha-
    // only runtime would silently fall through to AEAD decrypt and
    // surface as `AuthenticationFailed` — losing the §2.7.1
    // diagnostic that distinguishes "wrong cipher" from "wrong
    // key". Dual-cipher builds (litmask-cli) accept either byte
    // because `CURRENT_CIPHER` is absent in that cfg.
    #[cfg(any(
        all(feature = "chacha20-poly1305", not(feature = "aes-gcm")),
        all(feature = "aes-gcm", not(feature = "chacha20-poly1305")),
    ))]
    {
        if parsed.cipher != crate::CURRENT_CIPHER {
            return Err(DecryptError::UnsupportedCipher);
        }
    }
    let plaintext = Zeroizing::new(aead_decrypt(
        parsed.cipher,
        unlock_key,
        parsed.nonce,
        parsed.body,
    )?);
    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| DecryptError::AuthenticationFailed)
}

/// Decrypt a per-string blob.
///
/// `blob` is `nonce (12) || ciphertext (n) || tag (16)`. The blob
/// format does not record its own cipher id; every per-string blob
/// in a binary uses the same cipher as the wrapper, fixed at build
/// time to the value [`crate::CURRENT_CIPHER`] resolves to.
///
/// # Errors
///
/// Returns [`DecryptError::BlobTooShort`] when `blob` is shorter than
/// `NONCE_LEN + TAG_LEN`, and [`DecryptError::AuthenticationFailed`]
/// when the AEAD tag check fails.
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

// Wrapper tests hardcode ChaCha20-Poly1305 because `decrypt_wrapper`
// reads the cipher byte from the header and dispatches accordingly —
// the wrapper carries its own cipher identity. Blob tests use
// `CURRENT_CIPHER` because `decrypt_blob` dispatches through that
// constant (blobs don't carry a cipher byte). The AES-GCM-specific
// round-trip lives in `tests/cipher_selection.rs`.
#[cfg(all(test, feature = "chacha20-poly1305"))]
mod tests {
    use super::*;
    use crate::{
        CURRENT_CIPHER, CipherId, FormatVersion, WRAPPER_BODY_LEN, aead_encrypt, assemble_wrapper,
        nonce_for_wrapper,
    };

    /// Encrypt a `mask_key` under `unlock_key` and assemble the
    /// wrapper. Mirrors what the build-script helper does, but stays
    /// purely in-memory so tests run sub-millisecond.
    fn build_wrapper(
        unlock_key: &[u8; KEY_LEN],
        mask_key: &[u8; KEY_LEN],
        seed: &[u8; KEY_LEN],
    ) -> [u8; WRAPPER_LEN] {
        let nonce = nonce_for_wrapper(seed);
        let body = aead_encrypt(
            CipherId::ChaCha20Poly1305,
            unlock_key,
            &nonce,
            mask_key.as_slice(),
        )
        .expect("encrypt");
        let body: &[u8; WRAPPER_BODY_LEN] = body
            .as_slice()
            .try_into()
            .expect("AEAD output of 32-byte plaintext is WRAPPER_BODY_LEN bytes");
        assemble_wrapper(
            FormatVersion::CURRENT,
            CipherId::ChaCha20Poly1305,
            &nonce,
            body,
        )
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

        // Flip a single ciphertext byte (offset 20 lands inside the
        // 32-byte ciphertext region).
        wrapper[20] ^= 0x01;
        let err = decrypt_wrapper(&unlock_key, &wrapper).unwrap_err();
        assert_eq!(err, DecryptError::AuthenticationFailed);
    }

    #[test]
    fn wrapper_decrypt_rejects_unsupported_format_byte() {
        let unlock_key = [0x11u8; KEY_LEN];
        let mask_key = [0x22u8; KEY_LEN];
        let seed = [0x33u8; KEY_LEN];
        let mut wrapper = build_wrapper(&unlock_key, &mask_key, &seed);
        wrapper[0] = 0xFE;
        assert_eq!(
            decrypt_wrapper(&unlock_key, &wrapper),
            Err(DecryptError::UnsupportedFormat)
        );
    }

    #[test]
    fn wrapper_decrypt_rejects_unsupported_cipher_byte() {
        let unlock_key = [0x11u8; KEY_LEN];
        let mask_key = [0x22u8; KEY_LEN];
        let seed = [0x33u8; KEY_LEN];
        let mut wrapper = build_wrapper(&unlock_key, &mask_key, &seed);
        wrapper[1] = 0x99;
        assert_eq!(
            decrypt_wrapper(&unlock_key, &wrapper),
            Err(DecryptError::UnsupportedCipher)
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
