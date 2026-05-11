//! ChaCha20-Poly1305 AEAD wrappers (functional core).
//!
//! Stateless decrypt operations plus higher-level pure helpers that
//! validate the wrapper format. Encryption is performed only at build
//! time (in `litmask-build`) and at proc-macro expansion time (in
//! `litmask-macros`); the runtime crate decrypts only.
//!
//! The AES-256-GCM variant arrives in Task 18 under the `aes-gcm`
//! feature flag. All call sites use the `chacha20poly1305` crate
//! directly without further abstraction.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, generic_array::GenericArray},
};

use crate::format::{
    self, CIPHER_ID_CHACHA20, HEADER_LEN, KEY_LEN, NONCE_LEN, WRAPPER_LEN, WRAPPER_VERSION,
};

/// Errors surfaced by pure decryption helpers. These are converted to
/// panics by the runtime imperative shell per §1.9.5; the typed form
/// here lets unit tests assert specific failure modes without invoking
/// `panic::catch_unwind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecryptError {
    /// Wrapper byte 0 is not [`WRAPPER_VERSION`].
    UnsupportedFormat,
    /// Wrapper byte 1 is not a known cipher id.
    UnsupportedCipher,
    /// Per-string blob is shorter than `NONCE_LEN + TAG_LEN`.
    BlobTooShort,
    /// AEAD authentication failed (wrong key or tampered ciphertext).
    AuthenticationFailed,
}

/// Decrypt an AEAD blob with ChaCha20-Poly1305.
///
/// `body` is the `ciphertext || tag` payload (no leading nonce). Returns
/// the recovered plaintext on success, [`DecryptError::AuthenticationFailed`]
/// on tag mismatch or malformed input.
pub(crate) fn decrypt_aead(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    body: &[u8],
) -> Result<alloc::vec::Vec<u8>, DecryptError> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), body)
        .map_err(|_| DecryptError::AuthenticationFailed)
}

/// Decrypt the embedded encrypted-`mask_key` wrapper.
///
/// Validates the version and cipher-id bytes (per §1.7.3), then runs
/// the AEAD decryption with the supplied `unlock_key`. The recovered
/// `mask_key` is returned as a fixed-size byte array; callers wrap it
/// in [`crate::key::MaskKey`].
pub(crate) fn decrypt_wrapper(
    unlock_key: &[u8; KEY_LEN],
    wrapper: &[u8; WRAPPER_LEN],
) -> Result<[u8; KEY_LEN], DecryptError> {
    let (version, cipher_id, nonce, body) = format::parse_wrapper(wrapper);
    if version != WRAPPER_VERSION {
        return Err(DecryptError::UnsupportedFormat);
    }
    if cipher_id != CIPHER_ID_CHACHA20 {
        return Err(DecryptError::UnsupportedCipher);
    }
    debug_assert_eq!(body.len(), KEY_LEN + format::TAG_LEN);
    let plaintext = decrypt_aead(unlock_key, nonce, body)?;
    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| DecryptError::AuthenticationFailed)
}

/// Decrypt a per-string blob.
///
/// `blob` is `nonce (12) || ciphertext (n) || tag (16)` per §1.7.2.
/// Returns the recovered plaintext bytes.
pub(crate) fn decrypt_blob(
    mask_key: &[u8; KEY_LEN],
    blob: &[u8],
) -> Result<alloc::vec::Vec<u8>, DecryptError> {
    if blob.len() < NONCE_LEN + format::TAG_LEN {
        return Err(DecryptError::BlobTooShort);
    }
    let nonce_bytes: [u8; NONCE_LEN] = blob[..NONCE_LEN]
        .try_into()
        .expect("blob.len() >= NONCE_LEN checked above");
    decrypt_aead(mask_key, &nonce_bytes, &blob[NONCE_LEN..])
}

// The HEADER_LEN re-export is to keep symbol-name churn low if other
// modules want to reference the constant via this module. Format is the
// canonical home.
#[allow(dead_code)]
pub(crate) const _HEADER_LEN: usize = HEADER_LEN;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{self, TAG_LEN};
    use chacha20poly1305::{
        ChaCha20Poly1305, KeyInit, Nonce,
        aead::{Aead, generic_array::GenericArray},
    };

    /// Helper: encrypt a `mask_key` under `unlock_key` and assemble the
    /// 62-byte wrapper. Mirrors what `litmask-build::emit()` does, but
    /// stays purely in-memory so tests run sub-millisecond.
    fn build_wrapper(
        unlock_key: &[u8; KEY_LEN],
        mask_key: &[u8; KEY_LEN],
        seed: &[u8; KEY_LEN],
    ) -> [u8; WRAPPER_LEN] {
        let nonce = format::nonce_for_wrapper(seed);
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(unlock_key));
        let body = cipher
            .encrypt(Nonce::from_slice(&nonce), mask_key.as_slice())
            .expect("encrypt");
        format::assemble_wrapper(&nonce, &body)
    }

    fn build_blob(
        mask_key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> alloc::vec::Vec<u8> {
        let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(mask_key));
        let body = cipher
            .encrypt(Nonce::from_slice(nonce), plaintext)
            .expect("encrypt");
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
        // NONCE_LEN + TAG_LEN - 1 bytes; one short.
        let blob = alloc::vec![0u8; NONCE_LEN + TAG_LEN - 1];
        assert_eq!(
            decrypt_blob(&mask_key, &blob),
            Err(DecryptError::BlobTooShort)
        );
    }

    #[test]
    fn blob_empty_plaintext_round_trips() {
        // mask!("") encrypts to a 0-byte ciphertext + 16-byte tag; the
        // total blob is exactly NONCE_LEN + TAG_LEN bytes. This must
        // be accepted.
        let mask_key = [0x55u8; KEY_LEN];
        let nonce = [0x66u8; NONCE_LEN];
        let blob = build_blob(&mask_key, &nonce, b"");
        assert_eq!(blob.len(), NONCE_LEN + TAG_LEN);
        let recovered = decrypt_blob(&mask_key, &blob).expect("round-trip");
        assert!(recovered.is_empty());
    }
}
