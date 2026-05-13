//! ChaCha20-Poly1305 AEAD decrypt path (functional core).
//!
//! Stateless decrypt operations plus higher-level pure helpers that
//! validate the wrapper format. Encryption is performed only at build
//! time (in the build-script helper) and at proc-macro expansion time;
//! the runtime crate decrypts only.

use crate::{
    AeadError, CipherId, KEY_LEN, NONCE_LEN, TAG_LEN, WRAPPER_LEN, WrapperParseError, aead_decrypt,
    parse_wrapper,
};

/// Errors surfaced by pure decryption helpers. Converted to panics by
/// the runtime imperative shell; the typed form here lets unit tests
/// assert specific failure modes without `panic::catch_unwind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    // parse_wrapper rejects any byte that doesn't decode to a known
    // FormatVersion / CipherId variant, so a successful parse already
    // means the header is one this build supports.
    let parsed = parse_wrapper(wrapper).map_err(|e| match e {
        WrapperParseError::UnknownFormatVersion(_) => DecryptError::UnsupportedFormat,
        WrapperParseError::UnknownCipherId(_) => DecryptError::UnsupportedCipher,
    })?;
    let plaintext = aead_decrypt(parsed.cipher, unlock_key, parsed.nonce, parsed.body)?;
    plaintext
        .as_slice()
        .try_into()
        .map_err(|_| DecryptError::AuthenticationFailed)
}

/// Decrypt a per-string blob.
///
/// `blob` is `nonce (12) || ciphertext (n) || tag (16)`. The blob
/// format does not record its own cipher id; per spec §1.7.2 every
/// per-string blob in a binary uses the same cipher as the wrapper.
/// Until that cipher is threaded through from init time, the blob path
/// hardcodes the default ChaCha20-Poly1305.
///
/// # Errors
///
/// Returns [`DecryptError::BlobTooShort`] when `blob` is shorter than
/// `NONCE_LEN + TAG_LEN`, and [`DecryptError::AuthenticationFailed`]
/// when the AEAD tag check fails.
///
/// # Panics
///
/// Never panics for valid inputs; the internal `expect` exists only as
/// a sanity guard — the length check above already rejects any `blob`
/// shorter than `NONCE_LEN`.
pub fn decrypt_blob(
    mask_key: &[u8; KEY_LEN],
    blob: &[u8],
) -> Result<alloc::vec::Vec<u8>, DecryptError> {
    if blob.len() < NONCE_LEN + TAG_LEN {
        return Err(DecryptError::BlobTooShort);
    }
    let nonce_bytes: [u8; NONCE_LEN] = blob[..NONCE_LEN]
        .try_into()
        .expect("blob.len() >= NONCE_LEN checked above");
    aead_decrypt(
        CipherId::ChaCha20Poly1305,
        mask_key,
        &nonce_bytes,
        &blob[NONCE_LEN..],
    )
    .map_err(DecryptError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FormatVersion, aead_encrypt, assemble_wrapper, nonce_for_wrapper};

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
        assemble_wrapper(
            FormatVersion::CURRENT,
            CipherId::ChaCha20Poly1305,
            &nonce,
            &body,
        )
    }

    fn build_blob(
        mask_key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        plaintext: &[u8],
    ) -> alloc::vec::Vec<u8> {
        let body =
            aead_encrypt(CipherId::ChaCha20Poly1305, mask_key, nonce, plaintext).expect("encrypt");
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
}
