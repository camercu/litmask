//! ChaCha20-Poly1305 AEAD wrappers.
//!
//! Runtime decryption only. Encryption happens in `litmask-build` (for
//! the wrapper) and `litmask-macros` (for per-string blobs). All three
//! call sites use the `chacha20poly1305` crate directly; the AES-GCM
//! variant arrives in Task 18 under the `aes-gcm` feature flag.

use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, generic_array::GenericArray},
};

use crate::key::KEY_LEN;
use crate::nonce::NONCE_LEN;

/// Decrypt an AEAD blob with ChaCha20-Poly1305.
///
/// `blob` MUST be at least `NONCE_LEN + 16` bytes; the layout is
/// `nonce (12) || ciphertext (variable) || tag (16)` per §1.7.2.
///
/// # Errors
///
/// Returns `Err(())` on authentication-tag failure or malformed input.
/// Task 8 will route this through the tampering-panic policy (§1.9.5).
pub(crate) fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext_and_tag: &[u8],
) -> Result<alloc::vec::Vec<u8>, ()> {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext_and_tag)
        .map_err(|_| ())
}
