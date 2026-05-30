//! AEAD encrypt/decrypt dispatch across compile-time-selected ciphers.
//!
//! # Cipher selection
//!
//! [`CURRENT_CIPHER`] names the single cipher this build encrypts and
//! blob-decrypts with. When both cipher features are active (e.g.
//! `cargo build -p litmask --features aes-gcm` keeps the default
//! `chacha20-poly1305` alive under Cargo feature unification, or
//! `cargo test --all-features`), `aes-gcm` wins: passing it is an
//! explicit opt-in to AES-256-GCM. For a strict single-cipher build
//! with no `chacha20poly1305` crate in the dep tree, use
//! `--no-default-features --features std,aes-gcm`.
//!
//! [`CURRENT_CIPHER`] governs only [`aead_encrypt`] and the
//! blob-decrypt path; it is absent under `all-ciphers` alone. The
//! dual-cipher consumer (`litmask-cli`) ignores it entirely and
//! dispatches on the wrapper's cipher-id byte at runtime.

use alloc::vec::Vec;
use core::fmt;

use crate::{CipherId, KEY_LEN, NONCE_LEN};

// Feature → import mapping for the shared AEAD trait surface:
//
//  chacha only (default)    → traits from chacha20poly1305, ChaCha20Poly1305 cipher
//  aes-gcm only             → traits from aes-gcm,          Aes256Gcm cipher
//  both / all-ciphers       → traits from chacha20poly1305,  both ciphers
//
// `Aead`, `KeyInit`, and `GenericArray` are re-exported identically by
// both backend crates; importing from either path is sufficient.
#[cfg(all(
    feature = "aes-gcm",
    not(feature = "chacha20-poly1305"),
    not(feature = "all-ciphers"),
))]
use aes_gcm::aead::{Aead, generic_array::GenericArray};
#[cfg(any(feature = "chacha20-poly1305", feature = "all-ciphers"))]
use chacha20poly1305::aead::{Aead, generic_array::GenericArray};

#[cfg(any(feature = "aes-gcm", feature = "all-ciphers"))]
use aes_gcm::Aes256Gcm;
#[cfg(all(
    feature = "aes-gcm",
    not(feature = "chacha20-poly1305"),
    not(feature = "all-ciphers"),
))]
use aes_gcm::KeyInit as _;
#[cfg(any(feature = "chacha20-poly1305", feature = "all-ciphers"))]
use chacha20poly1305::{ChaCha20Poly1305, KeyInit as _};

/// The single cipher this build encrypts and blob-decrypts with. See
/// the module-level docs for the selection rules when multiple cipher
/// features are active.
#[cfg(feature = "aes-gcm")]
pub const CURRENT_CIPHER: CipherId = CipherId::Aes256Gcm;

/// See [`CURRENT_CIPHER`].
#[cfg(all(feature = "chacha20-poly1305", not(feature = "aes-gcm")))]
pub const CURRENT_CIPHER: CipherId = CipherId::ChaCha20Poly1305;

/// Errors surfaced by [`aead_encrypt`] and [`aead_decrypt`]. Today the
/// single variant covers AEAD authentication failure on decrypt; encrypt
/// failures are not reachable for the cipher set this crate supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AeadError {
    /// AEAD authentication failed (wrong key, wrong nonce, or tampered
    /// ciphertext + tag).
    AuthenticationFailed,
}

impl fmt::Display for AeadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AuthenticationFailed => f.write_str("authentication failed"),
        }
    }
}

/// Dispatch an AEAD operation across the compile-time-selected cipher.
///
/// Stamps out the feature-gated match arms once so `aead_encrypt` and
/// `aead_decrypt` share the same dispatch logic.
macro_rules! dispatch_cipher {
    ($cipher_id:expr, $key:expr, $nonce:expr, $data:expr, $method:ident) => {{
        match $cipher_id {
            #[cfg(any(feature = "chacha20-poly1305", feature = "all-ciphers"))]
            CipherId::ChaCha20Poly1305 => ChaCha20Poly1305::new(GenericArray::from_slice($key))
                .$method(GenericArray::from_slice($nonce), $data)
                .map_err(|_| AeadError::AuthenticationFailed),
            #[cfg(any(feature = "aes-gcm", feature = "all-ciphers"))]
            CipherId::Aes256Gcm => Aes256Gcm::new(GenericArray::from_slice($key))
                .$method(GenericArray::from_slice($nonce), $data)
                .map_err(|_| AeadError::AuthenticationFailed),
            #[cfg(not(any(feature = "chacha20-poly1305", feature = "all-ciphers")))]
            CipherId::ChaCha20Poly1305 => unreachable!(),
            #[cfg(not(any(feature = "aes-gcm", feature = "all-ciphers")))]
            CipherId::Aes256Gcm => unreachable!(),
        }
    }};
}

/// Encrypt `plaintext` with the AEAD cipher identified by `cipher_id`.
/// Returns `ciphertext || tag` (no leading nonce — the caller embeds the
/// nonce at whatever offset the wrapper / blob layout dictates).
///
/// # Errors
///
/// Returns [`AeadError::AuthenticationFailed`] only if the cipher's
/// encrypt step reports failure; for the ChaCha20-Poly1305 inputs litmask
/// produces this is not reachable in practice, but the result type
/// matches [`aead_decrypt`] so callers can share a control-flow path.
///
/// # Panics
///
/// Panics with `unreachable!()` if called with a [`CipherId`] whose
/// AEAD implementation is not compiled into this build.
pub fn aead_encrypt(
    cipher_id: CipherId,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, AeadError> {
    dispatch_cipher!(cipher_id, key, nonce, plaintext, encrypt)
}

/// Decrypt `ciphertext || tag` with the AEAD cipher identified by
/// `cipher_id`. Mirrors [`aead_encrypt`].
///
/// # Errors
///
/// Returns [`AeadError::AuthenticationFailed`] when the tag does not
/// verify (wrong key, wrong nonce, or tampered bytes).
///
/// # Panics
///
/// Panics with `unreachable!()` if called with a [`CipherId`] whose
/// AEAD implementation is not compiled into this build.
pub fn aead_decrypt(
    cipher_id: CipherId,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    body: &[u8],
) -> Result<Vec<u8>, AeadError> {
    dispatch_cipher!(cipher_id, key, nonce, body, decrypt)
}
