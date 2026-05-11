//! Symmetric key newtypes.
//!
//! [`UnlockKey`] is the public-facing key supplied by a
//! [`crate::KeyProvider`]. [`MaskKey`] is the runtime-only decrypted
//! master key held by the `OnceLock`. Both zero their contents on drop
//! via the `zeroize` crate.

use zeroize::Zeroize;

use crate::base64url;
use crate::error::KeyError;

/// Length of every symmetric key in bytes. ChaCha20-Poly1305 and
/// AES-256-GCM both use 32-byte keys.
pub const KEY_LEN: usize = 32;

/// The runtime-supplied key that decrypts the embedded `mask_key` wrapper.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct UnlockKey([u8; KEY_LEN]);

impl UnlockKey {
    /// Wrap raw bytes as an [`UnlockKey`].
    #[must_use]
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    /// Decode a base64url-encoded 32-byte key. Padded inputs and any
    /// length other than 32 are rejected with
    /// [`KeyError::InvalidFormat`].
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::InvalidFormat`] for malformed encoding or
    /// wrong length.
    pub fn from_base64url(input: &str) -> Result<Self, KeyError> {
        let decoded = base64url::decode(input).map_err(|_| KeyError::InvalidFormat)?;
        let bytes: [u8; KEY_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::InvalidFormat)?;
        Ok(Self(bytes))
    }

    /// Borrow the underlying key bytes.
    #[must_use]
    #[doc(hidden)]
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Clone for UnlockKey {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl core::fmt::Debug for UnlockKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material, even in Debug output.
        f.write_str("UnlockKey([REDACTED])")
    }
}

/// The decrypted master key. Held in a process-global OnceLock for the
/// program's lifetime; never re-decrypted.
#[derive(Zeroize)]
#[zeroize(drop)]
#[doc(hidden)]
pub struct MaskKey(pub(crate) [u8; KEY_LEN]);

impl MaskKey {
    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for MaskKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MaskKey([REDACTED])")
    }
}
