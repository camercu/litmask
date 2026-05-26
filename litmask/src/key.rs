//! Symmetric-key newtypes.
//!
//! [`UnlockKey`] is the public-facing unlock key supplied by a
//! [`crate::KeyProvider`]. [`MaskKey`] is the runtime-only decrypted
//! mask key held in a process-global once-cell. Both zero their
//! contents on drop.

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::KeyError;
use crate::internal::{KEY_LEN, base64url};

/// The runtime-supplied key that decrypts the embedded `mask_key`
/// wrapper.
///
/// `Clone` is intentionally not implemented; duplicating a
/// zero-on-drop secret should be opt-in and obvious at the call site.
///
/// # Examples
///
/// ```
/// use litmask::UnlockKey;
///
/// // 32 bytes of zeros encoded as base64url (43 chars, no padding).
/// let key = UnlockKey::from_base64url(
///     "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
/// ).expect("valid key");
/// assert_eq!(format!("{key:?}"), "UnlockKey([REDACTED])");
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct UnlockKey([u8; KEY_LEN]);

impl UnlockKey {
    /// Decode a base64url-encoded 32-byte key. Padded inputs and any
    /// length other than 32 are rejected with
    /// [`KeyError::InvalidFormat`].
    ///
    /// # Errors
    ///
    /// Returns [`KeyError::InvalidFormat`] for malformed encoding or
    /// wrong length.
    pub fn from_base64url(input: &str) -> Result<Self, KeyError> {
        // Plaintext key bytes MUST NOT linger on the heap after the
        // fixed-size array is populated.
        let decoded =
            Zeroizing::new(base64url::decode(input).map_err(|_| KeyError::InvalidFormat)?);
        let bytes: [u8; KEY_LEN] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| KeyError::InvalidFormat)?;
        Ok(Self(bytes))
    }

    /// Construct an `UnlockKey` from raw 32-byte material. Used by
    /// providers that source the key bytes directly (rather than via
    /// base64url-encoded text), e.g. `FileProvider` under
    /// `KeyEncoding::Raw` and `HardwareIdProvider`. Stays
    /// crate-private so the encoded/typed entry points
    /// (`from_base64url`) remain the canonical user-facing API and a
    /// caller cannot accidentally bypass the length check by handing
    /// in arbitrary bytes — the type system pins the array length.
    ///
    /// `#[allow(dead_code)]` covers the `--no-default-features
    /// --features alloc` build, where neither `FileProvider` nor
    /// `HardwareIdProvider` is compiled in and the function has no
    /// caller. Restoring `std` or adding `hw-id` reactivates the
    /// callers.
    #[allow(dead_code)]
    pub(crate) fn from_raw(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for UnlockKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never print key material, even in Debug output.
        f.write_str("UnlockKey([REDACTED])")
    }
}

/// The decrypted mask key. Held in a process-global once-cell for
/// the program's lifetime; never re-decrypted. Crate-internal only.
#[derive(Zeroize, ZeroizeOnDrop)]
#[doc(hidden)]
pub struct MaskKey([u8; KEY_LEN]);

impl MaskKey {
    pub(crate) fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl core::fmt::Debug for MaskKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("MaskKey([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    /// Canonical 32-byte test key encoded as 43-char base64url (no padding).
    const VALID_BASE64URL_32B: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

    #[test]
    fn from_base64url_accepts_valid_32_byte_key() {
        let key = UnlockKey::from_base64url(VALID_BASE64URL_32B).expect("valid 32-byte key");
        assert_eq!(key.0, [0u8; KEY_LEN]);
    }

    #[test]
    fn from_base64url_rejects_padded_input() {
        // 32 bytes encodes to 43 url-safe chars (no padding); the
        // padded RFC 4648 form appends "=" — must be rejected.
        let padded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        let err = UnlockKey::from_base64url(padded).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn from_base64url_rejects_wrong_length_short() {
        // 24 bytes encodes to 32 url-safe chars; shorter than 32-byte key.
        let short = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let err = UnlockKey::from_base64url(short).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn from_base64url_rejects_wrong_length_long() {
        // 48 bytes encodes to 64 url-safe chars; longer than 32-byte key.
        let long = "A".repeat(64);
        let err = UnlockKey::from_base64url(&long).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn from_base64url_rejects_non_alphabet_chars() {
        // '+' and '/' are standard base64 alphabet but NOT url-safe.
        let bad = "++++/////+++++++++/////++++++++++/////++++++";
        let err = UnlockKey::from_base64url(bad).unwrap_err();
        assert!(matches!(err, KeyError::InvalidFormat));
    }

    #[test]
    fn debug_does_not_print_key_material() {
        let bytes = [0xCAu8; KEY_LEN];
        let key = UnlockKey(bytes);
        let dbg = format!("{key:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("ca"));
        assert!(!dbg.contains("CA"));
    }

    #[test]
    fn debug_mask_key_does_not_print_key_material() {
        let bytes = [0xCAu8; KEY_LEN];
        let key = MaskKey(bytes);
        let dbg = format!("{key:?}");
        assert!(dbg.contains("REDACTED"));
        assert!(!dbg.contains("ca"));
    }

    use proptest::strategy::Strategy as _;

    proptest::proptest! {
        // Any 32-byte key encoded via the shared codec must round-trip
        // through the public parser unchanged. Catches future drift
        // between base64url::encode and from_base64url's accepted
        // alphabet / length policy.
        #[test]
        fn proptest_from_base64url_round_trips_random_keys(
            bytes in proptest::array::uniform32(proptest::num::u8::ANY),
        ) {
            let encoded = crate::internal::base64url::encode(&bytes);
            let key = UnlockKey::from_base64url(&encoded).expect("32-byte key must parse");
            proptest::prop_assert_eq!(key.as_bytes(), &bytes);
        }

        // Inputs whose decoded length is anything other than KEY_LEN
        // must surface as InvalidFormat. Generating via the codec
        // guarantees the candidate input is valid base64url, so the
        // failure mode under test is specifically the length check,
        // not the alphabet check.
        #[test]
        fn proptest_from_base64url_rejects_wrong_length(
            bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..=64)
                .prop_filter("must not be exactly KEY_LEN", |v| v.len() != KEY_LEN),
        ) {
            let encoded = crate::internal::base64url::encode(&bytes);
            proptest::prop_assert!(matches!(
                UnlockKey::from_base64url(&encoded),
                Err(KeyError::InvalidFormat),
            ));
        }
    }
}
