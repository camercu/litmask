//! Base64url codec — RFC 4648 §5 url-safe alphabet, no padding.
//!
//! Single source of truth for base64 encoding across the workspace:
//! `litmask` and `litmask-build` route key and seed encoding through
//! these two functions.
//!
//! Padding is rejected on decode to keep the wire format unambiguous;
//! padded and unpadded forms differ visibly, and accepting both would
//! mask configuration errors in key files and `litmask keygen` output.
//!
//! Callers that need zero-on-drop semantics for decoded secret bytes
//! (the unlock-key parse path, the `LITMASK_RNG_SEED` decoder) wrap
//! the returned `Vec<u8>` in `zeroize::Zeroizing` at the call site.
//! The wrapper is a runtime-crate concern; this module stays minimal
//! so the build crate can use it without a `zeroize` dependency.

use core::fmt;

use base64ct::{Base64UrlUnpadded, Encoding};

/// Encode raw bytes as RFC 4648 §5 url-safe base64 without padding.
#[must_use]
pub fn encode(bytes: &[u8]) -> alloc::string::String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// Decode RFC 4648 §5 url-safe base64. Padded inputs (`=` characters)
/// are rejected as malformed.
///
/// # Errors
///
/// Returns [`DecodeError`] if the input contains characters outside
/// the url-safe alphabet, includes padding, or is not a multiple of
/// the expected byte alignment.
pub fn decode(input: &str) -> Result<alloc::vec::Vec<u8>, DecodeError> {
    if input.contains('=') {
        return Err(DecodeError::Padded);
    }
    Base64UrlUnpadded::decode_vec(input).map_err(|_| DecodeError::Invalid)
}

/// Errors returned by [`decode`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// Input contained `=` characters; padding is disallowed.
    Padded,
    /// Input contained non-url-safe-alphabet characters or otherwise
    /// failed base64 decoding.
    Invalid,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Padded => f.write_str("padded input rejected"),
            Self::Invalid => f.write_str("invalid encoding"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_error_display_is_stable() {
        assert_eq!(
            alloc::format!("{}", DecodeError::Padded),
            "padded input rejected"
        );
        assert_eq!(
            alloc::format!("{}", DecodeError::Invalid),
            "invalid encoding"
        );
    }

    #[test]
    fn round_trip_random_bytes() {
        let cases: &[&[u8]] = &[
            &[],
            &[0],
            &[0x42],
            &[0x00, 0xff, 0x7f, 0x80],
            &[0u8; 32],
            &[0xab; 32],
        ];
        for case in cases {
            let encoded = encode(case);
            let decoded = decode(&encoded).expect("round-trip decode");
            assert_eq!(
                decoded.as_slice(),
                *case,
                "round-trip mismatch for {case:?}"
            );
            assert!(
                !encoded.contains('='),
                "encoder must not emit padding (got {encoded})",
            );
        }
    }

    #[test]
    fn reject_padded_input() {
        // 32 bytes encodes to 43 url-safe chars (no padding); RFC 4648 standard
        // padded form would append "=" — verify rejection.
        let padded = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
        assert_eq!(decode(padded), Err(DecodeError::Padded));
    }

    #[test]
    fn reject_non_alphabet_chars() {
        assert_eq!(decode("hello world"), Err(DecodeError::Invalid));
        // Standard base64 uses '+' / '/' — must be rejected in url-safe mode.
        assert_eq!(decode("a+b/c"), Err(DecodeError::Invalid));
    }

    #[test]
    fn encode_uses_url_safe_alphabet() {
        // Bytes that would produce '+' and '/' in standard base64 should
        // produce '-' and '_' in url-safe.
        let bytes: [u8; 3] = [0xfb, 0xff, 0xbf];
        let out = encode(&bytes);
        assert!(!out.contains('+'));
        assert!(!out.contains('/'));
    }

    proptest::proptest! {
        // Round-trip across the full byte-length space catches alignment
        // edge cases (sub-byte boundaries at lengths 1/2/3 mod 3) that
        // enumerated tests miss.
        #[test]
        fn proptest_decode_of_encode_returns_input(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..=256)) {
            let encoded = encode(&bytes);
            let decoded = decode(&encoded).expect("encoder output must decode");
            proptest::prop_assert_eq!(decoded, bytes);
            proptest::prop_assert!(!encoded.contains('='));
        }

        #[test]
        fn proptest_encode_of_decode_returns_input(bytes in proptest::collection::vec(proptest::num::u8::ANY, 0..=256)) {
            // Canonicalize via the encoder so the input string is
            // guaranteed-valid base64url; proptest of arbitrary strings
            // would mostly hit DecodeError::Invalid and test nothing.
            let canonical = encode(&bytes);
            let decoded = decode(&canonical).expect("canonical encoding decodes");
            let re_encoded = encode(&decoded);
            proptest::prop_assert_eq!(re_encoded, canonical);
        }
    }
}
