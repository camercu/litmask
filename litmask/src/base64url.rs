//! Base64url codec — RFC 4648 §5 url-safe alphabet, no padding.
//!
//! Single source of truth for base64 encoding across the project. All
//! providers, the build crate, and the CLI read and write keys,
//! locators, and other 32- and 12-byte blobs through this module.
//!
//! Padding is rejected on decode to keep the wire format unambiguous;
//! padded and unpadded forms differ visibly, and accepting both would
//! mask configuration errors in `litmask.config` and key files.

use base64ct::{Base64UrlUnpadded, Encoding};

/// Encode raw bytes as RFC 4648 §5 url-safe base64 without padding.
#[must_use]
#[allow(dead_code)] // First consumer is the file-based provider.
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
