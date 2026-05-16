//! Shared crypto primitives, wire-format constants, typed
//! format/cipher identifiers, and pure layout helpers for the litmask
//! binary format.
//!
//! Internal crate. Not part of the public litmask API. Versioned in
//! lockstep with `litmask`; do not depend on this crate directly. The
//! `litmask`, `litmask-build`, and `litmask-macros` crates all depend
//! on this one for a single canonical definition of:
//!
//! - The wrapper format: 1-byte format version, 1-byte cipher id,
//!   12-byte nonce, ciphertext, authentication tag.
//! - The per-string blob format: 12-byte nonce prefix, ciphertext,
//!   authentication tag.
//! - BLAKE3 nonce domain separators and derivation algorithms for the
//!   wrapper nonce and per-call-site nonces.
//! - The AEAD encrypt + decrypt primitives and the wrapper/blob
//!   decrypt helpers (see [`cipher`]).
//!
//! All functions here are pure (no I/O, no global state) and
//! `no_std`-compatible.

#![no_std]

extern crate alloc;

use chacha20poly1305::aead::{Aead, generic_array::GenericArray};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};

pub mod cipher;

/// Length of every symmetric key in bytes. ChaCha20-Poly1305 and
/// AES-256-GCM both use 32-byte keys.
pub const KEY_LEN: usize = 32;

/// AEAD nonce length, shared by ChaCha20-Poly1305 and AES-256-GCM.
pub const NONCE_LEN: usize = 12;

/// AEAD authentication-tag length, shared by both ciphers.
pub const TAG_LEN: usize = 16;

/// 1-byte version + 1-byte cipher id + 12-byte nonce.
const HEADER_LEN: usize = 2 + NONCE_LEN;

/// Total wrapper byte count: header + 32-byte encrypted `mask_key` + tag.
pub const WRAPPER_LEN: usize = HEADER_LEN + KEY_LEN + TAG_LEN;

/// BLAKE3 domain separator for per-call-site nonces.
pub const NONCE_TAG_CALL_SITE: &[u8] = b"litmask-nonce";

/// BLAKE3 domain separator for the wrapper nonce.
const NONCE_TAG_WRAPPER: &[u8] = b"litmask-mask-key-nonce";

/// Wire-format version of the encrypted-`mask_key` wrapper. Encoded as
/// a single byte at offset 0 of every wrapper.
///
/// Marked `#[non_exhaustive]` so adding a future format version is
/// non-breaking for downstream exhaustive matches.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FormatVersion {
    /// Initial format. 62-byte wrapper layout described at the crate
    /// docs.
    V1 = 0x01,
}

impl FormatVersion {
    /// The version produced by current builds. Older versions may still
    /// be readable; newer versions are rejected.
    pub const CURRENT: Self = Self::V1;

    /// Encode as the on-the-wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Error returned by `FormatVersion::try_from(u8)` when the byte does
/// not match any known wire-format version. The unrecognized byte is
/// preserved for diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownFormatVersion(pub u8);

impl TryFrom<u8> for FormatVersion {
    type Error = UnknownFormatVersion;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(Self::V1),
            other => Err(UnknownFormatVersion(other)),
        }
    }
}

/// AEAD cipher identifier. Encoded as a single byte at offset 1 of
/// every wrapper. Used by runtime tooling to confirm the wrapper was
/// produced with the cipher the current binary was compiled to handle.
///
/// Marked `#[non_exhaustive]` so adding AES-256-GCM (and any future
/// cipher) is non-breaking for downstream exhaustive matches.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CipherId {
    /// ChaCha20-Poly1305 AEAD, RFC 8439.
    ChaCha20Poly1305 = 0x01,
    // AES-256-GCM will land here as a second variant when the `aes-gcm`
    // feature ships.
}

impl CipherId {
    /// Encode as the on-the-wire byte.
    #[must_use]
    pub fn to_byte(self) -> u8 {
        self as u8
    }
}

/// Error returned by `CipherId::try_from(u8)` when the byte does not
/// match any known cipher. The unrecognized byte is preserved for
/// diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnknownCipherId(pub u8);

impl TryFrom<u8> for CipherId {
    type Error = UnknownCipherId;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(Self::ChaCha20Poly1305),
            other => Err(UnknownCipherId(other)),
        }
    }
}

/// Length of the AEAD body that follows the wrapper header: 32 bytes
/// of `mask_key` ciphertext + 16 bytes of authentication tag.
pub const WRAPPER_BODY_LEN: usize = KEY_LEN + TAG_LEN;

/// A parsed wrapper, decomposed into its typed header fields plus
/// borrowed nonce and `ciphertext || tag` body.
#[derive(Debug)]
pub struct ParsedWrapper<'a> {
    /// Format version recorded in the wrapper header.
    pub version: FormatVersion,
    /// Cipher identifier recorded in the wrapper header.
    pub cipher: CipherId,
    /// 12-byte AEAD nonce used to encrypt the body.
    pub nonce: &'a [u8; NONCE_LEN],
    /// `ciphertext || tag` — 32 bytes ciphertext followed by 16 bytes
    /// of authentication tag for the current cipher.
    pub body: &'a [u8; WRAPPER_BODY_LEN],
}

/// Reasons `parse_wrapper` may reject a wrapper byte sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum WrapperParseError {
    /// Header byte 0 is not a recognized [`FormatVersion`] value.
    UnknownFormatVersion(u8),
    /// Header byte 1 is not a recognized [`CipherId`] value.
    UnknownCipherId(u8),
}

/// Build a wrapper byte array from typed header fields and the
/// AEAD-encrypted body.
#[must_use]
pub fn assemble_wrapper(
    version: FormatVersion,
    cipher: CipherId,
    nonce: &[u8; NONCE_LEN],
    ciphertext_and_tag: &[u8; WRAPPER_BODY_LEN],
) -> [u8; WRAPPER_LEN] {
    let mut out = [0u8; WRAPPER_LEN];
    out[0] = version.to_byte();
    out[1] = cipher.to_byte();
    out[2..HEADER_LEN].copy_from_slice(nonce);
    out[HEADER_LEN..].copy_from_slice(ciphertext_and_tag);
    out
}

/// Parse a wrapper byte array into typed header fields and body slice.
///
/// # Errors
///
/// Returns [`WrapperParseError`] when the header version or cipher byte
/// is not recognized. Subsequent AEAD decryption is the caller's
/// responsibility.
///
/// # Panics
///
/// Never panics for valid `[u8; WRAPPER_LEN]` inputs. The internal
/// slice-to-array conversions are sanity guards against future drift
/// in the wrapper header layout.
pub fn parse_wrapper(bytes: &[u8; WRAPPER_LEN]) -> Result<ParsedWrapper<'_>, WrapperParseError> {
    let version = FormatVersion::try_from(bytes[0])
        .map_err(|e| WrapperParseError::UnknownFormatVersion(e.0))?;
    let cipher =
        CipherId::try_from(bytes[1]).map_err(|e| WrapperParseError::UnknownCipherId(e.0))?;
    let nonce: &[u8; NONCE_LEN] = (&bytes[2..HEADER_LEN])
        .try_into()
        .expect("nonce slice is NONCE_LEN bytes by construction");
    let body: &[u8; WRAPPER_BODY_LEN] = (&bytes[HEADER_LEN..])
        .try_into()
        .expect("body slice is WRAPPER_BODY_LEN bytes by construction");
    Ok(ParsedWrapper {
        version,
        cipher,
        nonce,
        body,
    })
}

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
pub fn aead_encrypt(
    cipher_id: CipherId,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Result<alloc::vec::Vec<u8>, AeadError> {
    match cipher_id {
        CipherId::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
            cipher
                .encrypt(Nonce::from_slice(nonce), plaintext)
                .map_err(|_| AeadError::AuthenticationFailed)
        }
    }
}

/// Decrypt `ciphertext || tag` with the AEAD cipher identified by
/// `cipher_id`. Mirrors [`aead_encrypt`].
///
/// # Errors
///
/// Returns [`AeadError::AuthenticationFailed`] when the tag does not
/// verify (wrong key, wrong nonce, or tampered bytes).
pub fn aead_decrypt(
    cipher_id: CipherId,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    body: &[u8],
) -> Result<alloc::vec::Vec<u8>, AeadError> {
    match cipher_id {
        CipherId::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
            cipher
                .decrypt(Nonce::from_slice(nonce), body)
                .map_err(|_| AeadError::AuthenticationFailed)
        }
    }
}

/// XOR every byte of `input` against the cyclically-repeated `key`,
/// returning the result as a new `Vec`.
///
/// The operation is its own inverse: applying it twice with the same
/// key recovers the original input. Used by the `weak_mask!` macro to
/// obfuscate string literals against the per-build wrapper bytes so
/// litmask-supplied static strings do not contribute a fixed byte
/// signature to user binaries.
///
/// # Panics
///
/// Panics if `key.is_empty()` while `input` is non-empty.
#[must_use]
pub fn xor_cycle(input: &[u8], key: &[u8]) -> alloc::vec::Vec<u8> {
    if input.is_empty() {
        return alloc::vec::Vec::new();
    }
    assert!(!key.is_empty(), "key must be non-empty");
    input
        .iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % key.len()])
        .collect()
}

/// Derive the wrapper nonce: first [`NONCE_LEN`] bytes of the keyed
/// BLAKE3 hash of a fixed domain-separator string under `seed`.
#[must_use]
pub fn nonce_for_wrapper(seed: &[u8; KEY_LEN]) -> [u8; NONCE_LEN] {
    let digest = blake3::keyed_hash(seed, NONCE_TAG_WRAPPER);
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    out
}

// The per-call-site nonce is owned by the proc-macro crate
// (`litmask-macros`). The macro derives it from
// `(seed, NONCE_TAG_CALL_SITE, counter)` and embeds the resulting
// 12-byte value in the leading bytes of every per-string blob, so the
// runtime never re-derives it.
//
// The (file, line, column) scheme that `docs/SPECIFICATION.md §1.5.2`
// describes is unreachable on stable Rust: `proc_macro::Span` does not
// expose accessors for those fields without the nightly
// `proc_macro_span` feature. When that stabilizes, the canonical
// derivation can live here as a shared helper.

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: [u8; KEY_LEN] = [0xaa; KEY_LEN];
    const SEED_B: [u8; KEY_LEN] = [0xbb; KEY_LEN];

    #[test]
    fn xor_cycle_empty_input_is_noop() {
        let key = [0xAAu8; 8];
        assert!(xor_cycle(&[], &key).is_empty());
    }

    #[test]
    fn xor_cycle_self_inverse_with_matching_lengths() {
        let plaintext = b"hello world";
        let key = b"0123456789ab";
        let encoded = xor_cycle(plaintext, key);
        let decoded = xor_cycle(&encoded, key);
        assert_eq!(decoded.as_slice(), plaintext);
    }

    #[test]
    fn xor_cycle_handles_key_shorter_than_input() {
        let plaintext = b"abcdef";
        let key = b"\xff\x55";
        let out = xor_cycle(plaintext, key);
        assert_eq!(
            out.as_slice(),
            &[
                b'a' ^ 0xff,
                b'b' ^ 0x55,
                b'c' ^ 0xff,
                b'd' ^ 0x55,
                b'e' ^ 0xff,
                b'f' ^ 0x55,
            ]
        );
    }

    #[test]
    fn xor_cycle_handles_key_longer_than_input() {
        let plaintext = b"hi";
        let key = b"\x01\x02\x03\x04\x05";
        let out = xor_cycle(plaintext, key);
        assert_eq!(out.as_slice(), &[b'h' ^ 0x01, b'i' ^ 0x02]);
    }

    #[test]
    #[should_panic(expected = "key must be non-empty")]
    fn xor_cycle_panics_on_empty_key_with_nonempty_input() {
        let _ = xor_cycle(b"x", &[]);
    }

    #[test]
    fn format_version_round_trips_through_byte() {
        assert_eq!(FormatVersion::V1.to_byte(), 0x01);
        assert_eq!(FormatVersion::try_from(0x01u8).unwrap(), FormatVersion::V1);
    }

    #[test]
    fn format_version_rejects_unknown_byte() {
        let err = FormatVersion::try_from(0x99u8).unwrap_err();
        assert_eq!(err, UnknownFormatVersion(0x99));
    }

    #[test]
    fn cipher_id_round_trips_through_byte() {
        assert_eq!(CipherId::ChaCha20Poly1305.to_byte(), 0x01);
        assert_eq!(
            CipherId::try_from(0x01u8).unwrap(),
            CipherId::ChaCha20Poly1305,
        );
    }

    #[test]
    fn cipher_id_rejects_unknown_byte() {
        let err = CipherId::try_from(0xFFu8).unwrap_err();
        assert_eq!(err, UnknownCipherId(0xFF));
    }

    #[test]
    fn wrapper_round_trip_layout() {
        let nonce = [0x55u8; NONCE_LEN];
        let body = [0x11u8; WRAPPER_BODY_LEN];
        let wrapper = assemble_wrapper(
            FormatVersion::CURRENT,
            CipherId::ChaCha20Poly1305,
            &nonce,
            &body,
        );
        let parsed = parse_wrapper(&wrapper).expect("round-trip parses");
        assert_eq!(parsed.version, FormatVersion::V1);
        assert_eq!(parsed.cipher, CipherId::ChaCha20Poly1305);
        assert_eq!(parsed.nonce, &nonce);
        assert_eq!(parsed.body, &body);
    }

    #[test]
    fn parse_wrapper_rejects_unknown_version_byte() {
        let nonce = [0u8; NONCE_LEN];
        let body = [0u8; WRAPPER_BODY_LEN];
        let mut wrapper = assemble_wrapper(
            FormatVersion::CURRENT,
            CipherId::ChaCha20Poly1305,
            &nonce,
            &body,
        );
        wrapper[0] = 0x99;
        assert_eq!(
            parse_wrapper(&wrapper).unwrap_err(),
            WrapperParseError::UnknownFormatVersion(0x99),
        );
    }

    #[test]
    fn parse_wrapper_rejects_unknown_cipher_byte() {
        let nonce = [0u8; NONCE_LEN];
        let body = [0u8; WRAPPER_BODY_LEN];
        let mut wrapper = assemble_wrapper(
            FormatVersion::CURRENT,
            CipherId::ChaCha20Poly1305,
            &nonce,
            &body,
        );
        wrapper[1] = 0x99;
        assert_eq!(
            parse_wrapper(&wrapper).unwrap_err(),
            WrapperParseError::UnknownCipherId(0x99),
        );
    }

    #[test]
    fn nonce_for_wrapper_is_deterministic_and_seed_dependent() {
        let a = nonce_for_wrapper(&SEED_A);
        let aa = nonce_for_wrapper(&SEED_A);
        let b = nonce_for_wrapper(&SEED_B);
        assert_eq!(a, aa);
        assert_ne!(a, b);
    }
}
