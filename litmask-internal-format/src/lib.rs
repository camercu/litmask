//! Wire-format constants, typed format/cipher identifiers, and pure
//! layout helpers for the litmask binary format.
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
//!
//! All functions here are pure (no I/O, no global state) and
//! `no_std`-compatible.

#![no_std]

extern crate alloc;

// ── Byte-length constants ───────────────────────────────────────────

/// Length of every symmetric key in bytes. ChaCha20-Poly1305 and
/// AES-256-GCM both use 32-byte keys.
pub const KEY_LEN: usize = 32;

/// AEAD nonce length, shared by ChaCha20-Poly1305 and AES-256-GCM.
pub const NONCE_LEN: usize = 12;

/// AEAD authentication-tag length, shared by both ciphers.
pub const TAG_LEN: usize = 16;

/// 1-byte version + 1-byte cipher id + 12-byte nonce.
pub const HEADER_LEN: usize = 2 + NONCE_LEN;

/// Total wrapper byte count: header + 32-byte encrypted `mask_key` + tag.
pub const WRAPPER_LEN: usize = HEADER_LEN + KEY_LEN + TAG_LEN;

/// BLAKE3 domain separator for per-call-site nonces.
pub const NONCE_TAG_CALL_SITE: &[u8] = b"litmask-nonce";

/// BLAKE3 domain separator for the wrapper nonce.
pub const NONCE_TAG_WRAPPER: &[u8] = b"litmask-mask-key-nonce";

// ── Format version ──────────────────────────────────────────────────

/// Wire-format version of the encrypted-`mask_key` wrapper. Encoded as
/// a single byte at offset 0 of every wrapper.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

// ── Cipher identifier ───────────────────────────────────────────────

/// AEAD cipher identifier. Encoded as a single byte at offset 1 of
/// every wrapper. Used by runtime tooling to confirm the wrapper was
/// produced with the cipher the current binary was compiled to handle.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

// ── Wrapper layout ──────────────────────────────────────────────────

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
pub enum WrapperParseError {
    /// Header byte 0 is not a recognized [`FormatVersion`] value.
    UnknownFormatVersion(u8),
    /// Header byte 1 is not a recognized [`CipherId`] value.
    UnknownCipherId(u8),
}

/// Build a wrapper byte array from typed header fields and the
/// AEAD-encrypted body.
///
/// # Panics
///
/// Panics if `ciphertext_and_tag.len()` is not exactly
/// `KEY_LEN + TAG_LEN` bytes.
#[must_use]
pub fn assemble_wrapper(
    version: FormatVersion,
    cipher: CipherId,
    nonce: &[u8; NONCE_LEN],
    ciphertext_and_tag: &[u8],
) -> [u8; WRAPPER_LEN] {
    assert_eq!(
        ciphertext_and_tag.len(),
        KEY_LEN + TAG_LEN,
        "ciphertext_and_tag must be {} bytes",
        KEY_LEN + TAG_LEN
    );
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
/// slice-to-array conversion is statically sized at [`NONCE_LEN`]; the
/// `expect` exists only as a sanity guard against future drift in
/// [`HEADER_LEN`].
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

// ── AEAD primitive ──────────────────────────────────────────────────

/// Errors surfaced by [`aead_encrypt`] and [`aead_decrypt`]. Today the
/// single variant covers AEAD authentication failure on decrypt; encrypt
/// failures are not reachable for the cipher set this crate supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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
    use chacha20poly1305::aead::{Aead, generic_array::GenericArray};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
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
    use chacha20poly1305::aead::{Aead, generic_array::GenericArray};
    use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
    match cipher_id {
        CipherId::ChaCha20Poly1305 => {
            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
            cipher
                .decrypt(Nonce::from_slice(nonce), body)
                .map_err(|_| AeadError::AuthenticationFailed)
        }
    }
}

// ── XOR-cycle obfuscation ───────────────────────────────────────────

/// XOR every byte of `input` with the corresponding byte of `key`,
/// cycling the key as needed. Writes the result into `out`.
///
/// The operation is its own inverse: applying it twice with the same
/// key recovers the original input. Used by the `weak_mask!` macro to
/// obfuscate string literals against the per-build wrapper bytes so
/// litmask-supplied static strings do not contribute a fixed byte
/// signature to user binaries.
///
/// # Panics
///
/// Panics if `input.len() != out.len()` or if `key.is_empty()` while
/// `input` is non-empty.
pub fn xor_cycle(input: &[u8], key: &[u8], out: &mut [u8]) {
    assert_eq!(
        input.len(),
        out.len(),
        "input and output lengths must match"
    );
    if input.is_empty() {
        return;
    }
    assert!(!key.is_empty(), "key must be non-empty");
    for (i, byte) in input.iter().enumerate() {
        out[i] = byte ^ key[i % key.len()];
    }
}

// ── Nonce derivation ────────────────────────────────────────────────

/// Derive the wrapper nonce: first 12 bytes of the keyed BLAKE3 hash of
/// the fixed domain-separator string [`NONCE_TAG_WRAPPER`] under
/// `seed` as the BLAKE3 key.
///
/// # Panics
///
/// Never panics for valid inputs; the `expect` exists only as a sanity
/// guard against future drift in [`NONCE_LEN`] vs. the BLAKE3 output
/// width.
#[must_use]
pub fn nonce_for_wrapper(seed: &[u8; KEY_LEN]) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(NONCE_TAG_WRAPPER);
    let digest = hasher.finalize();
    digest.as_bytes()[..NONCE_LEN]
        .try_into()
        .expect("BLAKE3 output is at least NONCE_LEN bytes")
}

// The per-call-site nonce is owned by the proc-macro crate
// (`litmask-macros`). The macro derives it from
// `(seed, NONCE_TAG_CALL_SITE, crate_name, counter, literal)` and
// embeds the resulting 12-byte value in the leading bytes of every
// per-string blob, so the runtime never re-derives it.
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

    // ── xor_cycle ───────────────────────────────────────────────────

    #[test]
    fn xor_cycle_empty_input_is_noop() {
        let key = [0xAAu8; 8];
        let mut out = [];
        xor_cycle(&[], &key, &mut out);
    }

    #[test]
    fn xor_cycle_self_inverse_with_matching_lengths() {
        let plaintext = b"hello world";
        let key = b"0123456789ab";
        let mut encoded = [0u8; 11];
        xor_cycle(plaintext, key, &mut encoded);
        let mut decoded = [0u8; 11];
        xor_cycle(&encoded, key, &mut decoded);
        assert_eq!(&decoded, plaintext);
    }

    #[test]
    fn xor_cycle_handles_key_shorter_than_input() {
        // Key cycles: input byte i is XOR'd with key[i % key.len()].
        let plaintext = b"abcdef";
        let key = b"\xff\x55"; // 2-byte key cycling across 6-byte input
        let mut out = [0u8; 6];
        xor_cycle(plaintext, key, &mut out);
        assert_eq!(out[0], b'a' ^ 0xff);
        assert_eq!(out[1], b'b' ^ 0x55);
        assert_eq!(out[2], b'c' ^ 0xff);
        assert_eq!(out[3], b'd' ^ 0x55);
        assert_eq!(out[4], b'e' ^ 0xff);
        assert_eq!(out[5], b'f' ^ 0x55);
    }

    #[test]
    fn xor_cycle_handles_key_longer_than_input() {
        let plaintext = b"hi";
        let key = b"\x01\x02\x03\x04\x05";
        let mut out = [0u8; 2];
        xor_cycle(plaintext, key, &mut out);
        assert_eq!(out[0], b'h' ^ 0x01);
        assert_eq!(out[1], b'i' ^ 0x02);
    }

    #[test]
    #[should_panic(expected = "input and output lengths must match")]
    fn xor_cycle_panics_when_buffers_disagree() {
        let mut out = [0u8; 5];
        xor_cycle(b"hello world", &[0xAA], &mut out);
    }

    #[test]
    #[should_panic(expected = "key must be non-empty")]
    fn xor_cycle_panics_on_empty_key_with_nonempty_input() {
        let mut out = [0u8; 1];
        xor_cycle(b"x", &[], &mut out);
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
        let body = [0x11u8; KEY_LEN + TAG_LEN];
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
        assert_eq!(parsed.body, body.as_slice());
    }

    #[test]
    fn parse_wrapper_rejects_unknown_version_byte() {
        let nonce = [0u8; NONCE_LEN];
        let body = [0u8; KEY_LEN + TAG_LEN];
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
        let body = [0u8; KEY_LEN + TAG_LEN];
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
    #[should_panic(expected = "ciphertext_and_tag must be")]
    fn assemble_wrapper_rejects_short_body() {
        let nonce = [0u8; NONCE_LEN];
        let body = [0u8; KEY_LEN + TAG_LEN - 1];
        let _ = assemble_wrapper(
            FormatVersion::CURRENT,
            CipherId::ChaCha20Poly1305,
            &nonce,
            &body,
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
