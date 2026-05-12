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
    pub body: &'a [u8],
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
    Ok(ParsedWrapper {
        version,
        cipher,
        nonce,
        body: &bytes[HEADER_LEN..],
    })
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

/// Derive a per-call-site nonce: first 12 bytes of the keyed BLAKE3
/// hash of `NONCE_TAG_CALL_SITE || file || ":" || line || ":" || column`
/// under `seed` as the BLAKE3 key.
///
/// This is the canonical (file, line, column)-keyed algorithm. The
/// proc-macro currently uses a counter-based variant because stable
/// Rust's `proc_macro::Span` does not expose those accessors; the
/// canonical algorithm lives here so the runtime decrypt path and
/// unit tests share one implementation.
///
/// # Panics
///
/// Never panics for valid inputs; the `expect` exists only as a sanity
/// guard against future drift in [`NONCE_LEN`] vs. the BLAKE3 output
/// width.
#[must_use]
pub fn nonce_for_call_site(
    seed: &[u8; KEY_LEN],
    file: &str,
    line: u32,
    column: u32,
) -> [u8; NONCE_LEN] {
    // Render `line` and `column` as decimal text without allocating, so
    // this fn stays usable from no_std + alloc consumers.
    let mut line_buf = [0u8; 10];
    let mut col_buf = [0u8; 10];
    let line_bytes = u32_to_decimal(line, &mut line_buf);
    let col_bytes = u32_to_decimal(column, &mut col_buf);

    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(NONCE_TAG_CALL_SITE);
    hasher.update(file.as_bytes());
    hasher.update(b":");
    hasher.update(line_bytes);
    hasher.update(b":");
    hasher.update(col_bytes);
    let digest = hasher.finalize();
    digest.as_bytes()[..NONCE_LEN]
        .try_into()
        .expect("BLAKE3 output is at least NONCE_LEN bytes")
}

/// Write `n` as decimal ASCII bytes into `buf`, returning the written
/// slice. Always writes at least `"0"`. Avoids the
/// `alloc::string::ToString` dependency so this fn stays usable from
/// `no_std` consumers.
fn u32_to_decimal(mut n: u32, buf: &mut [u8; 10]) -> &[u8] {
    if n == 0 {
        buf[0] = b'0';
        return &buf[..1];
    }
    let mut len = 0usize;
    let mut tmp = [0u8; 10];
    while n > 0 {
        tmp[len] = b'0' + u8::try_from(n % 10).expect("digit 0-9 fits in u8");
        n /= 10;
        len += 1;
    }
    // tmp holds digits in reverse order; flip into buf.
    for (i, &b) in tmp[..len].iter().rev().enumerate() {
        buf[i] = b;
    }
    &buf[..len]
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: [u8; KEY_LEN] = [0xaa; KEY_LEN];
    const SEED_B: [u8; KEY_LEN] = [0xbb; KEY_LEN];

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

    #[test]
    fn call_site_nonce_determinism_and_independence() {
        let a = nonce_for_call_site(&SEED_A, "src/lib.rs", 42, 7);
        let aa = nonce_for_call_site(&SEED_A, "src/lib.rs", 42, 7);
        let b = nonce_for_call_site(&SEED_A, "src/lib.rs", 42, 8);
        let c = nonce_for_call_site(&SEED_A, "src/main.rs", 42, 7);
        let d = nonce_for_call_site(&SEED_B, "src/lib.rs", 42, 7);
        assert_eq!(a, aa);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(a, d);
    }

    #[test]
    fn call_site_nonce_independent_of_unrelated_sites() {
        // The (5, 0) site's nonce is invariant under derivation of
        // nonces for unrelated locations — the spec property that
        // "adding code elsewhere in the file does not change unaffected
        // nonces."
        let pinned = nonce_for_call_site(&SEED_A, "src/lib.rs", 5, 0);
        for line in 11..100u32 {
            let _ignored = nonce_for_call_site(&SEED_A, "src/lib.rs", line, 0);
        }
        let pinned_again = nonce_for_call_site(&SEED_A, "src/lib.rs", 5, 0);
        assert_eq!(pinned, pinned_again);
    }

    #[test]
    fn wrapper_and_call_site_nonces_differ_at_same_seed() {
        let w = nonce_for_wrapper(&SEED_A);
        let cs = nonce_for_call_site(&SEED_A, "src/lib.rs", 0, 0);
        assert_ne!(w, cs, "domain separators must yield distinct nonces");
    }

    #[test]
    fn u32_to_decimal_edges() {
        let mut buf = [0u8; 10];
        assert_eq!(u32_to_decimal(0, &mut buf), b"0");
        assert_eq!(u32_to_decimal(1, &mut buf), b"1");
        assert_eq!(u32_to_decimal(42, &mut buf), b"42");
        assert_eq!(u32_to_decimal(1_000_000_000, &mut buf), b"1000000000");
        assert_eq!(u32_to_decimal(u32::MAX, &mut buf), b"4294967295");
    }
}
