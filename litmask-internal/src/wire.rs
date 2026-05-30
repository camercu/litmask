//! Wire-format types, layout constants, and wrapper assemble/parse.

use core::fmt;

// ── Crypto dimensions ───────────────────────────────────────────

/// Length of every symmetric key in bytes. ChaCha20-Poly1305 and
/// AES-256-GCM both use 32-byte keys.
pub const KEY_LEN: usize = 32;

/// AEAD nonce length, shared by ChaCha20-Poly1305 and AES-256-GCM.
pub const NONCE_LEN: usize = 12;

/// AEAD authentication-tag length, shared by both ciphers.
pub const TAG_LEN: usize = 16;

// ── Wrapper layout ──────────────────────────────────────────────

/// Byte offset of the format-version byte inside a wrapper.
pub const VERSION_OFFSET: usize = 0;

/// Byte offset of the cipher-id byte inside a wrapper.
pub const CIPHER_OFFSET: usize = 1;

/// Byte offset where the AEAD nonce starts inside a wrapper.
pub const NONCE_OFFSET: usize = 2;

/// 1-byte version + 1-byte cipher id + 12-byte nonce.
pub const HEADER_LEN: usize = 2 + NONCE_LEN;

/// Length of the AEAD body that follows the wrapper header: 32 bytes
/// of `mask_key` ciphertext + 16 bytes of authentication tag.
pub const WRAPPER_BODY_LEN: usize = KEY_LEN + TAG_LEN;

/// Total wrapper byte count: header + 32-byte encrypted `mask_key` + tag.
pub const WRAPPER_LEN: usize = HEADER_LEN + KEY_LEN + TAG_LEN;

// ── Wire-format discriminants ───────────────────────────────────

/// On-the-wire byte representing [`FormatVersion::V1`] — the only
/// version current builds produce. Re-exposed as a `u8` constant so
/// downstream consumers (notably `litmask-cli` whose dual-cipher
/// dispatch needs compile-time literals for `match` arms) don't
/// have to write `FormatVersion::V1.to_byte()` at every call site.
pub const FORMAT_V1: u8 = 0x01;

/// On-the-wire byte representing [`CipherId::ChaCha20Poly1305`].
/// Mirrors `CipherId::ChaCha20Poly1305 as u8`; exposed as a free
/// constant so `match cipher_byte` arms in downstream crates can
/// pattern-match without the discriminant cast.
pub const CIPHER_CHACHA20_POLY1305: u8 = 0x01;

/// On-the-wire byte representing [`CipherId::Aes256Gcm`].
/// Companion of [`CIPHER_CHACHA20_POLY1305`].
pub const CIPHER_AES_256_GCM: u8 = 0x02;

// ── Types ───────────────────────────────────────────────────────

/// Wire-format version of the encrypted-`mask_key` wrapper. Encoded as
/// a single byte at offset 0 of every wrapper.
///
/// `Display` is intentionally omitted — human-readable variant names
/// would be recognizable string signatures in user binaries.
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

impl fmt::Display for UnknownFormatVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown format version: {:#04x}", self.0)
    }
}

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
/// `Display` is intentionally omitted — human-readable cipher names
/// would be recognizable string signatures in user binaries.
///
/// Marked `#[non_exhaustive]` so adding AES-256-GCM (and any future
/// cipher) is non-breaking for downstream exhaustive matches.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CipherId {
    /// ChaCha20-Poly1305 AEAD, RFC 8439.
    ChaCha20Poly1305 = 0x01,
    /// AES-256-GCM AEAD, NIST SP 800-38D.
    Aes256Gcm = 0x02,
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

impl fmt::Display for UnknownCipherId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown cipher: {:#04x}", self.0)
    }
}

impl TryFrom<u8> for CipherId {
    type Error = UnknownCipherId;

    fn try_from(byte: u8) -> Result<Self, Self::Error> {
        match byte {
            0x01 => Ok(Self::ChaCha20Poly1305),
            0x02 => Ok(Self::Aes256Gcm),
            other => Err(UnknownCipherId(other)),
        }
    }
}

/// A parsed wrapper, decomposed into its typed header fields plus
/// borrowed nonce and `ciphertext || tag` body.
///
/// The format-version byte is validated during parsing (an unknown
/// version is rejected with [`WrapperParseError::UnknownFormatVersion`])
/// but not retained: only one version exists and no consumer dispatches
/// on it. Cipher, by contrast, drives runtime dispatch and is kept.
#[derive(Debug)]
pub struct ParsedWrapper<'a> {
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
    UnknownFormatVersion(UnknownFormatVersion),
    /// Header byte 1 is not a recognized [`CipherId`] value.
    UnknownCipherId(UnknownCipherId),
}

impl fmt::Display for WrapperParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownFormatVersion(e) => e.fmt(f),
            Self::UnknownCipherId(e) => e.fmt(f),
        }
    }
}

impl From<UnknownFormatVersion> for WrapperParseError {
    fn from(e: UnknownFormatVersion) -> Self {
        Self::UnknownFormatVersion(e)
    }
}

impl From<UnknownCipherId> for WrapperParseError {
    fn from(e: UnknownCipherId) -> Self {
        Self::UnknownCipherId(e)
    }
}

// ── Compile-time guards ─────────────────────────────────────────

// These relationships are load-bearing — `assemble_wrapper` /
// `parse_wrapper` index into a `[u8; WRAPPER_LEN]` assuming
// HEADER_LEN bytes of header followed by WRAPPER_BODY_LEN bytes of
// `ciphertext || tag`. A future tweak that breaks the math (adding a
// header byte, changing TAG_LEN) silently misaligns every wrapper
// read; these `const _` blocks fail the build instead.
const _: () = assert!(HEADER_LEN == 2 + NONCE_LEN);
const _: () = assert!(WRAPPER_BODY_LEN == KEY_LEN + TAG_LEN);
const _: () = assert!(NONCE_LEN < HEADER_LEN);
const _: () = assert!(WRAPPER_LEN > HEADER_LEN);
// Offset constants are load-bearing for the wrapper layout (§1.7.3)
// AND for every downstream byte-pattern match (litmask-cli dispatches
// on `wrapper[CIPHER_OFFSET]`). Pin the three offsets so a future
// header-byte addition reorders them only after the matching
// wire-format version bump.
const _: () = assert!(VERSION_OFFSET == 0);
const _: () = assert!(CIPHER_OFFSET == 1);
const _: () = assert!(NONCE_OFFSET == 2);
const _: () = assert!(NONCE_OFFSET + NONCE_LEN == HEADER_LEN);
const _: () = assert!(WRAPPER_LEN == HEADER_LEN + WRAPPER_BODY_LEN);
// Discriminant constants must equal their `CipherId` / `FormatVersion`
// counterparts. A future variant rename or discriminant swap would
// break the byte-level match arms in downstream crates without
// touching the enum — this guard catches the drift at compile time.
const _: () = assert!(FORMAT_V1 == FormatVersion::V1 as u8);
const _: () = assert!(CIPHER_CHACHA20_POLY1305 == CipherId::ChaCha20Poly1305 as u8);
const _: () = assert!(CIPHER_AES_256_GCM == CipherId::Aes256Gcm as u8);

// ── Functions ───────────────────────────────────────────────────

/// Extract the AEAD nonce from a raw wrapper byte array without
/// parsing or validating the header fields.
///
/// # Panics
///
/// Never panics — the compile-time asserts in this module guarantee
/// `NONCE_OFFSET + NONCE_LEN == HEADER_LEN <= WRAPPER_LEN`.
#[must_use]
pub fn wrapper_nonce(wrapper: &[u8; WRAPPER_LEN]) -> &[u8; NONCE_LEN] {
    wrapper[NONCE_OFFSET..HEADER_LEN]
        .try_into()
        .expect("nonce slice is NONCE_LEN bytes by construction")
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
    out[VERSION_OFFSET] = version.to_byte();
    out[CIPHER_OFFSET] = cipher.to_byte();
    out[NONCE_OFFSET..HEADER_LEN].copy_from_slice(nonce);
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
    // Validate the version byte (rejects unknown versions) but discard
    // the value — see `ParsedWrapper` for why it is not retained.
    FormatVersion::try_from(bytes[VERSION_OFFSET])?;
    let cipher = CipherId::try_from(bytes[CIPHER_OFFSET])?;
    let nonce: &[u8; NONCE_LEN] = (&bytes[NONCE_OFFSET..HEADER_LEN])
        .try_into()
        .expect("nonce slice is NONCE_LEN bytes by construction");
    let body: &[u8; WRAPPER_BODY_LEN] = (&bytes[HEADER_LEN..])
        .try_into()
        .expect("body slice is WRAPPER_BODY_LEN bytes by construction");
    Ok(ParsedWrapper {
        cipher,
        nonce,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

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
            WrapperParseError::UnknownFormatVersion(UnknownFormatVersion(0x99)),
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
            WrapperParseError::UnknownCipherId(UnknownCipherId(0x99)),
        );
    }

    proptest::proptest! {
        #[test]
        fn proptest_wrapper_assemble_parse_round_trip(
            nonce in proptest::array::uniform12(proptest::num::u8::ANY),
            body in proptest::array::uniform::<_, WRAPPER_BODY_LEN>(proptest::num::u8::ANY),
        ) {
            let wrapper = assemble_wrapper(
                FormatVersion::CURRENT,
                CipherId::ChaCha20Poly1305,
                &nonce,
                &body,
            );
            let parsed = parse_wrapper(&wrapper).expect("assembled wrappers always parse");
            proptest::prop_assert_eq!(parsed.cipher, CipherId::ChaCha20Poly1305);
            proptest::prop_assert_eq!(parsed.nonce, &nonce);
            proptest::prop_assert_eq!(parsed.body, &body);
        }
    }
}
