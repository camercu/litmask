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

/// Byte offset where the AEAD nonce starts inside a wrapper. The nonce
/// is the only cleartext field and sits at the very front.
pub const NONCE_OFFSET: usize = 0;

/// Length of the AEAD plaintext sealed inside the wrapper:
/// `version_byte (1) || mask_key (32)`. The format-version byte is
/// authenticated rather than carried in cleartext — keeping it out of
/// `.rodata` removes the one fixed-value structural tell a byte scan
/// could match.
pub const WRAPPER_PLAINTEXT_LEN: usize = 1 + KEY_LEN;

/// Length of the AEAD body that follows the cleartext nonce:
/// `ciphertext (33) || tag (16)`.
pub const WRAPPER_BODY_LEN: usize = WRAPPER_PLAINTEXT_LEN + TAG_LEN;

/// Total wrapper byte count: `nonce (12) || ciphertext (33) || tag (16)`
/// = 61 bytes.
pub const WRAPPER_LEN: usize = NONCE_LEN + WRAPPER_BODY_LEN;

// ── Build-artifact filenames ────────────────────────────────────
//
// The `OUT_DIR` filenames the build writes and the proc-macro / runtime
// read. The single source of truth for the on-disk contract, so the
// writer (`litmask-build::emit`) and the readers cannot drift; the
// `artifacts_have_consumers` test pins that every const here is both
// written and read.

/// Plaintext `mask_key` artifact: written by `emit()`, read by the
/// proc-macro to encrypt each `mask!` blob.
pub const KEY_ARTIFACT: &str = "litmask_key.bin";

/// Build-seed artifact: written by `emit()`, read by the proc-macro for
/// per-call-site nonce derivation.
pub const SEED_ARTIFACT: &str = "litmask_seed.bin";

/// Encrypted-`mask_key` wrapper artifact: written by `emit()`, embedded
/// by the runtime via `include_bytes!` (see `litmask`'s `__wrapper_bytes!`,
/// whose hardcoded literal is pinned to this const) and read by
/// `weak_mask!` expansion.
pub const WRAPPER_ARTIFACT: &str = "litmask_wrapper.bin";

// ── Types ───────────────────────────────────────────────────────

/// Wire-format version of the encrypted-`mask_key` wrapper. Encoded as
/// the first byte of the AEAD plaintext (`version_byte || mask_key`),
/// so it is authenticated and never appears in cleartext.
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
    /// Initial build-sealed format. 61-byte wrapper layout
    /// (`nonce || AEAD(version_byte || mask_key) || tag`).
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

/// AEAD cipher identifier. Selected at compile time via
/// [`CURRENT_CIPHER`](crate::CURRENT_CIPHER) and never written to the
/// wire — every wrapper and blob in a binary is encrypted with the one
/// cipher the build was compiled for, so the runtime dispatches on the
/// compiled constant rather than a stored byte.
///
/// `Display` is intentionally omitted — human-readable cipher names
/// would be recognizable string signatures in user binaries.
///
/// Marked `#[non_exhaustive]` so adding a future cipher is non-breaking
/// for downstream exhaustive matches. The cipher is fixed at build time
/// ([`CURRENT_CIPHER`](crate::CURRENT_CIPHER)) and is not recorded on the
/// wire, so the enum is an in-memory dispatch tag only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CipherId {
    /// ChaCha20-Poly1305 AEAD, RFC 8439.
    ChaCha20Poly1305,
    /// AES-256-GCM AEAD, NIST SP 800-38D.
    Aes256Gcm,
}

/// A parsed wrapper, decomposed into its cleartext nonce and the
/// `ciphertext || tag` AEAD body.
///
/// Parsing is purely a length-checked split: the format version lives
/// inside the AEAD plaintext and is validated only after a successful
/// decrypt (see [`decrypt_wrapper`](crate::decrypt_wrapper)).
#[derive(Debug)]
pub struct ParsedWrapper<'a> {
    /// 12-byte AEAD nonce used to encrypt the body.
    pub nonce: &'a [u8; NONCE_LEN],
    /// `ciphertext || tag` — 33 bytes of `version_byte || mask_key`
    /// ciphertext followed by 16 bytes of authentication tag.
    pub body: &'a [u8; WRAPPER_BODY_LEN],
}

// ── Compile-time guards ─────────────────────────────────────────

// These relationships are load-bearing — `assemble_wrapper` /
// `parse_wrapper` index into a `[u8; WRAPPER_LEN]` assuming a
// NONCE_LEN-byte cleartext nonce followed by WRAPPER_BODY_LEN bytes of
// `ciphertext || tag`. A future tweak that breaks the math (changing
// TAG_LEN, the plaintext length, or the nonce offset) silently
// misaligns every wrapper read; these `const _` blocks fail the build
// instead.
const _: () = assert!(NONCE_OFFSET == 0);
const _: () = assert!(WRAPPER_PLAINTEXT_LEN == 1 + KEY_LEN);
const _: () = assert!(WRAPPER_BODY_LEN == WRAPPER_PLAINTEXT_LEN + TAG_LEN);
const _: () = assert!(WRAPPER_LEN == NONCE_LEN + WRAPPER_BODY_LEN);
const _: () = assert!(WRAPPER_LEN > NONCE_LEN);

// ── Functions ───────────────────────────────────────────────────

/// Extract the AEAD nonce from a raw wrapper byte array.
///
/// # Panics
///
/// Never panics — the compile-time asserts in this module guarantee
/// `NONCE_OFFSET + NONCE_LEN <= WRAPPER_LEN`.
#[must_use]
pub(crate) fn wrapper_nonce(wrapper: &[u8; WRAPPER_LEN]) -> &[u8; NONCE_LEN] {
    wrapper[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN]
        .try_into()
        .expect("nonce slice is NONCE_LEN bytes by construction")
}

/// Build a wrapper byte array from the cleartext nonce and the
/// AEAD-encrypted body (`ciphertext || tag` of `version_byte ||
/// mask_key`).
#[must_use]
pub fn assemble_wrapper(
    nonce: &[u8; NONCE_LEN],
    body: &[u8; WRAPPER_BODY_LEN],
) -> [u8; WRAPPER_LEN] {
    let mut out = [0u8; WRAPPER_LEN];
    out[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN].copy_from_slice(nonce);
    out[NONCE_LEN..].copy_from_slice(body);
    out
}

/// Split a wrapper byte array into its cleartext nonce and AEAD body.
///
/// Infallible: there are no cleartext header fields to validate. The
/// authenticated format-version byte is checked by `decrypt_wrapper`
/// after the AEAD tag verifies.
///
/// # Panics
///
/// Never panics for valid `[u8; WRAPPER_LEN]` inputs. The internal
/// slice-to-array conversions are sanity guards against future drift in
/// the wrapper layout.
#[must_use]
pub fn parse_wrapper(bytes: &[u8; WRAPPER_LEN]) -> ParsedWrapper<'_> {
    let nonce = wrapper_nonce(bytes);
    let body: &[u8; WRAPPER_BODY_LEN] = (&bytes[NONCE_LEN..])
        .try_into()
        .expect("body slice is WRAPPER_BODY_LEN bytes by construction");
    ParsedWrapper { nonce, body }
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
    fn wrapper_len_is_sixty_one() {
        assert_eq!(WRAPPER_LEN, 61);
        assert_eq!(WRAPPER_BODY_LEN, 49);
        assert_eq!(WRAPPER_PLAINTEXT_LEN, 33);
    }

    #[test]
    fn wrapper_round_trip_layout() {
        let nonce = [0x55u8; NONCE_LEN];
        let body = [0x11u8; WRAPPER_BODY_LEN];
        let wrapper = assemble_wrapper(&nonce, &body);
        // Nonce sits in cleartext at the very front.
        assert_eq!(&wrapper[..NONCE_LEN], &nonce);
        let parsed = parse_wrapper(&wrapper);
        assert_eq!(parsed.nonce, &nonce);
        assert_eq!(parsed.body, &body);
    }

    proptest::proptest! {
        #[test]
        fn proptest_wrapper_assemble_parse_round_trip(
            nonce in proptest::array::uniform12(proptest::num::u8::ANY),
            body in proptest::array::uniform::<_, WRAPPER_BODY_LEN>(proptest::num::u8::ANY),
        ) {
            let wrapper = assemble_wrapper(&nonce, &body);
            let parsed = parse_wrapper(&wrapper);
            proptest::prop_assert_eq!(parsed.nonce, &nonce);
            proptest::prop_assert_eq!(parsed.body, &body);
        }
    }
}
