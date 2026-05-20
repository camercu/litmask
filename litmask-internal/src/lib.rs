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

pub mod base64url;
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

// Compile-time guards on wire-format invariants. These relationships
// are load-bearing — `assemble_wrapper` / `parse_wrapper` index into a
// `[u8; WRAPPER_LEN]` assuming HEADER_LEN bytes of header followed by
// WRAPPER_BODY_LEN bytes of `ciphertext || tag`. A future tweak that
// breaks the math (adding a header byte, changing TAG_LEN) silently
// misaligns every wrapper read; these `const _` blocks fail the build
// instead.
const _: () = assert!(HEADER_LEN == 2 + NONCE_LEN);
const _: () = assert!(WRAPPER_LEN == HEADER_LEN + KEY_LEN + TAG_LEN);
const _: () = assert!(NONCE_LEN < HEADER_LEN);
const _: () = assert!(WRAPPER_LEN > HEADER_LEN);

/// BLAKE3 domain separator for per-call-site nonces.
const NONCE_TAG_CALL_SITE: &[u8] = b"litmask-nonce";

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

const _: () = assert!(WRAPPER_BODY_LEN == KEY_LEN + TAG_LEN);
const _: () = assert!(WRAPPER_LEN == HEADER_LEN + WRAPPER_BODY_LEN);

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
    // BLAKE3 emits a 32-byte digest; NONCE_LEN (12) cannot exceed that.
    // The slice would panic if a future BLAKE3 API change shortened
    // the output below NONCE_LEN.
    debug_assert!(digest.as_bytes().len() >= NONCE_LEN);
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    out
}

/// Derive a per-call-site nonce: first [`NONCE_LEN`] bytes of the
/// keyed BLAKE3 hash of the `"litmask-nonce"` domain separator
/// followed by the call site's `file` path, `line`, `column`, and
/// the `plaintext` being encrypted — all keyed on `seed`.
///
/// **Why include plaintext.** `mask_format!` synthesizes one `mask!()`
/// per template fragment with all fragments routed through the
/// `mask_format!` invocation's span, so the `(file, line, column)`
/// triple alone is not unique across mask invocations within a
/// single proc-macro expansion. Mixing the plaintext into the
/// keyed hash guarantees that two `mask!()` calls with distinct
/// plaintexts at the same span get distinct nonces — required for
/// AEAD security, since encrypting two plaintexts under one
/// `(key, nonce)` pair would XOR-leak their contents.
///
/// **Why (file, line, column) at all.** Keying on source
/// coordinates instead of an expansion-order counter makes nonces
/// stable under parallel macro expansion (`-Z threads=N`): two
/// `mask!()` calls at distinct source positions receive distinct
/// nonces regardless of which rustc thread visited first. The
/// counter-based scheme this replaces relied on sequential
/// expansion and would race under parallelization.
///
/// **Encoding.** `line` and `column` are 4-byte little-endian.
/// `file` carries an 8-byte little-endian length prefix so its
/// byte stream cannot be ambiguously decoded as a distinct tuple
/// whose file/line boundary lies elsewhere. `plaintext` is the
/// trailing variable-length field, so any change to its bytes
/// changes the hash output directly — no length prefix needed.
///
/// **Seed keying.** The seed-keyed hash is hardening, not a
/// security boundary: the nonce ships in plaintext at the head of
/// every blob. Keying on the seed prevents source coordinates and
/// plaintext-length patterns from showing up as recognizable
/// structure in `.rodata`.
///
/// **Domain separation.** The call-site domain separator
/// (`"litmask-nonce"`) differs from the wrapper's
/// (`"litmask-mask-key-nonce"`), so the call-site nonce space is
/// disjoint from the wrapper's at the same seed.
#[must_use]
pub fn nonce_for_call_site(
    seed: &[u8; KEY_LEN],
    file: &str,
    line: u32,
    column: u32,
    plaintext: &[u8],
) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(NONCE_TAG_CALL_SITE);
    hasher.update(&(file.len() as u64).to_le_bytes());
    hasher.update(file.as_bytes());
    hasher.update(&line.to_le_bytes());
    hasher.update(&column.to_le_bytes());
    hasher.update(plaintext);
    let digest = hasher.finalize();
    debug_assert!(digest.as_bytes().len() >= NONCE_LEN);
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    out
}

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

    #[test]
    fn nonce_for_call_site_is_deterministic() {
        // Same (seed, file, line, column, plaintext) MUST yield the
        // same nonce — identical sources rebuilt with the same seed
        // produce byte-identical ciphertext (§2.1.1.8).
        for (file, line, column, plaintext) in [
            ("a.rs", 1u32, 1u32, b"x".as_slice()),
            ("src/lib.rs", 42, 17, b"long-plaintext-value".as_slice()),
            (
                "/abs/very/deep/path/mod.rs",
                u32::MAX,
                u32::MAX,
                b"".as_slice(),
            ),
        ] {
            let first = nonce_for_call_site(&SEED_A, file, line, column, plaintext);
            let second = nonce_for_call_site(&SEED_A, file, line, column, plaintext);
            assert_eq!(first, second, "non-deterministic at {file}:{line}:{column}",);
        }
    }

    #[test]
    fn nonce_for_call_site_changes_with_seed() {
        let a = nonce_for_call_site(&SEED_A, "x.rs", 1, 1, b"p");
        let b = nonce_for_call_site(&SEED_B, "x.rs", 1, 1, b"p");
        assert_ne!(a, b);
    }

    #[test]
    fn nonce_for_call_site_changes_with_file() {
        let a = nonce_for_call_site(&SEED_A, "a.rs", 1, 1, b"p");
        let b = nonce_for_call_site(&SEED_A, "b.rs", 1, 1, b"p");
        assert_ne!(a, b);
    }

    #[test]
    fn nonce_for_call_site_changes_with_line() {
        let a = nonce_for_call_site(&SEED_A, "x.rs", 1, 1, b"p");
        let b = nonce_for_call_site(&SEED_A, "x.rs", 2, 1, b"p");
        assert_ne!(a, b);
    }

    #[test]
    fn nonce_for_call_site_changes_with_column() {
        let a = nonce_for_call_site(&SEED_A, "x.rs", 1, 1, b"p");
        let b = nonce_for_call_site(&SEED_A, "x.rs", 1, 2, b"p");
        assert_ne!(a, b);
    }

    #[test]
    fn nonce_for_call_site_changes_with_plaintext() {
        // Multiple synthesized `mask!()` calls can share the same
        // (file, line, column) — e.g., `mask_format!` emits one
        // `mask!()` per template fragment with all fragments
        // routed through the `mask_format!` invocation's span.
        // Distinct plaintexts at the same span MUST get distinct
        // nonces; otherwise two ciphertexts share `(key, nonce)`
        // and their XOR leaks plaintext.
        let a = nonce_for_call_site(&SEED_A, "x.rs", 1, 1, b"first");
        let b = nonce_for_call_site(&SEED_A, "x.rs", 1, 1, b"second");
        assert_ne!(a, b);
    }

    #[test]
    fn nonce_for_call_site_unique_across_realistic_spread() {
        // AEAD requires unique (key, nonce) per plaintext. A
        // realistic crate spread — 16 files × 32 lines × 4 columns
        // × 2 distinct plaintexts = 4096 distinct logical sites
        // — MUST yield distinct nonces in full.
        let mut seen = alloc::collections::BTreeSet::new();
        for f in 0..16u32 {
            for l in 0..32u32 {
                for c in 0..4u32 {
                    for p in [b"alpha".as_slice(), b"beta".as_slice()] {
                        let file = alloc::format!("crate/src/file_{f}.rs");
                        let nonce = nonce_for_call_site(&SEED_A, &file, l, c, p);
                        assert!(seen.insert(nonce), "collision at {file}:{l}:{c}");
                    }
                }
            }
        }
        assert_eq!(seen.len(), 16 * 32 * 4 * 2);
    }

    #[test]
    fn nonce_for_call_site_canonical_encoding() {
        // Length-prefixing of file and plaintext prevents adjacent
        // variable-length fields from being ambiguously decoded.
        // Without the prefix, ("a", line=0x62, ...) could share a
        // byte stream with ("ab", line=0x00, ...) where 'b' bleeds
        // from file into the line bytes. Lock the property: tuples
        // that differ only in where the file/plaintext boundary
        // falls MUST produce distinct nonces.
        let a = nonce_for_call_site(&SEED_A, "ab", 1, 1, b"cd");
        let b = nonce_for_call_site(&SEED_A, "a", 1, 1, b"bcd");
        assert_ne!(a, b);
        let c = nonce_for_call_site(&SEED_A, "abc", 1, 1, b"d");
        assert_ne!(a, c);
    }

    #[test]
    fn nonce_for_call_site_independent_of_wrapper_space() {
        // The call-site and wrapper derivations key on the same
        // seed but distinct domain separators, so collisions
        // between the two spaces at the same seed are vanishingly
        // unlikely. Spot-check several call sites to confirm.
        let wrapper = nonce_for_wrapper(&SEED_A);
        for (file, line, column, plaintext) in [
            ("a.rs", 0u32, 0u32, b"p".as_slice()),
            ("b.rs", 1, 1, b"".as_slice()),
            ("/c.rs", u32::MAX, u32::MAX, b"longer".as_slice()),
        ] {
            assert_ne!(
                wrapper,
                nonce_for_call_site(&SEED_A, file, line, column, plaintext),
                "{file}:{line}:{column} collided with wrapper",
            );
        }
    }
}
