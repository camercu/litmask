//! Canonical layout constants and pure layout helpers for the litmask
//! binary format.
//!
//! **Internal crate.** Not part of the public litmask API. Versioned in
//! lockstep with `litmask`; do not depend on this crate directly. The
//! `litmask`, `litmask-build`, and `litmask-macros` crates all depend
//! on this one for a single canonical definition of:
//!
//! - The wrapper format (§1.7.3): version byte, cipher-id byte, nonce,
//!   ciphertext + tag layout, total length.
//! - The per-string blob format (§1.7.2): nonce prefix + ciphertext +
//!   tag layout.
//! - BLAKE3 nonce domain separators and derivation algorithms
//!   (§1.5.2 + §1.7.3).
//!
//! Functions here are pure (no I/O, no global state) and `no_std`-
//! compatible.

#![no_std]

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

/// Current wrapper format version (§1.7.3).
pub const WRAPPER_VERSION: u8 = 0x01;

/// Cipher identifier for ChaCha20-Poly1305 (§1.7.3 + §2.7.9).
pub const CIPHER_ID_CHACHA20: u8 = 0x01;

/// BLAKE3 domain separator for per-call-site nonces (§1.5.2).
pub const NONCE_TAG_CALL_SITE: &[u8] = b"litmask-nonce";

/// BLAKE3 domain separator for the wrapper nonce (§1.7.3).
pub const NONCE_TAG_WRAPPER: &[u8] = b"litmask-mask-key-nonce";

/// Build a 62-byte wrapper from its 12-byte nonce and the 48-byte
/// `ciphertext || tag` produced by ChaCha20-Poly1305.
///
/// # Panics
///
/// Panics if `ciphertext_and_tag` is not exactly `KEY_LEN + TAG_LEN`
/// bytes. Callers within the litmask crates always supply the
/// canonical length; this assertion catches future drift.
#[must_use]
pub fn assemble_wrapper(nonce: &[u8; NONCE_LEN], ciphertext_and_tag: &[u8]) -> [u8; WRAPPER_LEN] {
    assert_eq!(
        ciphertext_and_tag.len(),
        KEY_LEN + TAG_LEN,
        "ciphertext_and_tag must be {} bytes",
        KEY_LEN + TAG_LEN
    );
    let mut out = [0u8; WRAPPER_LEN];
    out[0] = WRAPPER_VERSION;
    out[1] = CIPHER_ID_CHACHA20;
    out[2..HEADER_LEN].copy_from_slice(nonce);
    out[HEADER_LEN..].copy_from_slice(ciphertext_and_tag);
    out
}

/// Decompose a wrapper into `(version, cipher_id, nonce, body)` where
/// `body` is the `ciphertext || tag` slice.
///
/// # Panics
///
/// Never panics for valid `[u8; WRAPPER_LEN]` inputs. The internal
/// slice-to-array conversion is statically sized at `NONCE_LEN`; the
/// `expect` exists only as a sanity guard against future drift in
/// `HEADER_LEN`.
#[must_use]
pub fn parse_wrapper(bytes: &[u8; WRAPPER_LEN]) -> (u8, u8, &[u8; NONCE_LEN], &[u8]) {
    // The slicing arithmetic is constant; const_eval guarantees the
    // shapes match WRAPPER_LEN. `try_into` is OK at this size; failure
    // would mean a constant mismatch caught at the call site.
    let nonce_slice: &[u8; NONCE_LEN] = (&bytes[2..HEADER_LEN])
        .try_into()
        .expect("nonce slice is NONCE_LEN bytes by construction");
    (bytes[0], bytes[1], nonce_slice, &bytes[HEADER_LEN..])
}

/// Derive the wrapper nonce (§1.7.3): first 12 bytes of
/// `BLAKE3-keyed-hash(seed, "litmask-mask-key-nonce")`.
///
/// # Panics
///
/// Never panics for any inputs; `BLAKE3`'s output is always ≥ `NONCE_LEN`
/// bytes.
#[must_use]
pub fn nonce_for_wrapper(seed: &[u8; KEY_LEN]) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(NONCE_TAG_WRAPPER);
    let digest = hasher.finalize();
    digest.as_bytes()[..NONCE_LEN]
        .try_into()
        .expect("blake3 output ≥ NONCE_LEN bytes")
}

/// Spec-canonical per-call-site nonce (§1.5.2): first 12 bytes of
/// `BLAKE3-keyed-hash(seed, "litmask-nonce" || file || ":" || line || ":" || column)`.
///
/// Task 5's proc-macro uses a counter-based variant because stable Rust's
/// `proc_macro::Span` does not expose file/line/column accessors as of
/// 1.88. This function is the authoritative algorithm and the target
/// for unit-test coverage; the proc-macro will adopt it once stable
/// Span APIs ship or the implementation opts in to
/// `procmacro2_semver_exempt`.
///
/// # Panics
///
/// Never panics for any inputs.
#[must_use]
pub fn nonce_for_call_site(
    seed: &[u8; KEY_LEN],
    file: &str,
    line: u32,
    column: u32,
) -> [u8; NONCE_LEN] {
    // Render `line` and `column` as decimal text without allocating, so
    // this fn stays usable from no_std + alloc and from build / proc-macro
    // crates without additional deps. `u32::MAX` fits in 10 digits.
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
        .expect("blake3 output ≥ NONCE_LEN bytes")
}

/// Write `n` as decimal ASCII bytes into `buf`, returning the written
/// slice. Always writes at least `"0"`. Avoids the `alloc::string::ToString`
/// dependency so this fn stays usable from `no_std` consumers.
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
    // tmp now has digits in reverse order; flip into buf.
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
    fn wrapper_round_trip_layout() {
        let nonce = [0x55u8; NONCE_LEN];
        let body = [0x11u8; KEY_LEN + TAG_LEN];
        let wrapper = assemble_wrapper(&nonce, &body);
        let (version, cipher_id, n, b) = parse_wrapper(&wrapper);
        assert_eq!(version, WRAPPER_VERSION);
        assert_eq!(cipher_id, CIPHER_ID_CHACHA20);
        assert_eq!(n, &nonce);
        assert_eq!(b, body.as_slice());
    }

    #[test]
    #[should_panic(expected = "ciphertext_and_tag must be")]
    fn assemble_wrapper_rejects_short_body() {
        let nonce = [0u8; NONCE_LEN];
        let body = [0u8; KEY_LEN + TAG_LEN - 1];
        let _ = assemble_wrapper(&nonce, &body);
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
        // Demonstrate that the (5, 0) site's nonce is unchanged
        // regardless of how many other distinct sites the caller
        // evaluates first or after — mirrors §1.5.2's "adding code
        // elsewhere in the file does not change unaffected nonces"
        // property.
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
