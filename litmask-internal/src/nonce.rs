//! Deterministic AEAD nonce derivation via BLAKE3.

use crate::{KEY_LEN, NONCE_LEN};

/// Personalization byte string mixed into the keyed BLAKE3 hash for
/// per-call-site nonces. Compile-time only — `nonce_for_call_site` is
/// called from `litmask-macros` proc-macros (which run inside rustc),
/// not from any runtime path, so this string never lands in user
/// binaries. The only requirement is that it differ from
/// `NONCE_TAG_WRAPPER` so the call-site nonce space stays disjoint
/// from the wrapper nonce space under the same seed.
const NONCE_TAG_CALL_SITE: &[u8] = b"call-site";

/// Personalization byte string mixed into the keyed BLAKE3 hash for
/// the wrapper nonce. Compile-time only — `nonce_for_wrapper` is
/// called from `litmask-build` (the build script) at expansion time,
/// not from any runtime path, so this string never lands in user
/// binaries. Must differ from `NONCE_TAG_CALL_SITE`.
const NONCE_TAG_WRAPPER: &[u8] = b"wrapper";

/// Take the first [`NONCE_LEN`] bytes of a BLAKE3 digest as the nonce.
fn truncate_to_nonce(digest: &blake3::Hash) -> [u8; NONCE_LEN] {
    let mut out = [0u8; NONCE_LEN];
    out.copy_from_slice(&digest.as_bytes()[..NONCE_LEN]);
    out
}

/// Derive the wrapper nonce: first [`NONCE_LEN`] bytes of the keyed
/// BLAKE3 hash of a fixed domain-separator string under `seed`.
#[must_use]
pub fn nonce_for_wrapper(seed: &[u8; KEY_LEN]) -> [u8; NONCE_LEN] {
    truncate_to_nonce(&blake3::keyed_hash(seed, NONCE_TAG_WRAPPER))
}

/// Derive a per-call-site nonce: first [`NONCE_LEN`] bytes of the
/// keyed BLAKE3 hash of the `b"call-site"` domain separator
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
/// (`b"call-site"`) differs from the wrapper's
/// (`b"wrapper"`), so the call-site nonce space is
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
    truncate_to_nonce(&hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED_A: [u8; KEY_LEN] = [0xaa; KEY_LEN];
    const SEED_B: [u8; KEY_LEN] = [0xbb; KEY_LEN];

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
        let a = nonce_for_call_site(&SEED_A, "x.rs", 1, 1, b"first");
        let b = nonce_for_call_site(&SEED_A, "x.rs", 1, 1, b"second");
        assert_ne!(a, b);
    }

    #[test]
    fn nonce_for_call_site_unique_across_realistic_spread() {
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
        let a = nonce_for_call_site(&SEED_A, "ab", 1, 1, b"cd");
        let b = nonce_for_call_site(&SEED_A, "a", 1, 1, b"bcd");
        assert_ne!(a, b);
        let c = nonce_for_call_site(&SEED_A, "abc", 1, 1, b"d");
        assert_ne!(a, c);
    }

    #[test]
    fn nonce_for_call_site_independent_of_wrapper_space() {
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
