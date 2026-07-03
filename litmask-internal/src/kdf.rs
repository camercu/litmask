//! Key derivation: machine-id key and weak XOR key.

use crate::{KEY_LEN, NONCE_LEN, WRAPPER_LEN, wrapper_nonce};

/// BLAKE3 `derive_key` domain separator for the machine-id key
/// derivation. The runtime `MachineIdProvider` and the build-time
/// machine seal (`litmask-build::emit`) both derive under this context,
/// so a `machine`-tier binary opens against the machine id recomputed
/// on the target host.
///
/// The runtime caller passes this value through `weak_mask!()` so the
/// literal does not land in user binaries; build / CLI sides pass the
/// const directly. The two MUST match byte-for-byte or build ↔ runtime
/// derivations diverge.
///
/// The `-v1` suffix reserves a rotation path. Changing this constant is
/// a BREAKING change: every previously sealed binary fails to decrypt
/// under the new context. Treat as a major-version event.
pub const MACHINE_ID_DERIVATION_CONTEXT: &str = "litmask-machine-id-v1";

/// BLAKE3 `derive_key` domain separator for the machine-id **salt**.
///
/// The machine salt is no longer user-supplied: it is derived from the
/// public wrapper nonce as `BLAKE3::derive_key(this, wrapper_nonce)`, so
/// two products sealed on the same host but with different builds (hence
/// different nonces) recover distinct machine keys without the consumer
/// choosing a salt. Domain-separated from
/// [`MACHINE_ID_DERIVATION_CONTEXT`] so the salt derivation and the key
/// derivation never collide.
///
/// Like the machine context, the runtime caller passes this through
/// `weak_mask!()`; build / CLI sides pass the const directly. The
/// `-v1` suffix reserves a rotation path; changing it is BREAKING.
pub const MACHINE_ID_SALT_DERIVATION_CONTEXT: &str = "litmask-machine-id-salt-v1";

/// Length of the derived `weak_mask!` XOR key: bit-rotated nonce
/// expansion (32) + BLAKE3 keyed hash (32) = 64 bytes.
pub const WEAK_XOR_KEY_LEN: usize = KEY_LEN + KEY_LEN;

/// BLAKE3 `derive_key` domain separator for the Embedded-tier
/// `unlock_key`.
///
/// The Embedded tier is the keyless obfuscation floor: the `unlock_key`
/// is recomputed — at build and at runtime — from the public wrapper
/// nonce alone, so an Embedded-tier binary opens with no stored key
/// material. This makes the floor honestly recoverable from the
/// artifact (the nonce ships in cleartext); the Embedded tier buys
/// `strings(1)` resistance, not secrecy.
///
/// The `-v1` suffix reserves a rotation path. Changing this constant is
/// a BREAKING change: every Embedded-tier wrapper sealed under the old
/// context fails to decrypt under the new one.
pub const EMBEDDED_UNLOCK_DERIVATION_CONTEXT: &str = "litmask-embedded-v1";

/// Derive the Embedded-tier `unlock_key` from the wrapper nonce.
///
/// `BLAKE3::derive_key(context, wrapper_nonce)`. The nonce is
/// fixed-width (`NONCE_LEN`), so no length prefix is needed to avoid
/// concatenation ambiguity. Build and runtime call this with the same
/// nonce to reach the identical key with nothing stored between them.
///
/// `context` is taken as a parameter — rather than read from the const
/// internally — so the runtime caller (`EmbeddedProvider`) can pass
/// it through `weak_mask!()`, keeping the literal out of `strings(1)`
/// output. The build/CLI side passes [`EMBEDDED_UNLOCK_DERIVATION_CONTEXT`]
/// directly. The two MUST match byte-for-byte or build ↔ runtime
/// derivations diverge; the drift is pinned by a unit test in
/// `litmask::provider::embedded`. Mirrors [`derive_machine_id_key`].
#[must_use]
pub fn derive_embedded_unlock_key(context: &str, wrapper_nonce: &[u8; NONCE_LEN]) -> [u8; KEY_LEN] {
    blake3::derive_key(context, wrapper_nonce)
}

/// BLAKE3 `derive_key` domain separator for the External-tier
/// `unlock_key`.
///
/// The External tier sources its key material from a runtime channel
/// (env var, file, or operator-supplied expression). The framework
/// never trusts that material as a key directly — it always runs it
/// through `BLAKE3::derive_key` under this context, so any byte string
/// (regardless of length or entropy shape) normalizes to a 32-byte
/// `unlock_key`. Build and runtime MUST use this same context or
/// sealed wrappers fail to open.
///
/// The `-v1` suffix reserves a rotation path. Changing this constant is
/// a BREAKING change: every External-tier wrapper sealed under the old
/// context fails to decrypt under the new one.
pub const EXTERNAL_UNLOCK_DERIVATION_CONTEXT: &str = "litmask-unlock-v1";

/// Derive the External-tier `unlock_key` from runtime key material.
///
/// `BLAKE3::derive_key(context, strip_trailing_newline(material))`.
/// Unlike the Embedded path, `material` is arbitrary-length operator
/// input, so the derivation normalizes it to a fixed 32-byte key —
/// callers pass raw bytes with no pre-hashing. Build and runtime call
/// this with the same material to reach the identical key. Domain-
/// separated from [`derive_embedded_unlock_key`] and
/// [`derive_machine_id_key`] by its distinct context.
///
/// The single-trailing-newline normalization ([`strip_trailing_newline`])
/// is applied here, inside the derivation, so every external channel
/// (env var, key file, build seal) agrees on one secret without each
/// call site repeating the strip — and so the at-most-one-newline
/// invariant cannot drift between them. Callers MUST NOT pre-strip:
/// doing so would remove a second newline that is part of the secret.
#[must_use]
pub fn derive_external_unlock_key(context: &str, material: &[u8]) -> [u8; KEY_LEN] {
    blake3::derive_key(context, strip_trailing_newline(material))
}

/// Strip a single trailing line ending (`\r\n` or `\n`) from external
/// key material.
///
/// Text channels disagree on trailing newlines: editors append one
/// when saving a key file, while an environment variable carrying the
/// same secret has none. Without normalization the two channels derive
/// different `unlock_key`s and decryption silently fails. Both the
/// runtime providers (`EnvVarProvider`, `FileProvider`) and the build
/// seal (`litmask-build::emit`) call this so all three reach
/// byte-identical material. Only one newline is removed (a second is
/// part of the secret) and only a newline — trailing spaces/tabs are
/// preserved, since a raw secret may legitimately end in one.
#[must_use]
pub fn strip_trailing_newline(material: &[u8]) -> &[u8] {
    if let Some(stripped) = material.strip_suffix(b"\r\n") {
        stripped
    } else if let Some(stripped) = material.strip_suffix(b"\n") {
        stripped
    } else {
        material
    }
}

/// Whether external key material is empty *as the KDF sees it* — empty
/// after the single-trailing-newline strip ([`strip_trailing_newline`]).
/// An unpopulated secret lands here: a CI variable that expanded to `""`,
/// a touched-but-empty key file, a lone editor-appended newline.
///
/// The build seal (`litmask-build::emit`) rejects empty material so it
/// can never seal under a key derived from zero bytes; the runtime
/// providers reject it so an unpopulated secret surfaces as a named
/// misconfiguration rather than a generic decrypt failure. Both call
/// this, so "empty" means the same thing on both sides — the same
/// build↔runtime agreement [`strip_trailing_newline`] exists for, kept
/// beside it so the two halves live at one site.
#[must_use]
pub fn is_empty_external_material(material: &[u8]) -> bool {
    strip_trailing_newline(material).is_empty()
}

/// Derive the machine-tier 32-byte `unlock_key` from the host machine
/// id and the build's wrapper nonce.
///
/// Used by both `MachineIdProvider` (runtime) and the build-time machine
/// seal (`litmask-build::emit`). The runtime caller passes `context` and
/// `salt_context` through `weak_mask!()` so neither literal appears in
/// user binaries; the build / CLI side passes
/// [`MACHINE_ID_DERIVATION_CONTEXT`] and
/// [`MACHINE_ID_SALT_DERIVATION_CONTEXT`] directly. Both pairs MUST match
/// byte-for-byte or build ↔ runtime derivations diverge.
///
/// The salt is **not** caller-supplied: it is `BLAKE3::derive_key(
/// salt_context, wrapper_nonce)`, binding the machine key to the
/// per-build nonce. The key itself is `BLAKE3::derive_key(context,
/// len(machine_id) || machine_id || salt)`, where `len` is an 8-byte
/// little-endian length prefix. Length-prefixing `machine_id` prevents
/// concatenation ambiguity with the trailing salt; the 8-byte width
/// matches the call-site nonce's `file` prefix
/// ([`nonce_for_call_site`](crate::nonce_for_call_site)) so the crate
/// uses one length-prefix convention throughout.
///
/// The output is a finished `unlock_key`: single-factor machine seals
/// use it verbatim, and two-factor composition (§2.3) takes it as one
/// compose input.
#[must_use]
pub fn derive_machine_id_key(
    context: &str,
    salt_context: &str,
    machine_id: &[u8],
    wrapper_nonce: &[u8; NONCE_LEN],
) -> [u8; KEY_LEN] {
    let salt = blake3::derive_key(salt_context, wrapper_nonce);
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&(machine_id.len() as u64).to_le_bytes());
    hasher.update(machine_id);
    hasher.update(&salt);
    *hasher.finalize().as_bytes()
}

/// BLAKE3 `derive_key` domain separator for the two-factor
/// (`machine_id + <external>`) composed `unlock_key`.
///
/// The two-factor tier composes the machine factor's finished
/// `unlock_key` with the external factor's finished `unlock_key` under
/// this context (§2.3). The distinct `-2fa-` segment guarantees a
/// two-factor key can never collide with a single-factor one even on
/// identical input bytes — domain-separated from every
/// `derive_*_unlock_key` context above.
///
/// The `-v1` suffix reserves a rotation path. Changing this constant is
/// a BREAKING change: every two-factor wrapper sealed under the old
/// context fails to decrypt under the new one.
pub const TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT: &str = "litmask-2fa-v1";

/// Compose the machine and external factors' finished `unlock_key`s into
/// the two-factor `unlock_key`.
///
/// `BLAKE3::derive_key(context, len(machine) ‖ machine ‖ len(external) ‖
/// external)`, where each `len` is an 8-byte little-endian length prefix
/// — the crate-wide length-prefix convention (see
/// [`derive_machine_id_key`] / [`nonce_for_call_site`](crate::nonce_for_call_site)).
/// Order is fixed by construction (machine first), so there is no
/// argument-order surface to get wrong; the length prefixes remove any
/// concatenation ambiguity between the two 32-byte inputs.
///
/// Both inputs are already finished `unlock_key`s — the machine factor
/// via [`derive_machine_id_key`], the external factor via
/// [`derive_external_unlock_key`] — so this is a pure mixing step over
/// two fixed-width keys, never raw material. The build seals under this
/// exact computation; the runtime `UnlockKey::compose` wraps it via
/// `weak_mask!()` so the context literal stays out of `strings(1)`. The
/// two MUST match byte-for-byte or build ↔ runtime derivations diverge.
#[must_use]
pub fn derive_two_factor_unlock_key(
    context: &str,
    machine_key: &[u8; KEY_LEN],
    external_key: &[u8; KEY_LEN],
) -> [u8; KEY_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&(machine_key.len() as u64).to_le_bytes());
    hasher.update(machine_key);
    hasher.update(&(external_key.len() as u64).to_le_bytes());
    hasher.update(external_key);
    *hasher.finalize().as_bytes()
}

/// Derive the XOR key used by `weak_mask!` from the wrapper nonce.
///
/// Returns `rotated(32) || BLAKE3::keyed_hash(rotated, nonce)(32)`:
/// 64 bytes total. The first half expands the 12-byte nonce into 32
/// bytes via position-dependent bit rotation; the second half
/// stretches it through BLAKE3 keyed mode. No string literals are
/// used — domain separation comes from BLAKE3's keyed-mode IV.
/// Keying on the cleartext wrapper nonce (rather than the sealed
/// `mask_key`) lets `weak_mask!` expand before `init!()`, when no key
/// material has been recovered yet.
#[must_use]
pub fn derive_weak_xor_key(wrapper: &[u8; WRAPPER_LEN]) -> [u8; WEAK_XOR_KEY_LEN] {
    let nonce: &[u8] = wrapper_nonce(wrapper);
    let mut rotated = [0u8; KEY_LEN];
    for i in 0..KEY_LEN {
        #[allow(clippy::cast_possible_truncation)]
        let shift = (i as u32) % 8;
        rotated[i] = nonce[i % NONCE_LEN].rotate_left(shift);
    }
    let hashed = blake3::keyed_hash(&rotated, nonce);
    let mut out = [0u8; WEAK_XOR_KEY_LEN];
    out[..KEY_LEN].copy_from_slice(&rotated);
    out[KEY_LEN..].copy_from_slice(hashed.as_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: derive the machine key under the canonical contexts so the
    /// tests below pin behavior (salt-source, id-source, nonce-source),
    /// not the literal context strings.
    fn machine_key(machine_id: &[u8], nonce: &[u8; NONCE_LEN]) -> [u8; KEY_LEN] {
        derive_machine_id_key(
            MACHINE_ID_DERIVATION_CONTEXT,
            MACHINE_ID_SALT_DERIVATION_CONTEXT,
            machine_id,
            nonce,
        )
    }

    #[test]
    fn derive_machine_id_key_is_deterministic() {
        let nonce = [0x07u8; NONCE_LEN];
        assert_eq!(
            machine_key(b"host-1", &nonce),
            machine_key(b"host-1", &nonce)
        );
    }

    /// The salt is nonce-derived, so the same host id under different
    /// build nonces recovers distinct keys — the per-build binding that
    /// replaces the old user-supplied salt.
    #[test]
    fn derive_machine_id_key_differs_across_nonces() {
        let machine_id = b"fixed-test-machine-id";
        let nonce_a = [0x01u8; NONCE_LEN];
        let nonce_b = [0x02u8; NONCE_LEN];
        assert_ne!(
            machine_key(machine_id, &nonce_a),
            machine_key(machine_id, &nonce_b)
        );
    }

    #[test]
    fn derive_machine_id_key_differs_across_machine_ids() {
        let nonce = [0x09u8; NONCE_LEN];
        assert_ne!(
            machine_key(b"host-A", &nonce),
            machine_key(b"host-B", &nonce)
        );
    }

    #[test]
    fn derive_machine_id_key_returns_full_32_bytes() {
        let key = machine_key(b"any-host", &[0x11u8; NONCE_LEN]);
        assert_eq!(key.len(), KEY_LEN);
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn derive_machine_id_key_no_concatenation_ambiguity() {
        let nonce = [0x22u8; NONCE_LEN];
        let a = machine_key(b"ab", &nonce);
        let b = machine_key(b"abc", &nonce);
        assert_ne!(a, b);
    }

    /// The salt context must domain-separate from the key context: the
    /// salt derivation and the key derivation read the same nonce bytes,
    /// so a context collision would let the salt equal a key (or vice
    /// versa). Swapping the two contexts must change the output.
    #[test]
    fn derive_machine_id_key_salt_context_is_domain_separated() {
        let machine_id = b"host-z";
        let nonce = [0x33u8; NONCE_LEN];
        let canonical = machine_key(machine_id, &nonce);
        let swapped = derive_machine_id_key(
            MACHINE_ID_SALT_DERIVATION_CONTEXT,
            MACHINE_ID_DERIVATION_CONTEXT,
            machine_id,
            &nonce,
        );
        assert_ne!(canonical, swapped);
    }

    #[test]
    fn derive_embedded_unlock_key_is_deterministic() {
        let nonce = [0x07u8; NONCE_LEN];
        assert_eq!(
            derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &nonce),
            derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &nonce)
        );
    }

    #[test]
    fn derive_embedded_unlock_key_differs_across_nonces() {
        let a =
            derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &[0x01u8; NONCE_LEN]);
        let b =
            derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &[0x02u8; NONCE_LEN]);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_embedded_unlock_key_returns_full_32_bytes() {
        let key =
            derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &[0x09u8; NONCE_LEN]);
        assert_eq!(key.len(), KEY_LEN);
        assert!(key.iter().any(|&b| b != 0));
    }

    /// The Embedded-tier context must domain-separate from the
    /// machine-id context: the same input bytes under a different
    /// `derive_key` context must not collide, so a key minted for one
    /// tier can never be reused for another.
    #[test]
    fn derive_embedded_unlock_key_domain_separated_from_machine_context() {
        let bytes = [0x11u8; NONCE_LEN];
        let embedded = derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &bytes);
        let machine = derive_machine_id_key(
            MACHINE_ID_DERIVATION_CONTEXT,
            MACHINE_ID_SALT_DERIVATION_CONTEXT,
            &bytes,
            &bytes,
        );
        assert_ne!(embedded, machine);
    }

    #[test]
    fn derive_external_unlock_key_is_deterministic() {
        let material = b"operator-supplied-secret";
        assert_eq!(
            derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, material),
            derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, material)
        );
    }

    #[test]
    fn derive_external_unlock_key_differs_across_material() {
        let a = derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, b"material-A");
        let b = derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, b"material-B");
        assert_ne!(a, b);
    }

    #[test]
    fn derive_external_unlock_key_accepts_arbitrary_length_material() {
        let short = derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, b"x");
        let long = derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, &[0x5au8; 1024]);
        assert_eq!(short.len(), KEY_LEN);
        assert_eq!(long.len(), KEY_LEN);
        assert!(long.iter().any(|&b| b != 0));
    }

    /// The newline-normalization invariant lives inside the external KDF,
    /// not at each call site: material carrying an editor-appended `\n` or
    /// `\r\n` derives the same key as the bare secret, so every external
    /// channel (env, file, build seal) agrees without repeating a strip.
    /// Only one newline is removed — a second is part of the secret.
    #[test]
    fn derive_external_unlock_key_strips_one_trailing_newline() {
        let bare = derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, b"secret");
        assert_eq!(
            derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, b"secret\n"),
            bare,
        );
        assert_eq!(
            derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, b"secret\r\n"),
            bare,
        );
        assert_ne!(
            derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, b"secret\n\n"),
            bare,
        );
    }

    #[test]
    fn derive_two_factor_unlock_key_is_deterministic() {
        let m = [0x11u8; KEY_LEN];
        let e = [0x22u8; KEY_LEN];
        assert_eq!(
            derive_two_factor_unlock_key(TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT, &m, &e),
            derive_two_factor_unlock_key(TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT, &m, &e),
        );
    }

    /// Order is fixed by construction (machine first). Swapping the two
    /// factors must change the output, or a build sealing `machine ‖
    /// external` could be opened by a runtime composing `external ‖
    /// machine` — the order-significance the 2fa context exists to pin.
    #[test]
    fn derive_two_factor_unlock_key_is_order_sensitive() {
        let m = [0x11u8; KEY_LEN];
        let e = [0x22u8; KEY_LEN];
        assert_ne!(
            derive_two_factor_unlock_key(TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT, &m, &e),
            derive_two_factor_unlock_key(TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT, &e, &m),
        );
    }

    #[test]
    fn derive_two_factor_unlock_key_differs_across_each_factor() {
        let base = derive_two_factor_unlock_key(
            TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT,
            &[0x11u8; KEY_LEN],
            &[0x22u8; KEY_LEN],
        );
        let other_machine = derive_two_factor_unlock_key(
            TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT,
            &[0x33u8; KEY_LEN],
            &[0x22u8; KEY_LEN],
        );
        let other_external = derive_two_factor_unlock_key(
            TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT,
            &[0x11u8; KEY_LEN],
            &[0x44u8; KEY_LEN],
        );
        assert_ne!(base, other_machine);
        assert_ne!(base, other_external);
    }

    /// The two-factor context must domain-separate from every
    /// single-factor context: composing two keys whose bytes happen to
    /// equal a single-factor derivation's inputs must never collide with
    /// that single-factor key. Pin it against the machine context (the
    /// nearest neighbor, since the machine key is one compose input).
    #[test]
    fn derive_two_factor_unlock_key_domain_separated_from_single_factor() {
        let m = [0x11u8; KEY_LEN];
        let e = [0x22u8; KEY_LEN];
        let two_factor = derive_two_factor_unlock_key(TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT, &m, &e);
        // Same bytes fed through the machine single-factor derivation.
        let nonce = [0x11u8; NONCE_LEN];
        let machine = derive_machine_id_key(
            MACHINE_ID_DERIVATION_CONTEXT,
            MACHINE_ID_SALT_DERIVATION_CONTEXT,
            &m,
            &nonce,
        );
        assert_ne!(two_factor, machine);
    }

    #[test]
    fn derive_two_factor_unlock_key_returns_full_32_bytes() {
        let key = derive_two_factor_unlock_key(
            TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT,
            &[0x11u8; KEY_LEN],
            &[0x22u8; KEY_LEN],
        );
        assert_eq!(key.len(), KEY_LEN);
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn strip_trailing_newline_removes_single_lf() {
        assert_eq!(strip_trailing_newline(b"secret\n"), b"secret");
    }

    #[test]
    fn strip_trailing_newline_removes_single_crlf() {
        assert_eq!(strip_trailing_newline(b"secret\r\n"), b"secret");
    }

    #[test]
    fn strip_trailing_newline_leaves_at_most_one() {
        // Only the editor-appended newline is removed; a second trailing
        // newline is part of the secret and must survive.
        assert_eq!(strip_trailing_newline(b"secret\n\n"), b"secret\n");
    }

    #[test]
    fn strip_trailing_newline_preserves_no_newline_and_inner_newlines() {
        assert_eq!(strip_trailing_newline(b"secret"), b"secret");
        assert_eq!(strip_trailing_newline(b"a\nb"), b"a\nb");
    }

    #[test]
    fn strip_trailing_newline_preserves_trailing_non_newline_whitespace() {
        // Raw secrets may legitimately end in a space or tab — only a
        // newline is treated as the editor footgun.
        assert_eq!(strip_trailing_newline(b"secret "), b"secret ");
        assert_eq!(strip_trailing_newline(b""), b"");
    }

    /// Empty *as the KDF sees it*: after the at-most-one-newline strip.
    /// Locks the build↔runtime agreement on what unpopulated material is,
    /// so a divergence here (which would make seals un-openable) is a
    /// test failure, not a silent field bug.
    #[test]
    fn is_empty_external_material_matches_the_kdf_view() {
        assert!(is_empty_external_material(b""));
        assert!(is_empty_external_material(b"\n"));
        assert!(is_empty_external_material(b"\r\n"));
        // Only one newline is stripped, so a second is real material.
        assert!(!is_empty_external_material(b"\n\n"));
        // Trailing spaces/tabs are real material, matching the strip.
        assert!(!is_empty_external_material(b" "));
        assert!(!is_empty_external_material(b"secret"));
    }

    /// The external-tier context must domain-separate from both the
    /// embedded and machine-id contexts: identical input bytes hashed
    /// under a different `derive_key` context must never collide, so a
    /// key minted for one tier can never be reused for another.
    #[test]
    fn derive_external_unlock_key_domain_separated_from_other_contexts() {
        let bytes = [0x11u8; NONCE_LEN];
        let external = derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, &bytes);
        let embedded = derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &bytes);
        let machine = derive_machine_id_key(
            MACHINE_ID_DERIVATION_CONTEXT,
            MACHINE_ID_SALT_DERIVATION_CONTEXT,
            &bytes,
            &bytes,
        );
        assert_ne!(external, embedded);
        assert_ne!(external, machine);
    }
}
