//! Key derivation: machine-id key and weak XOR key.

use crate::{KEY_LEN, NONCE_LEN, WRAPPER_LEN, wrapper_nonce};

/// BLAKE3 `derive_key` domain separator for the machine-id key
/// derivation. Shared verbatim by:
///
/// - `litmask::provider::MachineIdProvider` (runtime side)
/// - `litmask-cli`'s `bind` subcommand (build-time side)
///
/// Stays deliberately short and library-identifier-free: this string
/// is the ONE BLAKE3 separator that lands in user binaries (the
/// runtime path is `MachineIdProvider::unlock_key`), so every byte
/// here is a `strings(1)`-visible byte. The only requirements are
/// (a) global uniqueness in the BLAKE3 `derive_key` namespace
/// (workspace-internal: it's the only `derive_key` call) and (b)
/// byte-for-byte stability across the bind / runtime boundary
/// (centralizing here means Cargo's incremental rebuild catches any
/// drift). The `-v1` suffix reserves a rotation path if a future
/// security review invalidates the current derivation.
///
/// Changing this constant is a BREAKING change: every previously
/// bound binary fails to decrypt under the new context. Treat as a
/// major-version event.
pub const MACHINE_ID_DERIVATION_CONTEXT: &str = "machine-v1";

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
/// internally — so the runtime caller ([`EmbeddedProvider`]) can pass
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
/// `BLAKE3::derive_key(context, material)`. Unlike the Embedded path,
/// `material` is arbitrary-length operator input, so the derivation
/// normalizes it to a fixed 32-byte key — callers pass raw bytes with
/// no pre-hashing. Build and runtime call this with the same material
/// to reach the identical key. Domain-separated from
/// [`derive_embedded_unlock_key`] and [`derive_machine_id_key`] by its
/// distinct context.
#[must_use]
pub fn derive_external_unlock_key(context: &str, material: &[u8]) -> [u8; KEY_LEN] {
    blake3::derive_key(context, material)
}

/// Derive a 32-byte key from `(context, machine_id, salt)` via BLAKE3.
///
/// Shared by [`MachineIdProvider`](https://docs.rs/litmask) (runtime)
/// and the `litmask bind` command (CLI). The runtime caller passes
/// the context through `weak_mask!()` so the literal doesn't appear
/// in user binaries; the CLI imports [`MACHINE_ID_DERIVATION_CONTEXT`]
/// directly.
///
/// Derivation: `BLAKE3::derive_key(context, len(machine_id) ||
/// machine_id || salt)`, where `len` is an 8-byte little-endian length
/// prefix. Length-prefixing `machine_id` prevents concatenation
/// ambiguity — without it, `(id=b"ab", salt=b"cd")` and
/// `(id=b"abc", salt=b"d")` would hash the same input. The 8-byte
/// width matches the call-site nonce's `file` prefix
/// ([`nonce_for_call_site`](crate::nonce_for_call_site)) so the crate
/// uses one length-prefix convention throughout.
#[must_use]
pub fn derive_machine_id_key(context: &str, machine_id: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(&(machine_id.len() as u64).to_le_bytes());
    hasher.update(machine_id);
    hasher.update(salt);
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

    #[test]
    fn derive_machine_id_key_is_deterministic() {
        let a = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, b"host-1", b"");
        let b = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, b"host-1", b"");
        assert_eq!(a, b);
        let a_s = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, b"host-1", b"salt-A");
        let b_s = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, b"host-1", b"salt-A");
        assert_eq!(a_s, b_s);
    }

    #[test]
    fn derive_machine_id_key_differs_across_salts() {
        let machine_id = b"fixed-test-machine-id";
        let unsalted = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, machine_id, b"");
        let salt_a = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, machine_id, b"salt-A");
        let salt_b = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, machine_id, b"salt-B");
        assert_ne!(unsalted, salt_a);
        assert_ne!(unsalted, salt_b);
        assert_ne!(salt_a, salt_b);
    }

    #[test]
    fn derive_machine_id_key_differs_across_machine_ids() {
        let salt = b"shared-salt";
        let host_a = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, b"host-A", salt);
        let host_b = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, b"host-B", salt);
        assert_ne!(host_a, host_b);
    }

    #[test]
    fn derive_machine_id_key_returns_full_32_bytes() {
        let key = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, b"any-host", b"");
        assert_eq!(key.len(), KEY_LEN);
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn derive_machine_id_key_no_concatenation_ambiguity() {
        let a = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, b"ab", b"cd");
        let b = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, b"abc", b"d");
        assert_ne!(a, b);
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
        let machine = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, &bytes, b"");
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

    /// The external-tier context must domain-separate from both the
    /// embedded and machine-id contexts: identical input bytes hashed
    /// under a different `derive_key` context must never collide, so a
    /// key minted for one tier can never be reused for another.
    #[test]
    fn derive_external_unlock_key_domain_separated_from_other_contexts() {
        let bytes = [0x11u8; NONCE_LEN];
        let external = derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, &bytes);
        let embedded = derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &bytes);
        let machine = derive_machine_id_key(MACHINE_ID_DERIVATION_CONTEXT, &bytes, b"");
        assert_ne!(external, embedded);
        assert_ne!(external, machine);
    }
}
