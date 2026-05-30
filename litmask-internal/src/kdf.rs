//! Key derivation: hardware-id key and weak XOR key.

use crate::{KEY_LEN, NONCE_LEN, WRAPPER_LEN, wrapper_nonce};

/// BLAKE3 `derive_key` domain separator for the hardware-id key
/// derivation. Shared verbatim by:
///
/// - `litmask::provider::HardwareIdProvider` (runtime side)
/// - `litmask-cli`'s `bind` subcommand (build-time side)
///
/// Stays deliberately short and library-identifier-free: this string
/// is the ONE BLAKE3 separator that lands in user binaries (the
/// runtime path is `HardwareIdProvider::unlock_key`), so every byte
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
pub const HW_ID_DERIVATION_CONTEXT: &str = "hw-v1";

/// Length of the derived `weak_mask!` XOR key: bit-rotated nonce
/// expansion (32) + BLAKE3 keyed hash (32) = 64 bytes.
pub const WEAK_XOR_KEY_LEN: usize = KEY_LEN + KEY_LEN;

/// Derive a 32-byte key from `(context, machine_id, salt)` via BLAKE3.
///
/// Shared by [`HardwareIdProvider`](https://docs.rs/litmask) (runtime)
/// and `litmask-cli bind` (CLI). The runtime caller passes the context
/// through `weak_mask!()` so the literal doesn't appear in user
/// binaries; the CLI imports [`HW_ID_DERIVATION_CONTEXT`] directly.
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
pub fn derive_hw_key(context: &str, machine_id: &[u8], salt: &[u8]) -> [u8; KEY_LEN] {
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
/// Keying on the nonce (stable across `bind`) lets `weak_mask!`
/// literals survive wrapper re-encryption.
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
    fn derive_hw_key_is_deterministic() {
        let a = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"host-1", b"");
        let b = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"host-1", b"");
        assert_eq!(a, b);
        let a_s = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"host-1", b"salt-A");
        let b_s = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"host-1", b"salt-A");
        assert_eq!(a_s, b_s);
    }

    #[test]
    fn derive_hw_key_differs_across_salts() {
        let machine_id = b"fixed-test-machine-id";
        let unsalted = derive_hw_key(HW_ID_DERIVATION_CONTEXT, machine_id, b"");
        let salt_a = derive_hw_key(HW_ID_DERIVATION_CONTEXT, machine_id, b"salt-A");
        let salt_b = derive_hw_key(HW_ID_DERIVATION_CONTEXT, machine_id, b"salt-B");
        assert_ne!(unsalted, salt_a);
        assert_ne!(unsalted, salt_b);
        assert_ne!(salt_a, salt_b);
    }

    #[test]
    fn derive_hw_key_differs_across_machine_ids() {
        let salt = b"shared-salt";
        let host_a = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"host-A", salt);
        let host_b = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"host-B", salt);
        assert_ne!(host_a, host_b);
    }

    #[test]
    fn derive_hw_key_returns_full_32_bytes() {
        let key = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"any-host", b"");
        assert_eq!(key.len(), KEY_LEN);
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn derive_hw_key_no_concatenation_ambiguity() {
        let a = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"ab", b"cd");
        let b = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"abc", b"d");
        assert_ne!(a, b);
    }
}
