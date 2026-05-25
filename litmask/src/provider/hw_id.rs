//! [`HardwareIdProvider`] — derives `unlock_key` from the host's
//! machine ID via BLAKE3-keyed-hash. Feature-gated behind `hw-id`.
//! §2.5.4, §1.6.5.

use zeroize::Zeroizing;

use crate::error::KeyError;
use crate::internal::KEY_LEN;
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

// The BLAKE3 `derive_key` context for hw-id key derivation is the
// short literal `"hw-v1"`. The runtime call site below routes it
// through `crate::weak_mask!()` so the string is obfuscated in user
// binaries (the runtime path is the one place this constant would
// otherwise land in `strings(1)` output). `litmask-cli`'s `bind`
// subcommand imports the canonical value from
// `litmask_internal::HW_ID_DERIVATION_CONTEXT` directly — CLI tools
// don't need the obfuscation. The literal-vs-const drift between
// the two sides is pinned by `weak_mask_literal_matches_const` in
// the test module below.

/// Derives a 32-byte unlock key from the host's machine ID
/// (§2.5.4.3). `unlock_key()` is deterministic per host: two calls
/// on the same machine with the same salt produce byte-identical
/// output, so the binary's wrapper can be encrypted under this
/// key at build time and decrypted at runtime without any
/// secret-distribution channel.
///
/// # Salt
///
/// Salt is `Option<&'static [u8]>`. `with_salt(b"...")` mixes the
/// salt into the BLAKE3-keyed-hash derivation so two products
/// running on the same host but compiled with different salts
/// recover distinct unlock keys.
///
/// # Failure mode
///
/// `machine-uid::get()` can fail on container runtimes,
/// `/etc/machine-id`-less embedded Linux variants, and OpenBSD by
/// default. The failure surfaces as [`KeyError::Provider`] carrying
/// the upstream error. Cross-compilation users targeting such
/// environments MUST verify behavior on the target before relying
/// on this provider (§1.6.5).
pub struct HardwareIdProvider {
    salt: Option<&'static [u8]>,
}

impl HardwareIdProvider {
    /// Construct a provider with no salt. The derived key depends
    /// only on the host machine ID.
    #[must_use]
    pub const fn new() -> Self {
        Self { salt: None }
    }

    /// Construct a provider that mixes `salt` into the derived key.
    /// Salt is a compile-time constant — the type forces this so a
    /// runtime-supplied salt does not silently invalidate the
    /// build's wrapper encryption.
    #[must_use]
    pub const fn with_salt(salt: &'static [u8]) -> Self {
        Self { salt: Some(salt) }
    }
}

impl Default for HardwareIdProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for HardwareIdProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        // `machine_uid::get()`'s error type is a `Box<dyn Error>`
        // without the `Send + Sync` bound that [`KeyError::Provider`]
        // requires (for cross-thread propagation). Lift it into a
        // `Send + Sync` wrapper that carries the upstream `Display`
        // message verbatim — the `source()` chain on the original
        // box is not preserved (see `MachineUidError`'s docstring).
        let machine_id = machine_uid::get().map_err(|e| {
            KeyError::Provider(alloc::boxed::Box::new(MachineUidError(alloc::format!(
                "{e}"
            ))))
        })?;
        // Wrap the machine id in Zeroizing so the heap copy of the
        // identifier wipes when this function returns — without it,
        // a stable host identifier would linger in the allocator
        // even though `UnlockKey` zeroizes the derived key.
        let machine_id = Zeroizing::new(machine_id);
        // `weak_mask!()` keeps the BLAKE3 context literal out of
        // `strings(1)` output for user binaries. The literal MUST
        // match `litmask_internal::HW_ID_DERIVATION_CONTEXT`
        // byte-for-byte (which `bind` imports directly) or bind ↔
        // runtime derivations produce different keys; the drift is
        // pinned by the `weak_mask_literal_matches_const` unit
        // test below.
        Ok(UnlockKey::from_raw(derive_hw_key(
            crate::weak_mask!("hw-v1"),
            machine_id.as_bytes(),
            self.salt,
        )))
    }
}

/// Send + Sync wrapper around an upstream `machine-uid` failure.
///
/// `machine-uid::get()`'s native error is `Box<dyn Error>` without
/// the `Send + Sync` bound that [`KeyError::Provider`] requires.
/// This shim captures the upstream's `Display` rendering into an
/// owned `String` and re-impls `Error` to satisfy the bound.
///
/// **If `machine-uid` ever wraps a nested cause.** Today its errors
/// are flat strings, so capturing `Display` alone preserves every
/// rendered diagnostic byte. A future `machine-uid` upgrade that
/// chains an inner `io::Error` (or anything else with a non-empty
/// `source()`) would silently drop the chain at this lift point —
/// when that upgrade lands, walk `source()` here and accumulate the
/// chain into the owned `String` (e.g. via the `: ` separator
/// convention) before constructing `MachineUidError` so operators
/// keep seeing the full root cause.
#[derive(Debug)]
struct MachineUidError(alloc::string::String);

impl core::fmt::Display for MachineUidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for MachineUidError {}

/// Pure BLAKE3-keyed-hash derivation: produce a 32-byte unlock key
/// from `(context, machine_id, salt)`. `context` is the BLAKE3
/// `derive_key` domain separator; the runtime caller passes the
/// `weak_mask!`-decoded form so tests can supply
/// `HW_ID_DERIVATION_CONTEXT` directly without depending on
/// `weak_mask!`'s wrapper-XOR machinery.
///
/// Derivation: `blake3::derive_key` over the salt (or the empty
/// byte string when no salt) produces a 32-byte BLAKE3 key, then
/// `blake3::keyed_hash` of `machine_id` under that key. The
/// derive-key step domain-separates from every other BLAKE3 use in
/// the workspace; the keyed hash binds the machine id into the
/// 32-byte output without revealing the bare machine id in the
/// output.
fn derive_hw_key(context: &str, machine_id: &[u8], salt: Option<&'static [u8]>) -> [u8; KEY_LEN] {
    let salt_bytes = salt.unwrap_or(&[]);
    let key = blake3::derive_key(context, salt_bytes);
    let mac = blake3::keyed_hash(&key, machine_id);
    *mac.as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::HW_ID_DERIVATION_CONTEXT;

    #[test]
    fn derive_hw_key_is_deterministic_for_same_inputs() {
        // The runtime deployment depends on this property: the
        // build's wrapper is encrypted under derive_hw_key(ctx,
        // machine_id, salt) at build time; the binary recovers the
        // same key at runtime. A non-deterministic derivation would
        // brick every hw-id deployment.
        let machine_id = b"fixed-test-machine-id";
        let a = derive_hw_key(HW_ID_DERIVATION_CONTEXT, machine_id, None);
        let b = derive_hw_key(HW_ID_DERIVATION_CONTEXT, machine_id, None);
        assert_eq!(a, b);
        let a_salt = derive_hw_key(HW_ID_DERIVATION_CONTEXT, machine_id, Some(b"salt-A"));
        let b_salt = derive_hw_key(HW_ID_DERIVATION_CONTEXT, machine_id, Some(b"salt-A"));
        assert_eq!(a_salt, b_salt);
    }

    #[test]
    fn derive_hw_key_differs_across_salts() {
        // Different salts on the same machine-id MUST produce
        // distinct keys; otherwise two products sharing a host
        // would also share an unlock key, defeating the purpose of
        // per-product salting.
        let machine_id = b"fixed-test-machine-id";
        let unsalted = derive_hw_key(HW_ID_DERIVATION_CONTEXT, machine_id, None);
        let salt_a = derive_hw_key(HW_ID_DERIVATION_CONTEXT, machine_id, Some(b"salt-A"));
        let salt_b = derive_hw_key(HW_ID_DERIVATION_CONTEXT, machine_id, Some(b"salt-B"));
        assert_ne!(unsalted, salt_a);
        assert_ne!(unsalted, salt_b);
        assert_ne!(salt_a, salt_b);
    }

    #[test]
    fn derive_hw_key_differs_across_machine_ids() {
        // Two distinct hosts MUST produce distinct keys for the same
        // salt; the hardware binding is the whole point.
        let salt = Some(b"shared-salt".as_slice());
        let host_a = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"host-A", salt);
        let host_b = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"host-B", salt);
        assert_ne!(host_a, host_b);
    }

    #[test]
    fn derive_hw_key_returns_full_32_bytes() {
        // BLAKE3 output is 32 bytes; the helper relies on that to
        // populate the UnlockKey buffer directly. A future BLAKE3
        // API change that shortened the output would silently zero-
        // pad the tail of the key — the property test pins the
        // current shape.
        let key = derive_hw_key(HW_ID_DERIVATION_CONTEXT, b"any-host", None);
        assert_eq!(key.len(), KEY_LEN);
        // Sanity: BLAKE3 of a fixed input is not the all-zero vector.
        assert!(key.iter().any(|&b| b != 0));
    }

    #[test]
    fn hardware_id_provider_default_matches_new() {
        // Pin the `Default` impl: it should match `new()` exactly.
        let a = HardwareIdProvider::default();
        let b = HardwareIdProvider::new();
        assert_eq!(a.salt, b.salt);
    }

    /// Static bound assertion: `MachineUidError` must satisfy
    /// `Send + Sync` so it can populate `KeyError::Provider`'s
    /// `Box<dyn Error + Send + Sync>` slot. A regression in the
    /// trait bounds surfaces at compile time via this `const fn`.
    const fn assert_send_sync<T: Send + Sync>() {}

    #[test]
    fn machine_uid_error_carries_display_message_verbatim() {
        let wrapped = MachineUidError(alloc::string::String::from("simulated upstream error"));
        assert_eq!(alloc::format!("{wrapped}"), "simulated upstream error");
        assert_send_sync::<MachineUidError>();
    }

    /// Pin the literal-vs-const drift: the runtime call site
    /// (`KeyProvider::unlock_key` above) inlines `weak_mask!("hw-v1")`
    /// so the BLAKE3 context bytes are obfuscated in user binaries,
    /// while `litmask-cli`'s `bind` imports
    /// `HW_ID_DERIVATION_CONTEXT` directly. The two MUST decode to
    /// the same string or every freshly-bound binary will fail to
    /// unlock: bind would derive its mask key under one context and
    /// runtime would expect a different one. This test verifies the
    /// `weak_mask!()` literal still matches the canonical const.
    #[test]
    fn weak_mask_literal_matches_const() {
        assert_eq!(crate::weak_mask!("hw-v1"), HW_ID_DERIVATION_CONTEXT);
    }
}
