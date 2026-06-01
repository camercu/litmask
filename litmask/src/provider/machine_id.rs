//! [`MachineIdProvider`] — derives `unlock_key` from the host's
//! machine ID via BLAKE3-keyed-hash. Feature-gated behind `machine-id`.

use zeroize::Zeroizing;

use crate::error::KeyError;
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// Derives a 32-byte unlock key from the host's machine ID.
/// `unlock_key()` is deterministic per host: two calls on the same
/// machine with the same salt produce byte-identical output, so the
/// binary's wrapper can be encrypted under this key at build time
/// and decrypted at runtime without any secret-distribution channel.
///
/// # Examples
///
/// ```no_run
/// # fn main() -> Result<(), litmask::InitError> {
/// let provider = litmask::MachineIdProvider::with_salt(b"myapp-v1");
/// litmask::init_with!(provider)?;
/// # Ok(())
/// # }
/// ```
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
/// on this provider.
#[derive(Debug)]
pub struct MachineIdProvider {
    salt: Option<&'static [u8]>,
}

impl MachineIdProvider {
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

impl Default for MachineIdProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for MachineIdProvider {
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
        // match `litmask_internal::MACHINE_ID_DERIVATION_CONTEXT`
        // byte-for-byte (which `bind` imports directly) or bind ↔
        // runtime derivations produce different keys; the drift is
        // pinned by the `weak_mask_literal_matches_const` unit
        // test below.
        Ok(UnlockKey::from_raw(crate::internal::derive_machine_id_key(
            crate::weak_mask!("machine-v1"),
            machine_id.as_bytes(),
            self.salt.unwrap_or(&[]),
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
/// Limitation: only the `Display` text survives — a non-empty
/// `source()` chain is dropped at this lift point. Today
/// `machine-uid`'s errors are flat strings, so nothing is lost; if a
/// future version chains an inner cause, accumulate `source()` here
/// before constructing the wrapper.
#[derive(Debug)]
struct MachineUidError(alloc::string::String);

impl core::fmt::Display for MachineUidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.0)
    }
}

impl core::error::Error for MachineUidError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::MACHINE_ID_DERIVATION_CONTEXT;

    #[test]
    fn debug_shows_salt() {
        let p = MachineIdProvider::with_salt(b"myapp-v1");
        let dbg = alloc::format!("{p:?}");
        assert!(dbg.contains("salt"), "Debug must mention salt field");
    }

    #[test]
    fn debug_no_salt_shows_none() {
        let p = MachineIdProvider::new();
        let dbg = alloc::format!("{p:?}");
        assert!(dbg.contains("None"), "Debug must show None when no salt");
    }

    #[test]
    fn machine_id_provider_default_matches_new() {
        // Pin the `Default` impl: it should match `new()` exactly.
        let a = MachineIdProvider::default();
        let b = MachineIdProvider::new();
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
    /// (`KeyProvider::unlock_key` above) inlines `weak_mask!("machine-v1")`
    /// so the BLAKE3 context bytes are obfuscated in user binaries,
    /// while `litmask-cli`'s `bind` imports
    /// `MACHINE_ID_DERIVATION_CONTEXT` directly. The two MUST decode to
    /// the same string or every freshly-bound binary will fail to
    /// unlock: bind would derive its mask key under one context and
    /// runtime would expect a different one. This test verifies the
    /// `weak_mask!()` literal still matches the canonical const.
    #[test]
    fn weak_mask_literal_matches_const() {
        assert_eq!(
            crate::weak_mask!("machine-v1"),
            MACHINE_ID_DERIVATION_CONTEXT
        );
    }
}
