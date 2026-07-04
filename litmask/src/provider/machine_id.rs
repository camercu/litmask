//! [`MachineIdProvider`] — derives the machine-tier `unlock_key` from
//! the host's machine id and the build's wrapper nonce. Feature-gated
//! behind `machine-id`.

use zeroize::Zeroizing;

use crate::error::KeyError;
use crate::internal::{MachineId, NONCE_LEN, WRAPPER_LEN, derive_machine_id_key, parse_wrapper};
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// Derives the machine-tier 32-byte `unlock_key` from the host machine
/// id and the build's wrapper nonce.
///
/// Crate-private: a machine-sealed binary reaches this provider only
/// through the `init!(bind_to_machine)` seam ([`crate::__internal`]), which
/// injects the embedded wrapper nonce at the call site. The macro never
/// names the type — expansion lands in the consumer crate, which cannot
/// reach a `pub(crate)` symbol — so there is no public constructor.
///
/// `unlock_key()` is deterministic per (host, build): the salt is the
/// wrapper nonce, so two products built on the same host but with
/// different nonces recover distinct keys, and the same product opens
/// only on the host whose id matches the seal. No secret-distribution
/// channel is needed — the runtime recomputes the host id locally.
///
/// # Failure mode
///
/// `machine-uid::get()` can fail on container runtimes,
/// `/etc/machine-id`-less embedded Linux variants, and OpenBSD by
/// default. The failure surfaces as [`KeyError::Provider`] carrying the
/// upstream error. Cross-compilation users targeting such environments
/// MUST verify behavior on the target before relying on this provider.
#[derive(Debug)]
pub(crate) struct MachineIdProvider {
    // Non-secret: the wrapper nonce is public and ships in cleartext, so
    // no zeroize-on-drop is warranted. The salt is derived from it inside
    // `derive_machine_id_key`.
    nonce: [u8; NONCE_LEN],
}

impl MachineIdProvider {
    /// Capture the wrapper's cleartext nonce so [`unlock_key`] can derive
    /// the machine salt from it on demand.
    ///
    /// [`unlock_key`]: KeyProvider::unlock_key
    pub(crate) fn new(wrapper: &[u8; WRAPPER_LEN]) -> Self {
        Self {
            nonce: *parse_wrapper(wrapper).nonce,
        }
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
        // identifier wipes when the derivation returns — without it,
        // a stable host identifier would linger in the allocator
        // even though `UnlockKey` zeroizes the derived key.
        derive_from_machine_id(Zeroizing::new(machine_id), &self.nonce)
    }
}

/// Pure derivation core of [`KeyProvider::unlock_key`]: rejects an
/// empty machine id — a broken `machine_uid` read that no valid seal
/// can match, since `emit()` refuses a token with an empty id
/// (§2.9.3.3) — then derives under the canonical contexts. Extracted so
/// the empty guard is unit-testable without a host whose `machine_uid`
/// read is actually broken.
///
/// `weak_mask!()` keeps both BLAKE3 context literals out of
/// `strings(1)` output for user binaries. Each literal MUST match its
/// `litmask_internal` const byte-for-byte (which `litmask-build` uses
/// at seal time) or build ↔ runtime derivations diverge; pinned by the
/// `weak_mask_literals_match_consts` test below.
// By-value is load-bearing (same idiom as file.rs's
// `derive_key_from_buffer`): the `Zeroizing` drop wipes the host id
// when this function returns, even on the error path.
#[allow(clippy::needless_pass_by_value)]
fn derive_from_machine_id(
    machine_id: Zeroizing<alloc::string::String>,
    nonce: &[u8; NONCE_LEN],
) -> Result<UnlockKey, KeyError> {
    // An empty read is a broken read; `MachineId::new` rejects it so the
    // empty-id footgun is unrepresentable at `derive_machine_id_key`.
    let machine_id = MachineId::new(&machine_id).map_err(|_| KeyError::InvalidFormat)?;
    Ok(UnlockKey::from_raw(derive_machine_id_key(
        crate::weak_mask!("litmask-machine-id-v1"),
        crate::weak_mask!("litmask-machine-id-salt-v1"),
        &machine_id,
        nonce,
    )))
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
    use crate::internal::{
        CURRENT_CIPHER, FormatVersion, KEY_LEN, MACHINE_ID_DERIVATION_CONTEXT,
        MACHINE_ID_SALT_DERIVATION_CONTEXT, WRAPPER_BODY_LEN, WRAPPER_PLAINTEXT_LEN, aead_encrypt,
        assemble_wrapper,
    };

    /// Seal a wrapper exactly as `litmask-build` does for the Machine
    /// tier: `unlock_key` derived from the chosen machine id + nonce,
    /// then `version || mask_key` sealed under it.
    fn seal_machine_wrapper(
        nonce: [u8; NONCE_LEN],
        machine_id: &[u8],
        mask_key: [u8; KEY_LEN],
    ) -> [u8; WRAPPER_LEN] {
        let machine_id =
            MachineId::new(core::str::from_utf8(machine_id).expect("utf8")).expect("non-empty");
        let unlock_key = derive_machine_id_key(
            MACHINE_ID_DERIVATION_CONTEXT,
            MACHINE_ID_SALT_DERIVATION_CONTEXT,
            &machine_id,
            &nonce,
        );
        let mut plaintext = [0u8; WRAPPER_PLAINTEXT_LEN];
        plaintext[0] = FormatVersion::CURRENT.to_byte();
        plaintext[1..].copy_from_slice(&mask_key);
        let body = aead_encrypt(CURRENT_CIPHER, &unlock_key, &nonce, &plaintext)
            .expect("aead_encrypt under derived unlock_key");
        let body: &[u8; WRAPPER_BODY_LEN] = body.as_slice().try_into().expect("body length");
        assemble_wrapper(&nonce, body)
    }

    #[test]
    fn new_captures_the_wrapper_nonce() {
        let nonce = [0x5au8; NONCE_LEN];
        let wrapper = seal_machine_wrapper(nonce, b"host-id-abc", [0u8; KEY_LEN]);
        let provider = MachineIdProvider::new(&wrapper);
        assert_eq!(provider.nonce, nonce);
    }

    /// An empty `machine_uid` read can never open a valid seal —
    /// `emit()` rejects a token with an empty id (§2.9.3.3) — so name
    /// the broken read instead of failing later with a generic
    /// wrapper-decrypt error.
    #[test]
    fn empty_machine_id_yields_invalid_format() {
        let result = derive_from_machine_id(
            Zeroizing::new(alloc::string::String::new()),
            &[0u8; NONCE_LEN],
        );
        assert!(matches!(result, Err(KeyError::InvalidFormat)));
    }

    /// The runtime derivation must use the host's own machine id and the
    /// captured nonce under the canonical contexts. When `machine_uid`
    /// is available, `unlock_key()` must equal the const-context
    /// derivation over that id + the captured nonce; on hosts where
    /// `machine_uid` is unavailable, the call errors and the assertion is
    /// skipped (matches the integration test's tolerance).
    #[test]
    fn unlock_key_matches_const_context_derivation() {
        let Ok(host_id) = machine_uid::get() else {
            return;
        };
        let nonce = [0x21u8; NONCE_LEN];
        let wrapper = seal_machine_wrapper(nonce, host_id.as_bytes(), [0u8; KEY_LEN]);
        let provider = MachineIdProvider::new(&wrapper);
        let recovered = provider.unlock_key().expect("machine_uid available");
        assert_eq!(
            recovered.as_bytes(),
            &derive_machine_id_key(
                MACHINE_ID_DERIVATION_CONTEXT,
                MACHINE_ID_SALT_DERIVATION_CONTEXT,
                &MachineId::new(&host_id).expect("non-empty"),
                &nonce,
            )
        );
    }

    /// A wrapper sealed under the host's own machine id round-trips: the
    /// provider re-derives the same `unlock_key` and opens the wrapper.
    /// Skipped when `machine_uid` is unavailable.
    #[test]
    fn derived_key_round_trips_a_build_emitted_wrapper() {
        use crate::internal::decrypt_wrapper;
        let Ok(host_id) = machine_uid::get() else {
            return;
        };
        let nonce = [0x09u8; NONCE_LEN];
        let mask_key = [0x11u8; KEY_LEN];
        let wrapper = seal_machine_wrapper(nonce, host_id.as_bytes(), mask_key);
        let provider = MachineIdProvider::new(&wrapper);
        let unlock_key = provider.unlock_key().expect("machine_uid available");
        let recovered = decrypt_wrapper(unlock_key.as_bytes(), &wrapper).expect("round-trip");
        assert_eq!(recovered, mask_key);
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

    /// Pin the literal-vs-const drift: the runtime call site inlines
    /// `weak_mask!()` for both the key context and the salt context so
    /// the BLAKE3 context bytes are obfuscated in user binaries, while
    /// `litmask-build` seals using the consts directly. Each pair MUST
    /// decode to the same string or every machine build fails to unlock
    /// at runtime.
    #[test]
    fn weak_mask_literals_match_consts() {
        assert_eq!(
            crate::weak_mask!("litmask-machine-id-v1"),
            MACHINE_ID_DERIVATION_CONTEXT
        );
        assert_eq!(
            crate::weak_mask!("litmask-machine-id-salt-v1"),
            MACHINE_ID_SALT_DERIVATION_CONTEXT
        );
    }
}
