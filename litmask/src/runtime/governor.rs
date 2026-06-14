//! Process-global **governing provider** (ADR-0001).
//!
//! A **host binary** installs a governor through an `init!(...)` form. The
//! lazy unlock path ([`super::mask_key_or_lazy_init`]) then consults it for
//! *every* wrapper, so one provider unlocks the whole dependency graph
//! (governed masking). This works because, under a **uniform seal**, every
//! masking crate's wrapper is sealed under the same unlock material — the
//! external unlock key is material-derived and crate-independent.
//!
//! Install-once: the first `init!` wins; a later one is the idempotent
//! no-op the init seams already treat as a repeat. No governor installed is
//! the transparent-masking floor — each Embedded wrapper self-unlocks
//! keyless.

use crate::error::KeyError;
use crate::internal::WRAPPER_LEN;
use crate::key::UnlockKey;
use crate::provider::KeyProvider;

/// The installed governor's keying. Each variant resolves an unlock key
/// for a given wrapper; the External variant ignores the wrapper (its key
/// is material-derived), while the machine-bearing variants re-derive the
/// machine factor from each wrapper's own embedded nonce.
pub(super) enum Governor {
    /// `init!(<provider>)` — one external provider governs every wrapper.
    External(alloc::boxed::Box<dyn KeyProvider>),
    /// `init!(bind_to_machine)` — the machine factor, re-derived from each
    /// wrapper's own embedded nonce at consult time.
    #[cfg(feature = "machine-id")]
    Machine,
    /// `init!(bind_to_machine + <provider>)` — the per-wrapper machine
    /// factor composed (machine-first) with the external provider's key.
    #[cfg(feature = "machine-id")]
    MachineExternal(alloc::boxed::Box<dyn KeyProvider>),
}

impl Governor {
    /// Resolve the unlock key for `wrapper` under this governor. The
    /// machine-bearing variants construct a fresh `MachineIdProvider` from
    /// `wrapper`'s nonce per call, so one governor unlocks every crate's
    /// wrapper despite each carrying a distinct nonce.
    #[cfg_attr(not(feature = "machine-id"), allow(unused_variables))]
    pub(super) fn unlock_key_for(
        &self,
        wrapper: &[u8; WRAPPER_LEN],
    ) -> Result<UnlockKey, KeyError> {
        match self {
            Self::External(provider) => provider.unlock_key(),
            #[cfg(feature = "machine-id")]
            Self::Machine => crate::provider::MachineIdProvider::new(wrapper).unlock_key(),
            #[cfg(feature = "machine-id")]
            Self::MachineExternal(external) => {
                let machine = crate::provider::MachineIdProvider::new(wrapper).unlock_key()?;
                let external = external.unlock_key()?;
                Ok(UnlockKey::compose(&machine, &external))
            }
        }
    }
}

/// Process-global, install-once governor slot.
static GOVERNOR: super::cell::OnceCell<Governor> = super::cell::OnceCell::new();

/// Install `governor` if none is set yet and return the effective one
/// (the first installed wins). Returning the winner lets the caller derive
/// the host's own wrapper key through it without a second lookup.
pub(super) fn install(governor: Governor) -> &'static Governor {
    GOVERNOR.get_or_init(|| governor)
}

/// The installed governor, if any. `None` is the transparent-masking
/// floor (Embedded wrappers self-unlock keyless).
pub(super) fn current() -> Option<&'static Governor> {
    GOVERNOR.get()
}

#[cfg(all(test, feature = "machine-id"))]
mod tests {
    use super::*;
    use crate::internal::{KEY_LEN, WRAPPER_LEN};
    use crate::provider::MachineIdProvider;

    /// Only the wrapper's leading nonce feeds machine-factor derivation,
    /// so an all-`fill` byte array is a sufficient stand-in wrapper.
    fn wrapper(fill: u8) -> [u8; WRAPPER_LEN] {
        [fill; WRAPPER_LEN]
    }

    struct FixedExternal;
    const EXTERNAL_KEY: [u8; KEY_LEN] = [0x9c; KEY_LEN];
    impl KeyProvider for FixedExternal {
        fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
            Ok(UnlockKey::from_raw(EXTERNAL_KEY))
        }
    }

    /// The machine governor re-derives the factor from *each* wrapper's
    /// own nonce at consult time (no captured nonce): distinct nonces
    /// yield distinct keys, each matching a fresh `MachineIdProvider`.
    /// Tolerant of hosts without a readable machine id (CI sandboxes).
    #[test]
    fn machine_governor_rederives_per_wrapper_nonce() {
        let (w1, w2) = (wrapper(0x11), wrapper(0x22));
        let governor = Governor::Machine;
        let (Ok(k1), Ok(k2)) = (governor.unlock_key_for(&w1), governor.unlock_key_for(&w2)) else {
            return;
        };
        let Ok(direct) = MachineIdProvider::new(&w1).unlock_key() else {
            return;
        };
        assert_eq!(k1.as_bytes(), direct.as_bytes());
        assert_ne!(k1.as_bytes(), k2.as_bytes());
    }

    /// The two-factor governor composes the per-wrapper machine factor
    /// with the external provider's key, machine-first (§2.3).
    #[test]
    fn machine_external_governor_composes_both_factors() {
        let w = wrapper(0x33);
        let governor = Governor::MachineExternal(alloc::boxed::Box::new(FixedExternal));
        let (Ok(got), Ok(machine)) = (
            governor.unlock_key_for(&w),
            MachineIdProvider::new(&w).unlock_key(),
        ) else {
            return;
        };
        let want = UnlockKey::compose(&machine, &UnlockKey::from_raw(EXTERNAL_KEY));
        assert_eq!(got.as_bytes(), want.as_bytes());
    }
}
