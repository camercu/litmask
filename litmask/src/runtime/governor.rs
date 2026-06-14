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
/// machine factor from each wrapper's own embedded nonce (Slice 2).
pub(super) enum Governor {
    /// `init!(<provider>)` — one external provider governs every wrapper.
    External(alloc::boxed::Box<dyn KeyProvider>),
}

impl Governor {
    /// Resolve the unlock key for `wrapper` under this governor.
    pub(super) fn unlock_key_for(
        &self,
        _wrapper: &[u8; WRAPPER_LEN],
    ) -> Result<UnlockKey, KeyError> {
        match self {
            Self::External(provider) => provider.unlock_key(),
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
