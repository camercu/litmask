//! Process-global mask-key store, keyed by each masking crate's wrapper
//! nonce.
//!
//! Every masking crate in a host binary carries its own wrapper (and so
//! its own mask key). Keying the store by the wrapper's cleartext nonce
//! — rather than the former single set-once cell — lets independent
//! masking crates coexist, each unlocking its own wrapper (transparent
//! masking, `docs/adr/0001`).
//!
//! ## `&'static` contract
//!
//! [`get_or_init`] returns `&'static MaskKey`: the decrypted key is
//! leaked once per wrapper. Like the former single cell, a mask key
//! lives for the whole process — the threat model is the binary at rest,
//! not process memory — so the leak is bounded (one key per masking
//! crate) and never reclaimed. Returning `&'static` keeps the per-call
//! `mask!()` decrypt path allocation- and refcount-free.
//!
//! ## `no_std` scope
//!
//! Under `std`, entries live in a `Mutex<HashMap>`. Under `no_std`
//! (`alloc` only) the store keeps a single set-once cell — i.e. **one
//! masking crate per `no_std` binary** — a deliberate constraint:
//! `unsafe` is forbidden workspace-wide (ruling out a lock-free map) and
//! a `no_std` mutex is a dependency not yet justified by a real embedded
//! multi-masking-crate need (YAGNI). Lifting it later is a localized
//! change here (a `spin`/`critical-section` `Mutex<BTreeMap>`). A second
//! masking crate (distinct wrapper nonce) is detected and refused with a
//! debug diagnostic ([`crate::diagnostics::extra_masking_crate_no_std`])
//! rather than silently fed the first crate's key.

use crate::internal::{NONCE_LEN, WRAPPER_LEN, parse_wrapper};
use crate::key::MaskKey;

/// The store key for a wrapper: a copy of its cleartext nonce, under
/// which the wrapper's decrypted mask key is cached.
pub(super) fn key_for(wrapper: &[u8; WRAPPER_LEN]) -> [u8; NONCE_LEN] {
    *parse_wrapper(wrapper).nonce
}

#[cfg(feature = "std")]
static CACHE: std::sync::OnceLock<
    std::sync::Mutex<std::collections::HashMap<[u8; NONCE_LEN], &'static MaskKey>>,
> = std::sync::OnceLock::new();

// The `no_std` cell also remembers the first wrapper's nonce, so a
// second masking crate's distinct wrapper is detectable (see the
// mismatch check in [`get_or_init`]) rather than silently handed the
// first crate's key.
#[cfg(not(feature = "std"))]
static CACHE: super::cell::OnceCell<([u8; NONCE_LEN], MaskKey)> = super::cell::OnceCell::new();

/// The cached mask key for `nonce`, deriving and inserting it via
/// `derive` on first use. The returned reference is process-lifetime
/// (see the `&'static` contract above).
// The `*` on the entry is load-bearing, not redundant: it copies the
// `&'static MaskKey` (a `Copy` reference to leaked data) out of the map
// so the borrow of the `MutexGuard` ends before the guard drops.
// Auto-deref would instead yield a `&MaskKey` borrowed from the guard —
// not `'static`, and dangling past the guard.
#[allow(clippy::explicit_auto_deref)]
pub(super) fn get_or_init(
    nonce: [u8; NONCE_LEN],
    derive: impl FnOnce() -> MaskKey,
) -> &'static MaskKey {
    #[cfg(feature = "std")]
    {
        let mut map = CACHE
            .get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *map.entry(nonce)
            .or_insert_with(|| alloc::boxed::Box::leak(alloc::boxed::Box::new(derive())))
    }
    #[cfg(not(feature = "std"))]
    {
        let entry = CACHE.get_or_init(|| (nonce, derive()));
        // Single-cell store: one masking crate per no_std binary. If a
        // second crate's wrapper nonce differs from the one that won the
        // cell, returning this key would fail the AEAD tag with a generic
        // error — name the real constraint in debug instead. Release stays
        // opaque (the diagnostic and this check are debug-only).
        #[cfg(debug_assertions)]
        if entry.0 != nonce {
            crate::diagnostics::extra_masking_crate_no_std();
        }
        &entry.1
    }
}

/// Whether `nonce`'s mask key is already cached — the per-wrapper
/// analogue of the old single-cell `is_set`, gating the init seams'
/// idempotent early return.
pub(super) fn contains(nonce: &[u8; NONCE_LEN]) -> bool {
    #[cfg(feature = "std")]
    {
        CACHE.get().is_some_and(|m| {
            m.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .contains_key(nonce)
        })
    }
    #[cfg(not(feature = "std"))]
    {
        let _ = nonce;
        CACHE.is_set()
    }
}
