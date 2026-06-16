//! Imperative shell over the pure decryption core
//! ([`litmask_internal::decrypt_wrapper`]).
//!
//! Mask keys live in the process-global [`mask_key_store`], keyed by
//! each crate's wrapper nonce, populated by the governing `init!` seams
//! ([`__govern_external`] et al.) or lazily by [`__decrypt`] on the first
//! `mask!()` call. Keying by wrapper — rather than the former single
//! set-once cell — lets several **masking crates** coexist in one **host
//! binary**, each unlocking its own wrapper independently (transparent and
//! governed masking; see `docs/adr/0001`).
//!
//! The decryption path must not leak litmask-identifying message text
//! into a shipped (release) binary: `assert!` / `.expect("…")` and
//! `panic!("…")` with a custom message would all fingerprint user
//! binaries as litmask-built. Every failure arm here therefore routes
//! to a [`crate::diagnostics`] entry point, which owns the §1.9.5 profile
//! split — bare `panic!()` in release, actionable text in debug — in one
//! place, so these call sites stay free of per-site `cfg` branching.

use crate::error::InitError;
use crate::internal::{DecryptError, WRAPPER_LEN, decrypt_blob, decrypt_wrapper};
use crate::key::MaskKey;
use crate::provider::KeyProvider;

pub(crate) mod cell;
mod governor;
mod mask_key_store;
pub(crate) mod weak;

/// Crate-internal entry point for [`crate::test_util::reset_mask_key_cache`],
/// keeping `mask_key_store` private to this module. Feature-gated to the
/// test/bench hook surface.
#[cfg(feature = "test-util")]
pub(crate) fn reset_mask_key_cache() {
    mask_key_store::clear();
}

/// Non-governing eager init primitive: decrypt the embedded `mask_key`
/// wrapper under `provider` and cache it. No governor is installed (unlike
/// the `init!` govern seams), so it opens exactly the one `wrapper` given.
/// Used by the init error-path tests to exercise the [`InitError`] surface
/// in isolation, without a process-global governor leaking across cases.
///
/// # Errors
///
/// Forwards provider errors via [`InitError::KeyProvider`]. AEAD
/// authentication failure on the embedded wrapper (wrong `unlock_key`
/// or tampered wrapper — cryptographically indistinguishable) returns
/// [`InitError::Decryption`]. An authenticated-but-unrecognized
/// format-version byte surfaces as [`InitError::UnsupportedFormat`].
#[doc(hidden)]
#[allow(clippy::needless_pass_by_value, clippy::match_wild_err_arm)]
pub fn __init_with_wrapper<P: KeyProvider>(
    provider: P,
    wrapper: &[u8; WRAPPER_LEN],
) -> Result<(), InitError> {
    ensure_cached(wrapper, || {
        provider.unlock_key().map_err(InitError::KeyProvider)
    })
}

/// `init!(<provider>)` seam: install `provider` as the process-global
/// **governing provider** (ADR-0001), then eagerly unlock the host's own
/// `wrapper` through it for early-failure (the `Result` contract). Once
/// installed, the lazy path unlocks every other masking crate's wrapper
/// through the same provider — governed masking across the dependency
/// graph under a uniform seal.
///
/// # Errors
///
/// Forwards provider errors via [`InitError::KeyProvider`]; AEAD failure
/// on the host wrapper (wrong material or tamper) → [`InitError::Decryption`];
/// an unrecognized format-version byte → [`InitError::UnsupportedFormat`].
#[doc(hidden)]
#[allow(clippy::needless_pass_by_value)]
pub fn __govern_external<P: KeyProvider + 'static>(
    provider: P,
    wrapper: &[u8; WRAPPER_LEN],
) -> Result<(), InitError> {
    let governor = governor::install(governor::Governor::External(alloc::boxed::Box::new(
        provider,
    )));
    ensure_cached(wrapper, || {
        governor
            .unlock_key_for(wrapper)
            .map_err(InitError::KeyProvider)
    })
}

/// Shared tail of every eager `init!` seam: cache this wrapper's mask
/// key if it isn't already, deriving the `unlock_key` via `derive_unlock`
/// (the only thing that differs between tiers — provider, machine id, or
/// two-factor composition). A wrapper already cached (a repeat `init!`,
/// or a prior lazy first-`mask!()`) is an idempotent no-op.
fn ensure_cached(
    wrapper: &[u8; WRAPPER_LEN],
    derive_unlock: impl FnOnce() -> Result<crate::key::UnlockKey, InitError>,
) -> Result<(), InitError> {
    if mask_key_store::contains(&mask_key_store::key_for(wrapper)) {
        return Ok(());
    }
    let unlock_key = derive_unlock()?;
    let mask_key_bytes = decrypt_mask_key(&unlock_key, wrapper)?;
    mask_key_store::get_or_init(mask_key_store::key_for(wrapper), || {
        MaskKey::new(mask_key_bytes)
    });
    Ok(())
}

/// Decrypt the embedded `mask_key` wrapper under `unlock_key`, mapping
/// the [`DecryptError`] surface onto [`InitError`]. The single home for
/// that mapping: both the `init!` seams (which forward the
/// `InitError`) and the lazy first-`mask!()` path (which panics on
/// `Err`) decrypt the wrapper through here, so the AEAD-failure and
/// unknown-format distinction is made once.
#[allow(clippy::match_wild_err_arm)]
fn decrypt_mask_key(
    unlock_key: &crate::key::UnlockKey,
    wrapper: &[u8; WRAPPER_LEN],
) -> Result<[u8; crate::internal::KEY_LEN], InitError> {
    match decrypt_wrapper(unlock_key.as_bytes(), wrapper) {
        Ok(bytes) => Ok(bytes),
        Err(DecryptError::AuthenticationFailed) => Err(InitError::Decryption),
        Err(DecryptError::UnsupportedFormat) => Err(InitError::UnsupportedFormat),
        // `BlobTooShort` cannot reach this branch — `WRAPPER_LEN`
        // is fixed at the type level, so the wrapper is always
        // exactly long enough. A panic here would be a soundness
        // bug in `decrypt_wrapper`, which the typed `WRAPPER_LEN`
        // shape rules out at the call site; we keep the bare
        // `panic!()` (no message) for compile-time exhaustiveness
        // without leaking identifier text into the binary.
        Err(_) => panic!(),
    }
}

/// `init!(bind_to_machine)` seam: install the machine factor as the
/// process-global **governing provider** (ADR-0001) and eagerly unlock the
/// host's own `wrapper` through it. The governor re-derives the machine
/// factor from each wrapper's own nonce, so it unlocks every machine-sealed
/// crate's wrapper lazily.
///
/// The seam exists because `Governor::Machine` wraps the `pub(crate)`
/// `MachineIdProvider`, unreachable from the consumer crate where `init!`
/// expands; keeping the construction in-crate keeps that type out of
/// expanded code.
#[cfg(feature = "machine-id")]
#[doc(hidden)]
pub fn __govern_machine(wrapper: &[u8; WRAPPER_LEN]) -> Result<(), InitError> {
    let governor = governor::install(governor::Governor::Machine);
    ensure_cached(wrapper, || {
        governor
            .unlock_key_for(wrapper)
            .map_err(InitError::KeyProvider)
    })
}

/// `init!(bind_to_machine + <provider>)` seam: install the two-factor
/// (machine + external) **governing provider** and eagerly unlock the
/// host's own `wrapper` through it. Per wrapper the governor composes the
/// machine factor (re-derived from that wrapper's nonce) with the external
/// provider's key, machine-first (§2.3).
///
/// Routed here for the same reason as [`__govern_machine`]: the machine
/// factor wraps the `pub(crate)` `MachineIdProvider`, so neither it nor any
/// finished factor key appears in expanded code.
#[cfg(feature = "machine-id")]
#[doc(hidden)]
#[allow(clippy::needless_pass_by_value)]
pub fn __govern_machine_external<P: KeyProvider + 'static>(
    wrapper: &[u8; WRAPPER_LEN],
    external: P,
) -> Result<(), InitError> {
    let governor = governor::install(governor::Governor::MachineExternal(alloc::boxed::Box::new(
        external,
    )));
    ensure_cached(wrapper, || {
        governor
            .unlock_key_for(wrapper)
            .map_err(InitError::KeyProvider)
    })
}

/// Decrypt a per-string blob to raw bytes. Called by every `mask!()`
/// expansion regardless of literal kind — the proc-macro emits
/// type-specific construction (`String::from_utf8` / `CString::new`)
/// around this call.
///
/// `blob` is `nonce (12) || ciphertext (n) || tag (16)`. `wrapper` is
/// the embedded encrypted-`mask_key` blob, passed by the macro so lazy
/// init can derive the Embedded `unlock_key` via
/// [`crate::EmbeddedProvider`] when no explicit `init!` was issued.
/// `tier` is the build-sealed `LITMASK_SEAL_TIER` tag (injected by the
/// `mask!` expansion via `__seal_tier!`); it gates the lazy path so a
/// higher-tier seal refuses the Embedded fallback (§2.1).
///
/// # Panics
///
/// Panics on AEAD authentication failure, lazy-init provider failure,
/// wrapper format / cipher-id mismatch, or a lazy first-`mask!()` on a
/// non-Embedded seal (init-ordering bug). The panic is bare (no message)
/// in release and carries an actionable [`crate::diagnostics`] message in
/// debug (§1.9.5).
#[doc(hidden)]
#[allow(clippy::must_use_candidate)]
pub fn __decrypt(blob: &[u8], wrapper: &[u8; WRAPPER_LEN], tier: &str) -> alloc::vec::Vec<u8> {
    let mask_key = mask_key_or_lazy_init(wrapper, tier);
    decrypt_blob_or_panic(mask_key.as_bytes(), blob)
}

/// [`__decrypt`] plus `String` construction, in one runtime call.
/// Exists so the `mask!("...")` expansion never names the `String`
/// type: rustc's diagnostic path-trimming renders `String` vs the
/// `__String` re-export alias depending on the consumer's dependency
/// graph (a serde dep that publicly re-exports `String` flips it),
/// which made consumer-side error text — and the trybuild snapshots
/// pinning it — vary with enabled features.
///
/// # Panics
///
/// Same policy as [`__decrypt`]; additionally diverges via the
/// profile-split [`crate::diagnostics::blob_utf8_failure`] if the
/// decrypted bytes are not valid UTF-8 (unreachable in practice — the
/// proc-macro encrypts valid UTF-8 and the AEAD tag rejects tampering
/// first).
#[doc(hidden)]
#[allow(clippy::must_use_candidate, clippy::single_match_else)]
pub fn __decrypt_string(
    blob: &[u8],
    wrapper: &[u8; WRAPPER_LEN],
    tier: &str,
) -> alloc::string::String {
    match alloc::string::String::from_utf8(__decrypt(blob, wrapper, tier)) {
        Ok(s) => s,
        Err(_) => crate::diagnostics::blob_utf8_failure(),
    }
}

/// [`__decrypt_string`] wrapped in [`zeroize::Zeroizing`] so the decrypted
/// plaintext is overwritten when the value drops. Emitted by the
/// `#[derive(MaskDebug)]` expansion for each per-`fmt` name, so the name
/// is wiped without the derive naming a wrapper. (`mask_format!` fragments
/// achieve the same wipe differently — they wrap the public `mask!`
/// output in `Zeroizing::new(...)` to keep `mask!`'s literal/span
/// handling — so they do not route through here.)
///
/// `__decrypt_string`'s result reuses the single decrypt-path allocation
/// (no extra plaintext copy), so wrapping it here overwrites the complete
/// footprint on drop.
///
/// # Panics
///
/// Same policy as [`__decrypt_string`].
#[doc(hidden)]
#[allow(clippy::must_use_candidate)]
pub fn __decrypt_string_zeroizing(
    blob: &[u8],
    wrapper: &[u8; WRAPPER_LEN],
    tier: &str,
) -> zeroize::Zeroizing<alloc::string::String> {
    zeroize::Zeroizing::new(__decrypt_string(blob, wrapper, tier))
}

// The explicit `match` arms (tier selection and the Ok/Err decrypt
// result) are deliberate over clippy's `if let … else` / `let … else`
// rewrites: they keep the diverging arms uniform with the rest of the
// decrypt path, where `.expect()` / `if let` would inject identifier text
// into the unwind path and fingerprint user binaries.
#[allow(clippy::single_match_else, clippy::manual_let_else)]
fn mask_key_or_lazy_init(wrapper: &[u8; WRAPPER_LEN], tier: &str) -> &'static MaskKey {
    let nonce = mask_key_store::key_for(wrapper);
    mask_key_store::get_or_init(nonce, move || {
        // Lazy-unlock rule (ADR-0001): a governing provider, if one was
        // installed by an `init!` form, supplies the unlock key for EVERY
        // wrapper regardless of tier (governed masking under a uniform
        // seal). Absent a governor, only the keyless Embedded floor
        // self-unlocks:
        // a higher-tier seal here would derive the wrong key and fail the
        // wrapper AEAD check, masking the real cause (a missing/late
        // governing `init!`) as a generic decryption error — refuse
        // instead, naming the ordering bug. Seal tier is uniform across a
        // dependency graph (set by the shared build env), so the governor
        // key matches every wrapper it is asked to open.
        let unlock_key = match governor::current() {
            Some(governor) => governor.unlock_key_for(wrapper),
            None => {
                if crate::internal::SealTierTag::parse(tier)
                    != Some(crate::internal::SealTierTag::Embedded)
                {
                    crate::diagnostics::lazy_init_wrong_tier(tier);
                }
                crate::EmbeddedProvider::new(wrapper).unlock_key()
            }
        };
        // Decrypt the wrapper through the same path the explicit seams use.
        // Any failure (provider or decrypt) panics with no message to avoid
        // leaking litmask-identifying plaintext; the eager seams forward
        // the equivalent `InitError`.
        let bytes = match unlock_key
            .map_err(InitError::KeyProvider)
            .and_then(|unlock_key| decrypt_mask_key(&unlock_key, wrapper))
        {
            Ok(bytes) => bytes,
            Err(err) => crate::diagnostics::init_failure(&err),
        };
        MaskKey::new(bytes)
    })
}

#[allow(clippy::single_match_else, clippy::match_wild_err_arm)]
fn decrypt_blob_or_panic(
    mask_key: &[u8; crate::internal::KEY_LEN],
    blob: &[u8],
) -> alloc::vec::Vec<u8> {
    match decrypt_blob(mask_key, blob) {
        Ok(plaintext) => plaintext,
        Err(_) => crate::diagnostics::blob_failure(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Type-level pin (§2.15.1.5 relies on it): the internal seam returns
    // `Zeroizing<String>`. A real blob isn't needed — this only checks the
    // signature compiles, since behavioral coverage rides the macro
    // caller (the `MaskDebug` derive).
    #[allow(dead_code)]
    fn seam_returns_zeroizing_string(
        blob: &[u8],
        wrapper: &[u8; WRAPPER_LEN],
        tier: &str,
    ) -> zeroize::Zeroizing<alloc::string::String> {
        __decrypt_string_zeroizing(blob, wrapper, tier)
    }

    // The wipe itself is `zeroize`'s upstream-tested contract; this only
    // proves our reliance on it is wired — dropping a `Zeroizing<T>` calls
    // `T::zeroize` exactly once. The probe has no `Drop` of its own, so
    // the count isolates `Zeroizing`'s call (the provider tests' `Counted`
    // self-zeroizes in its own `Drop` and would double-count here).
    #[test]
    fn zeroizing_drop_calls_zeroize_exactly_once() {
        use core::sync::atomic::{AtomicUsize, Ordering};

        static COUNT: AtomicUsize = AtomicUsize::new(0);

        struct Probe;
        impl zeroize::Zeroize for Probe {
            fn zeroize(&mut self) {
                COUNT.fetch_add(1, Ordering::SeqCst);
            }
        }

        {
            let _z = zeroize::Zeroizing::new(Probe);
        }
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
    }
}
