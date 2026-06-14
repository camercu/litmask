//! Imperative shell over the pure decryption core
//! ([`litmask_internal::decrypt_wrapper`]).
//!
//! Mask keys live in the process-global [`mask_key_store`], keyed by
//! each crate's wrapper nonce, populated by [`__init_with_wrapper`] (the
//! target of `init!`) or lazily by [`__decrypt`] on the first `mask!()`
//! call. Keying by wrapper — rather than the former single set-once cell
//! — lets several **masking crates** coexist in one **host binary**,
//! each unlocking its own wrapper independently (transparent masking;
//! see `docs/adr/0001`).
//!
//! The decryption path must not leak litmask-identifying message text
//! into a shipped (release) binary: `assert!` / `.expect("…")` and
//! `panic!("…")` with a custom message would all fingerprint user
//! binaries as litmask-built. Every failure arm here therefore routes
//! to a [`crate::diagnostics`] entry point, which owns the §5.4 profile
//! split — bare `panic!()` in release, actionable text in debug — in one
//! place, so these call sites stay free of per-site `cfg` branching.

use crate::error::InitError;
use crate::internal::{DecryptError, WRAPPER_LEN, decrypt_blob, decrypt_wrapper};
use crate::key::MaskKey;
use crate::provider::KeyProvider;

pub(crate) mod cell;
mod mask_key_store;
pub(crate) mod weak;

/// Debug fail-fast for an `init!` that arrives after the lazy
/// first-`mask!()` path already installed *this wrapper's* mask key.
/// Called from every explicit init seam's already-initialized early
/// return. The check is per wrapper (see [`mask_key_store::was_lazy`]):
/// a host that `init!`s its own wrapper is not faulted because some other
/// masking crate lazy-unlocked first. On the Embedded floor the lazy key
/// equals the `init!()` key, so the bug is invisible at runtime — until a
/// higher-tier reseal turns it into the §2.1.1.12a refusal. Release
/// builds keep the silent idempotent `Ok(())` (§2.6.1.4): this function
/// compiles to nothing there, and no diagnostic text reaches the artifact.
#[cfg_attr(not(debug_assertions), allow(unused_variables))]
fn guard_init_after_lazy(wrapper: &[u8; WRAPPER_LEN]) {
    #[cfg(debug_assertions)]
    if mask_key_store::was_lazy(&mask_key_store::key_for(wrapper)) {
        crate::diagnostics::init_after_lazy();
    }
}

/// Decrypt the embedded `mask_key` wrapper and store the result in the
/// process-global mask key cell.
///
/// Called by the `init!` macro after it captures the wrapper bytes via
/// `include_bytes!`.
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

/// Shared tail of every eager `init!` seam: cache this wrapper's mask
/// key if it isn't already, deriving the `unlock_key` via `derive_unlock`
/// (the only thing that differs between tiers — provider, machine id, or
/// two-factor composition). A wrapper already cached (a repeat `init!`,
/// or a prior lazy first-`mask!()`) is an idempotent no-op past the
/// init-after-lazy guard.
fn ensure_cached(
    wrapper: &[u8; WRAPPER_LEN],
    derive_unlock: impl FnOnce() -> Result<crate::key::UnlockKey, InitError>,
) -> Result<(), InitError> {
    if mask_key_store::contains(&mask_key_store::key_for(wrapper)) {
        guard_init_after_lazy(wrapper);
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

/// `init!(bind_to_machine)` seam: construct the crate-private
/// `MachineIdProvider` from the embedded wrapper nonce and run the shared
/// init path.
///
/// The macro calls this seam rather than naming the provider type:
/// `MachineIdProvider` is `pub(crate)` and unreachable from the consumer
/// crate where `init!` expansion lands. Routing the construction through
/// here keeps the build-wrapper nonce injection in-crate and the type out
/// of expanded code.
#[cfg(feature = "machine-id")]
#[doc(hidden)]
pub fn __init_machine_id(wrapper: &[u8; WRAPPER_LEN]) -> Result<(), InitError> {
    __init_with_wrapper(crate::provider::MachineIdProvider::new(wrapper), wrapper)
}

/// `init!(bind_to_machine + <provider>)` seam: finish the machine factor key
/// in-crate (from the embedded wrapper nonce, via the `pub(crate)`
/// `MachineIdProvider`) and the external factor key from the consumer's
/// `provider`, compose them machine-first (§2.3), and run the shared init
/// path under the composition.
///
/// The macro routes here rather than naming `MachineIdProvider` for the
/// same reason as [`__init_machine_id`]: that provider is `pub(crate)`
/// and unreachable from the consumer crate where `init!` expansion lands.
/// Composition happens here so neither finished factor key, nor the
/// `MachineIdProvider` type, appears in expanded code.
#[cfg(feature = "machine-id")]
#[doc(hidden)]
#[allow(clippy::needless_pass_by_value)]
pub fn __init_machine_id_external<P: KeyProvider>(
    wrapper: &[u8; WRAPPER_LEN],
    external: P,
) -> Result<(), InitError> {
    ensure_cached(wrapper, || {
        let machine_key = crate::provider::MachineIdProvider::new(wrapper).unlock_key()?;
        let external_key = external.unlock_key()?;
        Ok(crate::key::UnlockKey::compose(&machine_key, &external_key))
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
/// debug (§5.4).
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

// The `match … { Ok => …, Err(_) => panic!() }` shape is deliberate
// (see the module header): `let…else` / `if let` alternatives or an
// `.expect()` would inject identifier text into the unwind path and
// fingerprint user binaries as litmask-built.
#[allow(
    clippy::single_match_else,
    clippy::match_wild_err_arm,
    clippy::manual_let_else
)]
fn mask_key_or_lazy_init(wrapper: &[u8; WRAPPER_LEN], tier: &str) -> &'static MaskKey {
    let nonce = mask_key_store::key_for(wrapper);
    mask_key_store::get_or_init(nonce, move || {
        #[cfg(debug_assertions)]
        mask_key_store::record_lazy(nonce);
        // No explicit `init!` ran. The lazy fallback derives the
        // Embedded-tier unlock_key from the wrapper's public nonce, which
        // is correct ONLY at the Embedded floor. On a higher-tier seal
        // this would silently derive the wrong key and fail the wrapper
        // AEAD check, masking the real cause (a missing/late `init!`) as a
        // generic decryption error. Refuse instead, naming the
        // init-ordering bug. The cell is set-once: a build that called
        // `init!` first never reaches this closure, so a correctly
        // ordered higher-tier program is unaffected.
        if crate::internal::SealTierTag::parse(tier) != Some(crate::internal::SealTierTag::Embedded)
        {
            crate::diagnostics::lazy_init_wrong_tier(tier);
        }
        // Derive the keyless Embedded unlock_key (works in both std and
        // no_std), then decrypt the wrapper through the same path the
        // explicit seams use. Any failure (provider or decrypt) panics
        // with no message to avoid leaking litmask-identifying plaintext;
        // the eager seams forward the equivalent `InitError`.
        let provider = crate::EmbeddedProvider::new(wrapper);
        let bytes = match provider
            .unlock_key()
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
