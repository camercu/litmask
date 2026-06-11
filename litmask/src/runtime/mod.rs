//! Imperative shell over the pure decryption core
//! ([`litmask_internal::decrypt_wrapper`]).
//!
//! The process-global mask key lives in a [`cell::OnceCell`] populated
//! by [`__init_with_wrapper`] (the target of `init!` / `init_with!`) or
//! lazily by [`__decrypt`] on the first `mask!()` call.
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
pub(crate) mod weak;

static MASK_KEY: cell::OnceCell<MaskKey> = cell::OnceCell::new();

/// Decrypt the embedded `mask_key` wrapper and store the result in the
/// process-global mask key cell.
///
/// Called by the `init!` and `init_with!` macros after they capture the
/// wrapper bytes via `include_bytes!`.
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
    if MASK_KEY.is_set() {
        return Ok(());
    }
    let unlock_key = provider.unlock_key()?;
    init_with_unlock_key(&unlock_key, wrapper)
}

/// Decrypt the embedded `mask_key` wrapper under an already-finished
/// `unlock_key` and store the result in the process-global cell. Shared
/// tail of every `init!` seam: the tiers differ only in how they obtain
/// the `unlock_key` (provider, machine id, or two-factor composition),
/// so the wrapper decrypt + cell-set logic lives here once.
fn init_with_unlock_key(
    unlock_key: &crate::key::UnlockKey,
    wrapper: &[u8; WRAPPER_LEN],
) -> Result<(), InitError> {
    let mask_key_bytes = decrypt_mask_key(unlock_key, wrapper)?;
    MASK_KEY.try_set(MaskKey::new(mask_key_bytes));
    Ok(())
}

/// Decrypt the embedded `mask_key` wrapper under `unlock_key`, mapping
/// the [`DecryptError`] surface onto [`InitError`]. The single home for
/// that mapping: both the `init!`/`init_with!` seams (which forward the
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

/// `init!(machine_id)` seam: construct the crate-private
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

/// `init!(machine_id + <provider>)` seam: finish the machine factor key
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
    if MASK_KEY.is_set() {
        return Ok(());
    }
    let machine_key = crate::provider::MachineIdProvider::new(wrapper).unlock_key()?;
    let external_key = external.unlock_key()?;
    let unlock_key = crate::key::UnlockKey::compose(&machine_key, &external_key);
    init_with_unlock_key(&unlock_key, wrapper)
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
    MASK_KEY.get_or_init(|| {
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
