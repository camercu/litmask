//! Imperative shell over the pure decryption core
//! ([`litmask_internal::decrypt_wrapper`]).
//!
//! The process-global mask key lives in a `OnceLock` populated by
//! [`__init_with_wrapper`] (the target of `init!` / `init_with!`) or
//! lazily by [`__decrypt_str`] on the first `mask!()` call.
//!
//! The decryption path must not leak litmask-identifying message text
//! into a shipped (release) binary: `assert!` / `.expect("…")` and
//! `panic!("…")` with a custom message would all fingerprint user
//! binaries as litmask-built. Every failure arm here therefore routes
//! to a [`crate::diagnostics`] entry point, which owns the §5.4 profile
//! split — bare `panic!()` in release, actionable text in debug — in one
//! place, so these call sites stay free of per-site `cfg` branching.

use alloc::string::String;

use crate::error::InitError;
use crate::internal::{DecryptError, WRAPPER_LEN, decrypt_blob, decrypt_wrapper};
use crate::key::MaskKey;
use crate::provider::KeyProvider;

// `std::sync::OnceLock` and `once_cell::race::OnceBox` have different
// shapes; this wrapper normalizes them so the rest of the file is
// feature-flag-free.

#[cfg(feature = "std")]
mod cell {
    use crate::key::MaskKey;
    use std::sync::OnceLock;

    pub(super) static MASK_KEY: OnceLock<MaskKey> = OnceLock::new();

    pub(super) fn try_set(key: MaskKey) {
        let _ = MASK_KEY.set(key);
    }

    pub(super) fn get_or_init(init: impl FnOnce() -> MaskKey) -> &'static MaskKey {
        MASK_KEY.get_or_init(init)
    }

    pub(super) fn is_set() -> bool {
        MASK_KEY.get().is_some()
    }
}

#[cfg(not(feature = "std"))]
mod cell {
    use crate::key::MaskKey;
    use alloc::boxed::Box;
    use once_cell::race::OnceBox;

    pub(super) static MASK_KEY: OnceBox<MaskKey> = OnceBox::new();

    pub(super) fn try_set(key: MaskKey) {
        let _ = MASK_KEY.set(Box::new(key));
    }

    pub(super) fn get_or_init(init: impl FnOnce() -> MaskKey) -> &'static MaskKey {
        MASK_KEY.get_or_init(|| Box::new(init()))
    }

    pub(super) fn is_set() -> bool {
        MASK_KEY.get().is_some()
    }
}

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
    if cell::is_set() {
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
    cell::try_set(MaskKey::new(mask_key_bytes));
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
    if cell::is_set() {
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
///
/// # Panics
///
/// Panics on AEAD authentication failure, lazy-init provider failure, or
/// wrapper format / cipher-id mismatch. The panic is bare (no message)
/// in release and carries an actionable [`crate::diagnostics`] message in
/// debug (§5.4).
#[doc(hidden)]
#[allow(clippy::must_use_candidate)]
pub fn __decrypt(blob: &[u8], wrapper: &[u8; WRAPPER_LEN]) -> alloc::vec::Vec<u8> {
    let mask_key = mask_key_or_lazy_init(wrapper);
    decrypt_blob_or_panic(mask_key.as_bytes(), blob)
}

/// XOR-decode obfuscated bytes against the per-build weak key derived
/// from the wrapper header.
///
/// The `black_box` calls hide the const-folded inputs from LLVM.
/// Without them the optimizer can constant-fold the XOR cycle and
/// materialize the decoded plaintext directly in `.rodata`, defeating
/// `weak_mask!()`'s anti-`strings(1)` purpose.
fn weak_xor_decode(obf: &[u8], wrapper: &[u8; WRAPPER_LEN]) -> alloc::vec::Vec<u8> {
    let weak_key = crate::internal::derive_weak_xor_key(wrapper);
    let key = core::hint::black_box(weak_key.as_slice());
    let obf = core::hint::black_box(obf);
    crate::internal::xor_cycle(obf, key)
}

/// Decode a `weak_mask!()`-obfuscated literal on first call and cache
/// the result for the program's lifetime, returning a stable
/// `&'static str` borrowed from the cache.
///
/// The cache parameter is the [`WeakCell`] shim — under the `std`
/// feature it wraps `std::sync::OnceLock<String>`, under
/// `no_std + alloc` it wraps `once_cell::race::OnceBox<String>`.
/// Either backend gives the same observable contract: at-most-once
/// initialization, stable borrow of the cached `String`.
///
/// # Panics
///
/// Panics if the cached decode does not produce valid UTF-8. The
/// macro only accepts string literals, so the AEAD-equivalent
/// guarantee here is just that `weak_mask!()` callers don't feed it
/// arbitrary bytes; UTF-8 failure indicates an in-process tamper of
/// either the obfuscated bytes or the wrapper. The panic is bare in
/// release and actionable in debug (§5.4), like the `mask!()` path.
#[doc(hidden)]
pub fn __weak_decode<const N: usize>(
    obf: &'static [u8; N],
    wrapper: &'static [u8; WRAPPER_LEN],
    cache: &'static WeakCell,
) -> &'static str {
    cache.get_or_init(|| {
        let decoded = weak_xor_decode(obf, wrapper);
        match String::from_utf8(decoded) {
            Ok(text) => text,
            Err(_) => crate::diagnostics::weak_utf8_failure(),
        }
    })
}

/// Per-call-site once-init cache for `weak_mask!()` expansions.
///
/// Generic over the stored type `T`. The proc-macro emits a `static`
/// of the appropriate alias at each invocation site; the first
/// runtime access populates it, and subsequent accesses borrow.
///
/// Two backends, selected by feature flag:
///
/// - `feature = "std"` → `std::sync::OnceLock<T>`.
/// - `not(feature = "std")` → `once_cell::race::OnceBox<T>`.
///
/// The two backends have differently-shaped `get_or_init` APIs
/// (`OnceLock` accepts `FnOnce() -> T`; `OnceBox` accepts `FnOnce()
/// -> Box<T>`). The struct wraps both behind a unified interface so
/// callers and proc-macro emissions are feature-flag-free.
#[doc(hidden)]
pub struct WeakCache<T> {
    #[cfg(feature = "std")]
    inner: std::sync::OnceLock<T>,
    #[cfg(not(feature = "std"))]
    inner: once_cell::race::OnceBox<T>,
}

impl<T> WeakCache<T> {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            inner: std::sync::OnceLock::new(),
            #[cfg(not(feature = "std"))]
            inner: once_cell::race::OnceBox::new(),
        }
    }

    pub fn get_or_init<F: FnOnce() -> T>(&'static self, f: F) -> &'static T::Target
    where
        T: core::ops::Deref,
    {
        #[cfg(feature = "std")]
        {
            self.inner.get_or_init(f)
        }
        #[cfg(not(feature = "std"))]
        {
            self.inner.get_or_init(|| alloc::boxed::Box::new(f()))
        }
    }
}

impl<T> Default for WeakCache<T> {
    fn default() -> Self {
        Self::new()
    }
}

/// `weak_mask!("...")` cache — stores `String`, returns `&'static str`.
#[doc(hidden)]
pub type WeakCell = WeakCache<String>;

/// `weak_mask!(b"...")` cache — stores `Vec<u8>`, returns `&'static [u8]`.
#[doc(hidden)]
pub type WeakByteCell = WeakCache<alloc::vec::Vec<u8>>;

/// `weak_mask!(c"...")` cache — stores `CString`, returns `&'static CStr`.
#[cfg(feature = "std")]
#[doc(hidden)]
pub type WeakCStrCell = WeakCache<std::ffi::CString>;

/// XOR-decode byte-string obfuscated data and cache the result.
/// Returns `&'static [u8]`. No UTF-8 validation — raw bytes pass
/// through unchanged.
#[doc(hidden)]
pub fn __weak_decode_bytes<const N: usize>(
    obf: &'static [u8; N],
    wrapper: &'static [u8; WRAPPER_LEN],
    cache: &'static WeakByteCell,
) -> &'static [u8] {
    cache.get_or_init(|| weak_xor_decode(obf, wrapper))
}

/// XOR-decode C-string obfuscated data, construct a `CString`, and
/// cache the result. Returns `&'static CStr`.
///
/// `LitCStr` rejects interior NUL at parse time and the XOR cycle cannot
/// introduce one, so the error arm is unreachable in practice; it panics
/// (bare in release, actionable in debug, §5.4) only on an in-process
/// tamper of the obfuscated bytes or wrapper.
#[cfg(feature = "std")]
#[doc(hidden)]
pub fn __weak_decode_cstr<const N: usize>(
    obf: &'static [u8; N],
    wrapper: &'static [u8; WRAPPER_LEN],
    cache: &'static WeakCStrCell,
) -> &'static std::ffi::CStr {
    cache.get_or_init(
        || match std::ffi::CString::new(weak_xor_decode(obf, wrapper)) {
            Ok(cstring) => cstring,
            Err(_) => crate::diagnostics::weak_cstr_failure(),
        },
    )
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
fn mask_key_or_lazy_init(wrapper: &[u8; WRAPPER_LEN]) -> &'static MaskKey {
    cell::get_or_init(|| {
        // No explicit `init!` ran: derive the Embedded-tier unlock_key
        // from the wrapper's public nonce — the keyless floor works in
        // both std and no_std — then decrypt the wrapper through the same
        // path the explicit seams use. Any failure (provider or decrypt)
        // panics with no message to avoid leaking litmask-identifying
        // plaintext; the eager seams forward the equivalent `InitError`.
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
