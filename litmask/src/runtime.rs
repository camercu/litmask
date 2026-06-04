//! Imperative shell over the pure decryption core
//! ([`litmask_internal::decrypt_wrapper`]).
//!
//! The process-global mask key lives in a `OnceLock` populated by
//! [`__init_with_wrapper`] (the target of `init!` / `init_with!`) or
//! lazily by [`__decrypt_str`] on the first `mask!()` call.
//!
//! The decryption path uses bare `panic!()` with no custom message
//! for AEAD authentication and configuration failures. `assert!` and
//! `.expect(...)` alternatives inject message text that would
//! identify the code as litmask-related and leak into user binaries;
//! `match X { Ok(_) => …, Err(_) => panic!() }` is the only form
//! that keeps the unwind path identifier-free.

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
    let mask_key_bytes = match decrypt_wrapper(unlock_key.as_bytes(), wrapper) {
        Ok(bytes) => bytes,
        Err(DecryptError::AuthenticationFailed) => {
            return Err(InitError::Decryption);
        }
        Err(DecryptError::UnsupportedFormat) => {
            return Err(InitError::UnsupportedFormat);
        }
        // `BlobTooShort` cannot reach this branch — `WRAPPER_LEN`
        // is fixed at the type level, so the wrapper is always
        // exactly long enough. A panic here would be a soundness
        // bug in `decrypt_wrapper`, which the typed `WRAPPER_LEN`
        // shape rules out at the call site; we keep the bare
        // `panic!()` (no message) for compile-time exhaustiveness
        // without leaking identifier text into the binary.
        Err(_) => panic!(),
    };
    cell::try_set(MaskKey::new(mask_key_bytes));
    Ok(())
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
/// Panics with no litmask-specific message on AEAD authentication
/// failure, lazy-init provider failure, or wrapper format / cipher-id
/// mismatch.
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
/// either the obfuscated bytes or the wrapper.
#[doc(hidden)]
pub fn __weak_decode<const N: usize>(
    obf: &'static [u8; N],
    wrapper: &'static [u8; WRAPPER_LEN],
    cache: &'static WeakCell,
) -> &'static str {
    cache.get_or_init(|| {
        let decoded = weak_xor_decode(obf, wrapper);
        String::from_utf8(decoded).unwrap()
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
/// The bare `.unwrap()` mirrors the `__decrypt_cstring_call!` policy:
/// `LitCStr` rejects interior NUL at parse time, and the XOR cycle
/// cannot introduce one. Unreachable in practice.
#[cfg(feature = "std")]
#[doc(hidden)]
pub fn __weak_decode_cstr<const N: usize>(
    obf: &'static [u8; N],
    wrapper: &'static [u8; WRAPPER_LEN],
    cache: &'static WeakCStrCell,
) -> &'static std::ffi::CStr {
    cache.get_or_init(|| std::ffi::CString::new(weak_xor_decode(obf, wrapper)).unwrap())
}

#[allow(
    clippy::single_match_else,
    clippy::match_wild_err_arm,
    clippy::manual_let_else
)]
fn mask_key_or_lazy_init(wrapper: &[u8; WRAPPER_LEN]) -> &'static MaskKey {
    cell::get_or_init(|| {
        // No explicit `init!` ran: derive the Embedded-tier unlock_key
        // from the wrapper's public nonce — the keyless floor works in
        // both std and no_std. A failure here panics with no message to
        // avoid leaking litmask-identifying plaintext.
        let provider = crate::EmbeddedProvider::new(wrapper);
        let unlock_key = match provider.unlock_key() {
            Ok(k) => k,
            Err(_) => panic!(),
        };
        let bytes = decrypt_wrapper_or_panic(unlock_key.as_bytes(), wrapper);
        MaskKey::new(bytes)
    })
}

// Both the lazy Embedded path here and (indirectly) every `mask!`
// without an explicit `init!` rely on this; `__init_with_wrapper`
// returns `InitError::Decryption` instead of panicking.
#[allow(clippy::single_match_else, clippy::match_wild_err_arm)]
fn decrypt_wrapper_or_panic(
    unlock_key: &[u8; crate::internal::KEY_LEN],
    wrapper: &[u8; WRAPPER_LEN],
) -> [u8; crate::internal::KEY_LEN] {
    match decrypt_wrapper(unlock_key, wrapper) {
        Ok(bytes) => bytes,
        Err(_) => panic!(),
    }
}

#[allow(clippy::single_match_else, clippy::match_wild_err_arm)]
fn decrypt_blob_or_panic(
    mask_key: &[u8; crate::internal::KEY_LEN],
    blob: &[u8],
) -> alloc::vec::Vec<u8> {
    match decrypt_blob(mask_key, blob) {
        Ok(plaintext) => plaintext,
        Err(_) => panic!(),
    }
}
