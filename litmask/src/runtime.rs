//! Imperative shell over the pure decryption core in
//! [`litmask_internal::cipher`].
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
#![allow(
    clippy::single_match_else,
    clippy::match_wild_err_arm,
    clippy::manual_let_else,
    clippy::needless_pass_by_value,
    clippy::must_use_candidate
)]

use alloc::string::String;

use crate::error::InitError;
use crate::internal::{WRAPPER_LEN, cipher};
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
/// [`InitError::Decryption`]. Unrecognized wrapper header bytes
/// surface as [`InitError::UnsupportedFormat`] or
/// [`InitError::UnsupportedCipher`].
#[doc(hidden)]
pub fn __init_with_wrapper<P: KeyProvider>(
    provider: P,
    wrapper: &[u8; WRAPPER_LEN],
) -> Result<(), InitError> {
    if cell::is_set() {
        return Ok(());
    }
    let unlock_key = provider.unlock_key()?;
    let mask_key_bytes = match cipher::decrypt_wrapper(unlock_key.as_bytes(), wrapper) {
        Ok(bytes) => bytes,
        Err(cipher::DecryptError::AuthenticationFailed) => {
            return Err(InitError::Decryption);
        }
        Err(cipher::DecryptError::UnsupportedFormat) => {
            return Err(InitError::UnsupportedFormat);
        }
        Err(cipher::DecryptError::UnsupportedCipher) => {
            return Err(InitError::UnsupportedCipher);
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
/// init can fall back to [`crate::EnvVarProvider`] when no explicit
/// `init!` was issued.
///
/// # Panics
///
/// Panics with no litmask-specific message on AEAD authentication
/// failure, lazy-init provider failure, or wrapper format / cipher-id
/// mismatch.
#[doc(hidden)]
pub fn __decrypt(blob: &[u8], wrapper: &[u8; WRAPPER_LEN]) -> alloc::vec::Vec<u8> {
    let mask_key = mask_key_or_lazy_init(wrapper);
    decrypt_blob_or_panic(mask_key.as_bytes(), blob)
}

/// Decode a `weak_mask!()`-obfuscated literal on first call and cache
/// the result for the program's lifetime, returning a stable
/// `&'static str` borrowed from the cache.
///
/// The two `black_box` calls hide the const-folded inputs (the
/// per-call-site `__WEAK_OBF` array and the per-build `include_bytes!`
/// wrapper) from LLVM. Without them the optimizer can constant-fold
/// the XOR-cycle and materialize the decoded plaintext directly in
/// `.rodata`, defeating `weak_mask!()`'s anti-`strings(1)` purpose.
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
        let wrapper = core::hint::black_box(&wrapper[..]);
        let obf = core::hint::black_box(&obf[..]);
        let decoded = crate::internal::xor_cycle(obf, wrapper);
        String::from_utf8(decoded).unwrap_or_else(|_| panic!("invalid utf-8"))
    })
}

/// Per-call-site cache type for `weak_mask!()`. The proc-macro
/// emits a `static` of this type at each invocation site; the first
/// runtime access through [`__weak_decode`] populates it with the
/// decoded `String`, and subsequent accesses return a borrow.
///
/// Two backends, selected by feature flag:
///
/// - `feature = "std"` → `std::sync::OnceLock<String>`. Standard
///   library primitive, optimal under hosted targets.
/// - `not(feature = "std")` → `once_cell::race::OnceBox<String>`.
///   The same `race::OnceBox` primitive the runtime's global
///   `MASK_KEY` cell uses under `no_std + alloc`.
///
/// The two backends have differently-shaped `get_or_init` APIs
/// (`OnceLock` accepts `FnOnce() -> T`; `OnceBox` accepts `FnOnce()
/// -> Box<T>`). The shim wraps both behind a unified
/// `FnOnce() -> String` interface so callers don't have to feature-
/// gate at every call site.
///
/// # Why a struct and not a type alias
///
/// A bare `pub type WeakCell = <backend>` would force callers (the
/// emitted `weak_mask!()` expansion) to know the backend's
/// `get_or_init` shape per feature. The struct wrapper localizes
/// that conditional inside this module so the proc-macro emits one
/// shape regardless of which feature is active.
#[doc(hidden)]
pub struct WeakCell {
    #[cfg(feature = "std")]
    inner: std::sync::OnceLock<String>,
    #[cfg(not(feature = "std"))]
    inner: once_cell::race::OnceBox<String>,
}

impl WeakCell {
    /// Construct an empty cell. `const fn` so the proc-macro can
    /// emit `static __WEAK_CACHE: WeakCell = WeakCell::new();`
    /// without a lazy initializer.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            inner: std::sync::OnceLock::new(),
            #[cfg(not(feature = "std"))]
            inner: once_cell::race::OnceBox::new(),
        }
    }

    /// Initialize the cell on first call; return a `&str` borrowing
    /// the cached `String`. The closure runs at most once even
    /// under concurrent first-callers (`OnceLock` / `OnceBox` both
    /// guarantee this).
    pub fn get_or_init<F: FnOnce() -> String>(&'static self, f: F) -> &'static str {
        #[cfg(feature = "std")]
        {
            self.inner.get_or_init(f).as_str()
        }
        #[cfg(not(feature = "std"))]
        {
            self.inner
                .get_or_init(|| alloc::boxed::Box::new(f()))
                .as_str()
        }
    }
}

impl Default for WeakCell {
    fn default() -> Self {
        Self::new()
    }
}

/// Per-call-site cache for `weak_mask!(b"...")`. Same architecture as
/// [`WeakCell`] but stores `Vec<u8>` and returns `&'static [u8]`.
#[doc(hidden)]
pub struct WeakByteCell {
    #[cfg(feature = "std")]
    inner: std::sync::OnceLock<alloc::vec::Vec<u8>>,
    #[cfg(not(feature = "std"))]
    inner: once_cell::race::OnceBox<alloc::vec::Vec<u8>>,
}

impl WeakByteCell {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            #[cfg(feature = "std")]
            inner: std::sync::OnceLock::new(),
            #[cfg(not(feature = "std"))]
            inner: once_cell::race::OnceBox::new(),
        }
    }

    pub fn get_or_init<F: FnOnce() -> alloc::vec::Vec<u8>>(&'static self, f: F) -> &'static [u8] {
        #[cfg(feature = "std")]
        {
            self.inner.get_or_init(f).as_slice()
        }
        #[cfg(not(feature = "std"))]
        {
            self.inner
                .get_or_init(|| alloc::boxed::Box::new(f()))
                .as_slice()
        }
    }
}

impl Default for WeakByteCell {
    fn default() -> Self {
        Self::new()
    }
}

/// XOR-decode byte-string obfuscated data and cache the result.
/// Returns `&'static [u8]`. No UTF-8 validation — raw bytes pass
/// through unchanged.
#[doc(hidden)]
pub fn __weak_decode_bytes<const N: usize>(
    obf: &'static [u8; N],
    wrapper: &'static [u8; WRAPPER_LEN],
    cache: &'static WeakByteCell,
) -> &'static [u8] {
    cache.get_or_init(|| {
        let wrapper = core::hint::black_box(&wrapper[..]);
        let obf = core::hint::black_box(&obf[..]);
        crate::internal::xor_cycle(obf, wrapper)
    })
}

/// Per-call-site cache for `weak_mask!(c"...")`. Stores a `CString`
/// and returns `&'static CStr`. Only available under the `std`
/// feature, matching `mask!(c"...")`'s feature gate.
#[cfg(feature = "std")]
#[doc(hidden)]
pub struct WeakCStrCell {
    inner: std::sync::OnceLock<std::ffi::CString>,
}

#[cfg(feature = "std")]
impl WeakCStrCell {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            inner: std::sync::OnceLock::new(),
        }
    }

    pub fn get_or_init<F: FnOnce() -> std::ffi::CString>(
        &'static self,
        f: F,
    ) -> &'static std::ffi::CStr {
        self.inner.get_or_init(f).as_c_str()
    }
}

#[cfg(feature = "std")]
impl Default for WeakCStrCell {
    fn default() -> Self {
        Self::new()
    }
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
    cache.get_or_init(|| {
        let wrapper = core::hint::black_box(&wrapper[..]);
        let obf = core::hint::black_box(&obf[..]);
        let decoded = crate::internal::xor_cycle(obf, wrapper);
        std::ffi::CString::new(decoded).unwrap()
    })
}

fn mask_key_or_lazy_init(wrapper: &[u8; WRAPPER_LEN]) -> &'static MaskKey {
    cell::get_or_init(|| {
        // Under no_std there is no default provider — lazy init only
        // makes sense if init_with! ran first. Reaching this branch
        // means a configuration error; panic with no message to
        // avoid leaking litmask-identifying plaintext.
        #[cfg(feature = "std")]
        {
            let provider = crate::EnvVarProvider::default();
            let unlock_key = match provider.unlock_key() {
                Ok(k) => k,
                Err(_) => panic!(),
            };
            let bytes = decrypt_wrapper_or_panic(unlock_key.as_bytes(), wrapper);
            MaskKey::new(bytes)
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = wrapper;
            panic!()
        }
    })
}

// Only the lazy-init path under `cfg(feature = "std")` panics on
// wrapper decrypt failure now; `__init_with_wrapper` returns
// `InitError::Decryption` instead. Without the cfg gate this would
// be dead code under `--no-default-features`.
#[cfg(feature = "std")]
fn decrypt_wrapper_or_panic(
    unlock_key: &[u8; crate::internal::KEY_LEN],
    wrapper: &[u8; WRAPPER_LEN],
) -> [u8; crate::internal::KEY_LEN] {
    match cipher::decrypt_wrapper(unlock_key, wrapper) {
        Ok(bytes) => bytes,
        Err(_) => panic!(),
    }
}

fn decrypt_blob_or_panic(
    mask_key: &[u8; crate::internal::KEY_LEN],
    blob: &[u8],
) -> alloc::vec::Vec<u8> {
    match cipher::decrypt_blob(mask_key, blob) {
        Ok(plaintext) => plaintext,
        Err(_) => panic!(),
    }
}
