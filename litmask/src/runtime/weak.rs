//! `weak_mask!()` runtime: XOR decode + per-call-site once-init caches.
//!
//! Independent of the mask-key path in the parent module — the weak key
//! derives from the embedded wrapper's cleartext nonce alone, so every
//! entry point here works before `init!()` has populated the mask-key
//! cell. The same §5.4 panic-hygiene contract applies: failure arms
//! route to [`crate::diagnostics`], never to message-bearing panics
//! that would fingerprint user binaries as litmask-built.

use alloc::string::String;

use crate::internal::WRAPPER_LEN;

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
