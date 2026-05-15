//! Imperative shell over the pure decryption core in
//! [`litmask_internal::cipher`].
//!
//! The process-global mask key lives in a `OnceLock` populated by
//! [`__init_with_wrapper`] (the target of `init!` / `init_with!`) or
//! lazily by [`__decrypt_str`] on the first `mask!()` call.
//!
//! Spec §1.9.5 prescribes the `match X { Ok(_) => …, Err(_) => panic!() }`
//! form for panic hygiene. The `assert!` and `.expect(...)` alternatives
//! that clippy's pedantic group prefers all inject custom message text
//! that would identify the code as litmask-related, which §1.9.5
//! forbids.
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
/// Forwards provider errors via [`InitError::KeyProvider`]. Decryption
/// failures panic with no litmask-specific message until the
/// `InitError::Decryption` variant lands.
#[doc(hidden)]
pub fn __init_with_wrapper<P: KeyProvider>(
    provider: P,
    wrapper: &[u8; WRAPPER_LEN],
) -> Result<(), InitError> {
    if cell::is_set() {
        return Ok(());
    }
    let unlock_key = provider.unlock_key()?;
    let mask_key_bytes = decrypt_wrapper_or_panic(unlock_key.as_bytes(), wrapper);
    cell::try_set(MaskKey::new(mask_key_bytes));
    Ok(())
}

/// Decrypt a per-string blob. Called by every `mask!("...")` expansion.
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
pub fn __decrypt_str(blob: &[u8], wrapper: &[u8; WRAPPER_LEN]) -> String {
    // mask! generates UTF-8 ciphertext from UTF-8 string literals; the
    // AEAD tag check inside decrypt_blob_to_vec rejects any tampering
    // that could produce non-UTF-8 plaintext, so the unwrap is safe by
    // construction.
    String::from_utf8(decrypt_blob_to_vec(blob, wrapper)).unwrap()
}

/// Decrypt a per-string blob to raw bytes. Called by every
/// `mask!(b"...")` expansion (spec §2.1.1.3).
///
/// Same panic policy as [`__decrypt_str`].
#[doc(hidden)]
pub fn __decrypt_bytes(blob: &[u8], wrapper: &[u8; WRAPPER_LEN]) -> alloc::vec::Vec<u8> {
    decrypt_blob_to_vec(blob, wrapper)
}

/// Decrypt a per-string blob to a NUL-terminated `CString`. Called by
/// every `mask!(c"...")` expansion (spec §2.1.1.4). The NUL terminator
/// is added by `CString::new` over the decrypted payload bytes; the
/// blob itself never carries a NUL.
///
/// # Panics
///
/// Same panic policy as [`__decrypt_str`]. The `CString::new` step
/// cannot reach its `NulError` branch in practice: c-string literals
/// reject interior NUL at parse time, AEAD authentication rejects any
/// tampering that could introduce one — but the unwrap stays
/// `unwrap()` rather than expect-with-message to preserve spec §1.9.5
/// panic hygiene.
#[cfg(feature = "std")]
#[doc(hidden)]
pub fn __decrypt_cstring(blob: &[u8], wrapper: &[u8; WRAPPER_LEN]) -> std::ffi::CString {
    std::ffi::CString::new(decrypt_blob_to_vec(blob, wrapper)).unwrap()
}

fn decrypt_blob_to_vec(blob: &[u8], wrapper: &[u8; WRAPPER_LEN]) -> alloc::vec::Vec<u8> {
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
/// # Panics
///
/// Panics if the cached decode does not produce valid UTF-8. The
/// macro only accepts string literals, so the AEAD-equivalent
/// guarantee here is just that `weak_mask!()` callers don't feed it
/// arbitrary bytes; UTF-8 failure indicates an in-process tamper of
/// either the obfuscated bytes or the wrapper.
#[cfg(feature = "std")]
#[doc(hidden)]
pub fn __weak_decode<const N: usize>(
    obf: &'static [u8; N],
    wrapper: &'static [u8; WRAPPER_LEN],
    cache: &'static std::sync::OnceLock<String>,
) -> &'static str {
    cache
        .get_or_init(|| {
            let wrapper = core::hint::black_box(&wrapper[..]);
            let obf = core::hint::black_box(&obf[..]);
            let decoded = crate::internal::xor_cycle(obf, wrapper);
            String::from_utf8(decoded).expect("weak_mask! input was valid UTF-8")
        })
        .as_str()
}

fn mask_key_or_lazy_init(wrapper: &[u8; WRAPPER_LEN]) -> &'static MaskKey {
    cell::get_or_init(|| {
        // Under no_std there is no default provider — lazy init only
        // makes sense if init_with! ran first. Reaching this branch
        // means a configuration error; panic per §1.9.5.
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
