//! Imperative shell over the pure decryption core in [`crate::cipher`].
//!
//! The process-global [`MaskKey`] lives in a `OnceLock` populated by
//! [`__init_with_wrapper`] (the target of `init!` / `init_with!`) or
//! lazily by [`__decrypt_str`] on the first `mask!()` call.
//!
//! ### Pedantic-lint exceptions
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

use crate::cipher;
use crate::error::InitError;
use crate::format::WRAPPER_LEN;
use crate::key::MaskKey;
use crate::provider::KeyProvider;

// ── Process-global decrypted-key cell ───────────────────────────────
//
// Under `std` we use `std::sync::OnceLock`; under `no_std` we use
// `once_cell::race::OnceBox`. The thin wrapper module below normalizes
// both into the same API shape so the rest of this file is feature-flag
// free.

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

// ── Public entry points called by macro expansion ───────────────────

/// Decrypt the embedded `mask_key` wrapper and store the result in the
/// process-global [`MaskKey`] cell.
///
/// Called by the `init!` and `init_with!` macros after they capture the
/// wrapper bytes via `include_bytes!`.
///
/// # Errors
///
/// Forwards provider errors via [`InitError::KeyProvider`]. Decryption
/// failures will surface as `InitError::Decryption` once Task 8 lands
/// the variant; for now they panic per the §1.9.5 tampering-panic stub.
#[doc(hidden)]
pub fn __init_with_wrapper<P: KeyProvider>(
    provider: P,
    wrapper: &[u8; WRAPPER_LEN],
) -> Result<(), InitError> {
    if cell::is_set() {
        return Ok(());
    }
    let unlock_key = provider.unlock_key()?;
    let mask_key_bytes = decrypt_wrapper_or_panic(&unlock_key.0, wrapper);
    cell::try_set(MaskKey(mask_key_bytes));
    Ok(())
}

/// Decrypt a per-string blob. Called by every expansion of `mask!()`.
///
/// `blob` layout per §1.7.2. `wrapper` is the embedded encrypted-`mask_key`
/// blob, passed by the macro so lazy init can fall back to
/// [`crate::EnvVarProvider`] when no explicit `init!` was issued.
///
/// # Panics
///
/// Panics with no litmask-specific message on AEAD authentication
/// failure, lazy-init provider failure, or wrapper format / cipher-id
/// mismatch (per the §1.9.5 panic-hygiene stub; Task 8 will tighten
/// the error surface).
#[doc(hidden)]
pub fn __decrypt_str(blob: &[u8], wrapper: &[u8; WRAPPER_LEN]) -> String {
    let mask_key = mask_key_or_lazy_init(wrapper);
    let plaintext = decrypt_blob_or_panic(&mask_key.0, blob);
    // mask! generates UTF-8 ciphertext from UTF-8 string literals; the
    // AEAD tag check above already rejects any tampering that could
    // produce non-UTF-8 plaintext. unwrap is safe by construction.
    String::from_utf8(plaintext).unwrap()
}

// ── Imperative-shell glue: panic at unrecoverable boundaries ────────

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
            let bytes = decrypt_wrapper_or_panic(&unlock_key.0, wrapper);
            MaskKey(bytes)
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = wrapper;
            panic!()
        }
    })
}

fn decrypt_wrapper_or_panic(
    unlock_key: &[u8; crate::format::KEY_LEN],
    wrapper: &[u8; WRAPPER_LEN],
) -> [u8; crate::format::KEY_LEN] {
    match cipher::decrypt_wrapper(unlock_key, wrapper) {
        Ok(bytes) => bytes,
        Err(_) => panic!(),
    }
}

fn decrypt_blob_or_panic(
    mask_key: &[u8; crate::format::KEY_LEN],
    blob: &[u8],
) -> alloc::vec::Vec<u8> {
    match cipher::decrypt_blob(mask_key, blob) {
        Ok(plaintext) => plaintext,
        Err(_) => panic!(),
    }
}
