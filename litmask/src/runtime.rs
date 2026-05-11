//! Runtime state and entry points called by macro expansion.
//!
//! The process-global [`MaskKey`] lives in a `OnceLock` populated by
//! [`__init_with_wrapper`] (the target of `init!` / `init_with!`) or
//! lazily by [`__decrypt_str`] on the first `mask!()` call.
//!
//! ### Pedantic-lint exceptions
//!
//! Spec §1.9.5 prescribes the `match X { Ok(_) => …, Err(_) => panic!() }`
//! form and bare `if cond { panic!() }` guards as the canonical pattern
//! for panic hygiene. The `assert!` and `.expect(...)` alternatives that
//! clippy's pedantic group prefers all inject custom message text that
//! would identify the code as litmask-related, which §1.9.5 forbids.
#![allow(
    clippy::single_match_else,
    clippy::match_wild_err_arm,
    clippy::manual_assert,
    clippy::manual_let_else,
    clippy::needless_pass_by_value,
    clippy::must_use_candidate
)]

use alloc::string::String;
use alloc::vec::Vec;

use crate::cipher;
use crate::error::InitError;
use crate::key::{KEY_LEN, MaskKey};
use crate::nonce;
use crate::provider::KeyProvider;

/// Wrapper-format constants per §1.7.3.
const WRAPPER_LEN: usize = 62;
const WRAPPER_VERSION: u8 = 0x01;
const WRAPPER_CIPHER_CHACHA20: u8 = 0x01;
const HEADER_LEN: usize = 14; // 1 (version) + 1 (cipher) + 12 (nonce)

// Process-global once-cell for the decrypted `MaskKey`. Under `std` we
// use `std::sync::OnceLock`; under `no_std` we use
// `once_cell::race::OnceBox` which provides equivalent semantics.
//
// `OnceBox` stores a `Box<MaskKey>` and exposes `set(Box<T>)` / `get()`
// instead of `OnceLock`'s `set(T)` / `get()`. The thin wrapper module
// below normalizes both into the same `get / try_set / get_or_init` API
// shape used by the rest of this file.

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
/// process-global [`MaskKey`] cell.
///
/// Called by the `init!` and `init_with!` macros after they capture the
/// wrapper bytes via `include_bytes!`.
///
/// # Errors
///
/// Forwards provider errors. Decryption failures will surface as
/// [`InitError::Decryption`] once Task 8 lands the variant; for now
/// they panic per the tampering-panic policy stub.
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

    // First-writer-wins. If two threads race, both compute the same
    // mask_key (deterministic), so the loser silently drops its copy.
    cell::try_set(MaskKey(mask_key_bytes));
    Ok(())
}

/// Decrypt a per-string blob. Called by every expansion of `mask!()`.
///
/// `blob` layout per §1.7.2: `nonce (12) || ciphertext (n) || tag (16)`.
/// `wrapper` is the embedded encrypted-`mask_key` blob, passed by the
/// macro expansion so lazy init can fall back to
/// [`crate::EnvVarProvider`] when `init!` was never called.
///
/// # Panics
///
/// Panics with no litmask-specific message on AEAD authentication
/// failure or on lazy-init provider failure (per the §1.9.5 panic
/// hygiene stub; Task 8 will tighten this).
#[doc(hidden)]
pub fn __decrypt_str(blob: &[u8], wrapper: &[u8; WRAPPER_LEN]) -> String {
    let mask_key = mask_key_or_lazy_init(wrapper);
    let plaintext = decrypt_blob_or_panic(mask_key.as_bytes(), blob);
    // mask! only generates UTF-8 ciphertext from UTF-8 string literals,
    // so this conversion can only fail under tampering — which is
    // already detected by the AEAD tag above. unwrap is safe here.
    String::from_utf8(plaintext).unwrap()
}

fn mask_key_or_lazy_init(wrapper: &[u8; WRAPPER_LEN]) -> &'static MaskKey {
    cell::get_or_init(|| {
        // Under no_std there is no default provider — lazy init is
        // only viable if the user already called init_with! before the
        // first mask!(). Reaching this branch without init_with! is a
        // configuration error that panics per §1.9.5.
        #[cfg(feature = "std")]
        {
            let provider = crate::EnvVarProvider::default();
            let unlock_key = match provider.unlock_key() {
                Ok(k) => k,
                Err(_) => panic!(),
            };
            let bytes = decrypt_wrapper_or_panic(unlock_key.as_bytes(), wrapper);
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
    unlock_key: &[u8; KEY_LEN],
    wrapper: &[u8; WRAPPER_LEN],
) -> [u8; KEY_LEN] {
    // Header sanity. Format-version and cipher-id mismatch produce
    // their own InitError variants in Task 21; for the walking skeleton
    // we panic if the bytes disagree, since build and runtime ship in
    // lockstep.
    if wrapper[0] != WRAPPER_VERSION || wrapper[1] != WRAPPER_CIPHER_CHACHA20 {
        panic!();
    }
    let wrapper_nonce: [u8; 12] = wrapper[2..HEADER_LEN].try_into().unwrap();
    let body = &wrapper[HEADER_LEN..]; // ciphertext (32) || tag (16)
    let plaintext: Vec<u8> = match cipher::decrypt(unlock_key, &wrapper_nonce, body) {
        Ok(p) => p,
        Err(()) => panic!(),
    };
    plaintext
        .as_slice()
        .try_into()
        .expect("mask_key is 32 bytes")
}

fn decrypt_blob_or_panic(mask_key: &[u8; KEY_LEN], blob: &[u8]) -> Vec<u8> {
    if blob.len() < nonce::NONCE_LEN + 16 {
        panic!();
    }
    let nonce_bytes: [u8; nonce::NONCE_LEN] = blob[..nonce::NONCE_LEN]
        .try_into()
        .expect("checked length above");
    let body = &blob[nonce::NONCE_LEN..];
    match cipher::decrypt(mask_key, &nonce_bytes, body) {
        Ok(p) => p,
        Err(()) => panic!(),
    }
}
