//! Compile-time string literal obfuscation with runtime decryption.
//!
//! See `docs/SPECIFICATION.md` for design, threat model, and binary
//! format. Task 5 of `docs/TASKS.md` ships the walking skeleton: a
//! single string literal can be masked via `mask!` and decrypted at
//! runtime via the default `EnvVarProvider`.
//!
//! The crate is `#![no_std]` + `alloc` from day one. The default `std`
//! feature gates only what genuinely requires `std` (currently
//! `EnvVarProvider`'s `std::env::var` lookup).

#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod base64url;
mod cipher;
mod error;
mod key;
mod provider;
mod runtime;

/// Wire-format constants and pure helpers shared with `litmask-build`
/// and `litmask-macros`. Re-exported from the internal crate.
pub(crate) use litmask_internal_format as format;

pub use error::{InitError, KeyError};
pub use key::UnlockKey;
pub use provider::KeyProvider;

/// Length of every symmetric key in bytes (32). Shared by
/// ChaCha20-Poly1305 and AES-256-GCM. Provided for callers that
/// allocate buffers sized to match the key.
pub const KEY_LEN: usize = litmask_internal_format::KEY_LEN;

#[cfg(feature = "std")]
pub use provider::EnvVarProvider;

pub use litmask_macros::mask;

/// Internal helper macro: expands to `include_bytes!(...)` for the
/// embedded encrypted-`mask_key` wrapper at the caller's `OUT_DIR`.
/// Shared by [`init!`], [`init_with!`], and the `mask!` proc-macro to
/// avoid duplicating the `OUT_DIR` path literal at three call sites.
#[doc(hidden)]
#[macro_export]
macro_rules! __wrapper_bytes {
    () => {
        ::core::include_bytes!(::core::concat!(
            ::core::env!("OUT_DIR"),
            "/litmask_wrapper.bin"
        ))
    };
}

/// Initialize the runtime using [`EnvVarProvider::default`] (reads
/// `LITMASK_UNLOCK_KEY` as base64url-encoded 32 bytes).
///
/// This is a declarative macro per `docs/SPECIFICATION.md` Amendment 5;
/// it expands at the call site so it can `include_bytes!` the encrypted
/// `mask_key` wrapper from the calling crate's `OUT_DIR`. Calling
/// `litmask::init!()?` is recommended at program startup to surface
/// initialization errors as `Result`. Without it, the first `mask!()`
/// call performs lazy initialization and panics on failure.
#[macro_export]
macro_rules! init {
    () => {
        $crate::__internal::__init_with_wrapper(
            $crate::EnvVarProvider::default(),
            $crate::__wrapper_bytes!(),
        )
    };
}

/// Initialize the runtime using a caller-supplied [`KeyProvider`].
///
/// Like [`init!`] but accepts any `KeyProvider` value. Errors flow
/// through the same `Result<(), InitError>` as `init!`.
#[macro_export]
macro_rules! init_with {
    ($provider:expr) => {
        $crate::__internal::__init_with_wrapper($provider, $crate::__wrapper_bytes!())
    };
}

#[doc(hidden)]
pub mod __internal {
    //! Symbols required by macro expansion. Not part of the stable API
    //! per spec §1.8.4.
    pub use crate::runtime::{__decrypt_str, __init_with_wrapper};
}
