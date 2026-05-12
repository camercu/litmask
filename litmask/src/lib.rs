//! Compile-time string literal obfuscation with runtime decryption.
//!
//! Raise the cost of static binary analysis for string constants in
//! Rust binaries. Each call to [`mask!`] encrypts its literal at
//! compile time with an AEAD cipher; the runtime decrypts on first use
//! using a master key supplied by a [`KeyProvider`] (the default
//! [`EnvVarProvider`] reads `LITMASK_UNLOCK_KEY` from the environment).
//!
//! See `docs/SPECIFICATION.md` and `docs/THREAT_MODEL.md` in the
//! source repository for the design rationale, threat model, and
//! security guarantees.
//!
//! ```ignore
//! use litmask::{init, mask};
//!
//! fn main() {
//!     // Optional but recommended: surface init errors as Result.
//!     litmask::init!().expect("missing LITMASK_UNLOCK_KEY");
//!     println!("{}", mask!("hello"));
//! }
//! ```
//!
//! The crate is `#![no_std]` + `alloc` from day one. The default `std`
//! feature gates only what genuinely requires `std`.

#![no_std]

// Self-import: lets the public proc-macros emit absolute `::litmask::`
// paths in their generated code, and have those paths resolve
// correctly when the macros are invoked from inside this crate itself
// (e.g., `EnvVarProvider::default()` calling `crate::weak_mask!(...)`).
extern crate self as litmask;

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

mod base64url;
mod cipher;
mod error;
mod key;
mod provider;
mod runtime;

/// Wire-format constants and pure helpers shared with the build-script
/// helper and the proc-macro crate.
pub(crate) use litmask_internal_format as format;

pub use error::{InitError, KeyError};
pub use key::UnlockKey;
pub use litmask_internal_format::KEY_LEN;
pub use provider::KeyProvider;

#[cfg(feature = "std")]
pub use provider::EnvVarProvider;

pub use litmask_macros::{mask, weak_mask};

/// Internal helper: expand to `include_bytes!(...)` for the embedded
/// encrypted-`mask_key` wrapper at the caller's `OUT_DIR`. Shared by
/// [`init!`], [`init_with!`], and the `mask!` proc-macro to avoid
/// duplicating the path literal at three call sites.
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
/// Declarative macro: expands at the call site so it can read the
/// embedded encrypted-`mask_key` wrapper from the calling crate's
/// `OUT_DIR`. Calling `litmask::init!()?` at program startup is
/// recommended to surface initialization errors as `Result`. Without
/// it, the first `mask!()` call performs lazy initialization and
/// panics on failure.
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
    //! Symbols required by macro expansion. Not part of the stable API.
    pub use crate::runtime::{__decrypt_str, __init_with_wrapper};
    pub use litmask_internal_format::xor_cycle as __xor_cycle;
}
