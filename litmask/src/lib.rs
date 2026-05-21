//! Compile-time string literal obfuscation with runtime decryption.
//!
//! Raise the cost of static binary analysis for string constants in
//! Rust binaries. Each call to [`mask!`] encrypts its literal at
//! compile time with an AEAD cipher; the runtime decrypts on first
//! use, after a process-global mask key is recovered from the
//! embedded wrapper using an unlock key that a [`KeyProvider`] sources
//! at runtime (the default [`EnvVarProvider`] reads
//! `LITMASK_UNLOCK_KEY` from the environment).
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

mod error;
mod key;
mod provider;
mod runtime;

pub(crate) use litmask_internal as internal;

pub use error::{InitError, KeyError};
pub use key::UnlockKey;
pub use litmask_internal::KEY_LEN;
pub use provider::{KeyProvider, StaticProvider};

#[cfg(feature = "std")]
pub use provider::{EnvVarProvider, FileProvider, KeyEncoding};

#[cfg(feature = "hw-id")]
pub use provider::HardwareIdProvider;

pub use litmask_macros::{
    mask, mask_all, mask_concat, mask_env, mask_file, mask_format, mask_include_bytes,
    mask_include_str, mask_option_env, unmasked, weak_mask,
};

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

/// Internal dispatch for `mask!(c"...")` expansion. With the `std`
/// feature, wraps the runtime's [`__internal::__decrypt`] return in
/// `CString::new(...).unwrap()`; without it, emits a `compile_error!`
/// pointing at the user's `mask!(c"...")` call site.
///
/// Lives at the crate root (not inside [`__internal`]) because the
/// proc-macro can't read the consumer's feature flags — gating must
/// happen here, in `litmask`'s own cfg context. The c-string-specific
/// construction lives in this shim rather than in a dedicated runtime
/// helper because it is the only kind whose return type is `std`-only.
///
/// `CString::new(...)` only returns `NulError` if the input contains
/// an interior NUL byte. Two layers rule this out at compile + runtime:
/// `LitCStr` rejects interior NUL at parse time (so the encrypted
/// blob never carries one), and AEAD authentication rejects any
/// tampering that could introduce one. The bare `.unwrap()` is
/// therefore unreachable in practice — and stays bare (no message)
/// to keep the unwind path free of litmask-identifying plaintext.
/// The unwind point is the user's `mask!(c"...")` call site, not
/// inside the litmask crate.
#[cfg(feature = "std")]
#[doc(hidden)]
#[macro_export]
macro_rules! __decrypt_cstring_call {
    ($blob:expr, $wrapper:expr) => {
        ::std::ffi::CString::new($crate::__internal::__decrypt($blob, $wrapper)).unwrap()
    };
}

#[cfg(not(feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __decrypt_cstring_call {
    ($blob:expr, $wrapper:expr) => {
        ::core::compile_error!(
            "mask!(c\"...\") requires the `std` feature on the `litmask` crate; \
             enable it via `litmask = { features = [\"std\"] }`"
        )
    };
}

#[doc(hidden)]
pub mod __internal {
    //! Symbols required by macro expansion. Not part of the stable API.
    #[cfg(feature = "std")]
    pub use crate::runtime::__weak_decode;
    pub use crate::runtime::{__decrypt, __init_with_wrapper};
    // Re-export under a hygienic alias so the proc-macro emits a
    // single `::litmask::__internal::__String::from_utf8(...)` path
    // for the `mask!("...")` case.
    //
    // The natural alternative — emitting `::alloc::string::String`
    // directly — does NOT work in std consumer crates: `alloc` is
    // not in the list of imported crates at a std crate's root
    // unless the user adds `extern crate alloc;` explicitly. Without
    // it, the emitted path fails with E0433. The re-export routes
    // through `::litmask::`, which the user is already importing,
    // so no extra declaration is required from the consumer side
    // for either std or no_std + alloc.
    pub use alloc::string::String as __String;
}
