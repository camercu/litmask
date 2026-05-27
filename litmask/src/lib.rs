//! Compile-time string literal obfuscation with runtime decryption.
//!
//! Raise the cost of static binary analysis for string constants in
//! Rust binaries. Each call to [`mask!`] encrypts its literal at
//! compile time with an AEAD cipher (ChaCha20-Poly1305 or
//! AES-256-GCM); the runtime decrypts on first use, after a
//! process-global mask key is recovered from the embedded wrapper
//! using an unlock key that a [`KeyProvider`] sources at runtime
//! (the default [`EnvVarProvider`] reads `LITMASK_UNLOCK_KEY` from
//! the environment).
//!
//! ```ignore
//! use litmask::{init, mask};
//!
//! fn main() -> Result<(), litmask::InitError> {
//!     litmask::init!()?;
//!     println!("{}", mask!("sensitive data"));
//!     Ok(())
//! }
//! ```
//!
//! ## Security levels
//!
//! | Configuration | Defeats |
//! |---|---|
//! | Zero-config build (defaults to `EnvVarProvider`) | `strings`, casual binary inspection (Level 1); also Level 2 because `unlock_key` is not embedded |
//! | `FileProvider` | Above, key sourced from a file path |
//! | `HardwareIdProvider` | Above + binary moved to a different machine |
//! | Custom `KeyProvider` (network call, vault) | Above + offline attackers |
//!
//! The "zero-config" descriptor refers to absence of project
//! configuration, not to absence of runtime key provisioning.
//! Providers that source `unlock_key` from external runtime state
//! require the deployer to provision that state.
//!
//! ## What litmask does NOT protect against
//!
//! - Runtime memory inspection
//! - Debugger attachment after key derivation
//! - Compromised runtime environments
//! - Side-channel attacks (timing, power analysis)
//! - Control-flow obfuscation or anti-debugging
//! - Protection of dynamically generated strings
//! - Perfect secrecy under any threat model
//!
//! ## Comparison with existing crates
//!
//! | Property | `obfstr` | `litcrypt`/`litcrypt2` | `litmask` |
//! |---|---|---|---|
//! | Cipher | XOR | XOR | ChaCha20-Poly1305 (AEAD) or AES-256-GCM |
//! | Tamper detection | No | No | Yes (AEAD authentication) |
//! | Per-string nonces | Compile-time random (no auth) | None | Per-build deterministic, authenticated |
//! | Key model | Compile-time random per build | Single env var | Layered: `mask_key` + `unlock_key`, multiple providers |
//! | Format string masking | Separate `fmtools` crate | None | Built-in [`mask_format!`] with single-evaluation semantics |
//! | Module-level masking | None | None | [`macro@mask_all`] with deep substitution |
//! | Hardware binding | None | None | Yes (post-build rebind via `litmask` CLI) |
//! | Multiple literal types (str/bytes/cstr) | str only | str only | All three |
//! | `no_std` support | Limited | No | Yes (with `alloc`) |
//! | Threat model documented | Minimal | Minimal | Explicit security ladder, honest scope |
//! | Reproducible builds | No | No | Yes (with `LITMASK_RNG_SEED`) |
//! | Fuzzing | No | No | Yes |
//!
//! The cipher upgrade (XOR to AEAD) is the primary technical advance.
//!
//! ## Two-phase masking
//!
//! [`mask!`] (and its variants [`mask_format!`], [`mask_concat!`],
//! etc.) require [`init!`] to have populated the AEAD mask-key cell.
//! [`weak_mask!`] is the **only** masking macro that works before
//! `init!()` — use it exclusively for bootstrap-phase strings
//! (env-var names, default file paths) that must be readable before
//! the provider has run. `weak_mask!` provides anti-`strings(1)`
//! obfuscation only; real secrets always go through `mask!`.
//!
//! ## Return types
//!
//! [`mask!`] returns [`String`](alloc::string::String), not
//! `&'static str`, because masked values are decrypted at runtime
//! and cannot inhabit `'static` storage. If a call site needs
//! `&str`, bind once:
//!
//! ```ignore
//! let secret = mask!("my secret");
//! let s: &str = &secret;
//! ```
//!
//! When the threat model permits weaker guarantees (no AEAD,
//! plaintext cached for program lifetime), [`weak_mask!`] returns
//! `&'static str` directly.
//!
//! The crate is `#![no_std]` + `alloc` from day one. The default
//! `std` feature gates only what genuinely requires `std`.

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

/// Write a `mask_format!`-encrypted format string to a destination.
///
/// Thin wrapper: `mask_write!(dst, "fmt", args)` expands to
/// `write!(dst, "{}", mask_format!("fmt", args))`. Works with any
/// `core::fmt::Write` or `std::io::Write` implementor (the caller
/// must have the appropriate trait in scope, same as `write!`).
///
/// **Security note:** the decrypted text is written in the clear to
/// `dst`. litmask protects literals at rest in the binary; once
/// written, the destination controls confidentiality.
///
/// Available in `no_std` + `alloc` builds.
#[macro_export]
macro_rules! mask_write {
    ($dst:expr, $($args:tt)*) => {
        ::core::write!($dst, "{}", $crate::mask_format!($($args)*))
    };
}

/// Write a `mask_format!`-encrypted format string plus newline to a
/// destination.
///
/// Thin wrapper: `mask_writeln!(dst, "fmt", args)` expands to
/// `writeln!(dst, "{}", mask_format!("fmt", args))`. The no-argument
/// form `mask_writeln!(dst)` writes a bare newline (no masking
/// needed).
///
/// **Security note:** the decrypted text is written in the clear to
/// `dst`. litmask protects literals at rest in the binary; once
/// written, the destination controls confidentiality.
///
/// Available in `no_std` + `alloc` builds.
#[macro_export]
macro_rules! mask_writeln {
    ($dst:expr) => {
        ::core::writeln!($dst)
    };
    ($dst:expr, $($args:tt)*) => {
        ::core::writeln!($dst, "{}", $crate::mask_format!($($args)*))
    };
}

/// Print a `mask_format!`-encrypted format string to stdout.
///
/// Thin wrapper: `mask_print!("fmt", args)` expands to
/// `print!("{}", mask_format!("fmt", args))`.
///
/// **Security note:** the decrypted text is printed in the clear to
/// stdout. litmask protects literals at rest in the binary; once
/// printed, the output is unprotected.
#[cfg(feature = "std")]
#[macro_export]
macro_rules! mask_print {
    ($($args:tt)*) => {
        ::std::print!("{}", $crate::mask_format!($($args)*))
    };
}

/// Print a `mask_format!`-encrypted format string plus newline to
/// stdout.
///
/// Thin wrapper: `mask_println!("fmt", args)` expands to
/// `println!("{}", mask_format!("fmt", args))`. The no-argument form
/// `mask_println!()` prints a bare newline (no masking needed).
///
/// **Security note:** the decrypted text is printed in the clear to
/// stdout. litmask protects literals at rest in the binary; once
/// printed, the output is unprotected.
#[cfg(feature = "std")]
#[macro_export]
macro_rules! mask_println {
    () => {
        ::std::println!()
    };
    ($($args:tt)*) => {
        ::std::println!("{}", $crate::mask_format!($($args)*))
    };
}

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
    pub use crate::runtime::{__decrypt, __init_with_wrapper, __weak_decode, WeakCell};
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
