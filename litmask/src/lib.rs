//! Compile-time string literal obfuscation with runtime decryption.
//!
//! Raise the cost of static binary analysis for string constants in
//! Rust binaries. Each call to [`mask!`] encrypts its literal at
//! compile time with an AEAD cipher (ChaCha20-Poly1305 or
//! AES-256-GCM); the runtime decrypts on first use, after a
//! process-global mask key is recovered from the embedded wrapper
//! using an unlock key that a [`KeyProvider`] sources at runtime. The
//! keyless Embedded floor derives that key from the wrapper's public
//! nonce (no `init!` needed); stronger providers source the key from
//! external runtime state via a governing `init!(provider)`.
//!
//! ```no_run
//! // The keyless Embedded tier self-initializes on the first `mask!()`.
//! println!("{}", litmask::mask!("sensitive data"));
//! ```
//!
//! For the project overview, the security-level ladder, the threat
//! scope, and how litmask compares to `obfstr` / `litcrypt`, see the
//! project README and `docs/ARCHITECTURE.md`. This module doc is the API
//! reference.
//!
//! ## Two-phase masking
//!
//! [`mask!`] (and its variants [`mask_format!`], [`mask_concat!`],
//! etc.) need the AEAD mask key, which the keyless Embedded tier
//! recovers lazily on the first call; higher tiers require a governing
//! [`init!`] first. [`weak_mask!`] is the **only** masking macro that
//! works before the runtime is unlocked — use it exclusively for
//! bootstrap-phase strings (env-var names, default file paths) a
//! governing provider itself needs. `weak_mask!` provides
//! anti-`strings(1)` obfuscation only; real secrets always go through
//! [`mask!`].
//!
//! ## Library authors and governed masking
//!
//! litmask composes across a dependency graph. The rule for **library
//! authors** is one line:
//!
//! > **If your crate uses litmask internally, never call [`init!`] — only
//! > [`mask!`].** Unlocking is the *host binary's* job, not the library's.
//!
//! A library just masks its own strings; whoever links the final binary
//! decides how the whole graph is unlocked:
//!
//! - **Transparent masking** (default): the host does nothing — every
//!   masking crate self-unlocks at the keyless Embedded floor on first
//!   use (`strings(1)`-resistance only).
//! - **Governed masking**: the host sets one unlock key in the *build*
//!   environment (`LITMASK_UNLOCK_KEY`, reaching every crate's
//!   `build.rs`) and calls a single governing [`init!`] at startup; that
//!   one key unlocks the entire graph with real secrecy.
//!
//! The seal tier is fixed by the shared build environment, so the binary
//! owner governs the whole graph and libraries need no configuration.
//! There is no bare `init!()`; the governing forms are `init!(provider)`,
//! `init!(bind_to_machine)`, and `init!(bind_to_machine + provider)`. See
//! `docs/adr/0001-masking-crate-unlock-governance.md`.
//!
//! ## Return types
//!
//! [`mask!`] returns [`String`](alloc::string::String), not
//! `&'static str`, because masked values are decrypted at runtime
//! and cannot inhabit `'static` storage. If a call site needs
//! `&str`, bind once:
//!
//! ```no_run
//! let secret = litmask::mask!("my secret");
//! let s: &str = &secret;
//! ```
//!
//! When the threat model permits weaker guarantees (no AEAD,
//! plaintext cached for program lifetime), [`weak_mask!`] returns
//! `&'static` references directly: `&'static str` for `"..."`,
//! `&'static [u8]` for `b"..."`, `&'static CStr` for `c"..."`
//! (`std` feature).
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

mod diagnostics;
mod error;
mod key;
mod macro_plumbing;
mod provider;
mod runtime;

pub(crate) use litmask_internal as internal;

pub use error::{InitError, KeyError};
pub use key::UnlockKey;

pub use litmask_internal::KEY_LEN;
pub(crate) use provider::EmbeddedProvider;
pub use provider::KeyProvider;
/// Re-export of [`zeroize::Zeroizing`], a wrapper that overwrites its
/// contents when dropped.
///
/// Masked outputs (`mask!`, `mask_include_str!`, `mask_format!`, …)
/// decrypt to ordinary owned values (`String`, `Vec<u8>`) that are freed
/// **without** overwriting; their plaintext lingers in residual memory
/// until the allocator reuses the pages. Wrapping a masked output opts it
/// into overwrite-on-drop:
///
/// ```
/// let token = litmask::Zeroizing::new(litmask::mask!("super-secret"));
/// assert_eq!(token.as_str(), "super-secret"); // derefs to `str`
/// // `token`'s buffer is overwritten when it drops.
/// ```
///
/// This is **memory-remanence hygiene** — it shrinks the window in which
/// a dropped secret is recoverable from a core dump, swap file, or
/// hibernation image. It does **not** defend against a live debugger
/// reading the value before it drops, and it does not prevent
/// re-derivation. Any copy made by `.clone()`, `format!`, or printing
/// escapes the wrapper and is not overwritten.
pub use zeroize::Zeroizing;

#[cfg(feature = "std")]
pub use provider::{EnvVarProvider, FileProvider};

pub use litmask_macros::{
    MaskDebug, init, mask, mask_all, mask_concat, mask_env, mask_file, mask_format,
    mask_include_bytes, mask_include_str, mask_option_env, unmasked, unmasked_derive, weak_mask,
};

#[cfg(feature = "unstable-serde")]
pub use litmask_macros::{MaskDeserialize, MaskSerialize};

// The `MaskSerialize`/`MaskDeserialize` expansions reference serde's
// traits through `::litmask::__serde::...` so consumers don't need a
// direct serde dependency for the generated code to resolve.
#[cfg(feature = "unstable-serde")]
#[doc(hidden)]
pub use serde as __serde;

// The double-underscore module name marks it as macro-plumbing in
// consumer-facing paths; the source file keeps the conventional name.
#[cfg(feature = "unstable-serde")]
#[doc(hidden)]
#[path = "serde_support.rs"]
pub mod __serde_support;

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

#[doc(hidden)]
pub mod __internal {
    //! Symbols required by macro expansion. Not part of the stable API.
    pub use crate::runtime::weak::{__weak_decode, __weak_decode_bytes, WeakByteCell, WeakCell};
    #[cfg(feature = "std")]
    pub use crate::runtime::weak::{__weak_decode_cstr, WeakCStrCell};
    pub use crate::runtime::{__decrypt, __decrypt_string, __govern_external, __init_with_wrapper};
    #[cfg(feature = "machine-id")]
    pub use crate::runtime::{__govern_machine, __govern_machine_external};
    // Hygienic `String` alias for the `mask_format!` / `mask_option_env!`
    // expansions (`__String::new()` / `Option::<__String>::None`).
    //
    // The natural alternative — emitting `::alloc::string::String`
    // directly — does NOT work in std consumer crates: `alloc` is
    // not in the list of imported crates at a std crate's root
    // unless the user adds `extern crate alloc;` explicitly. Without
    // it, the emitted path fails with E0433. The re-export routes
    // through `::litmask::`, which the user is already importing,
    // so no extra declaration is required from the consumer side
    // for either std or no_std + alloc.
    //
    // `mask!("...")` deliberately does NOT use this alias: its
    // expansion goes through `__decrypt_string` so consumer-side
    // diagnostics never render the alias (see that fn's rustdoc).
    pub use alloc::string::String as __String;
}

/// Test/bench-only hooks for the process-global init state. Behind the
/// `test-util` feature, so this module does not exist in normal consumer
/// builds. Not part of the stable API.
#[cfg(feature = "test-util")]
#[doc(hidden)]
pub mod test_util {
    /// Drop the process-global mask-key cache so the next `mask!()`
    /// re-runs the full first-use unlock (provider derivation + wrapper
    /// AEAD-open + cache insert) through the real production path. The
    /// installed governor is left in place; only the per-wrapper key
    /// cache is cleared.
    ///
    /// Exists so benchmarks can re-measure the one-time unlock cost per
    /// sample and tests can isolate the global between cases. It exposes
    /// no key material — it clears a cache and returns nothing. The
    /// leaked `&'static` keys from prior unlocks are not reclaimed, so
    /// repeated calls leak one `MaskKey` each (bounded, test/bench-scope
    /// only).
    pub fn reset_mask_key_cache() {
        crate::runtime::reset_mask_key_cache();
    }
}

#[cfg(test)]
#[cfg(not(feature = "std"))]
mod no_std_tests {
    extern crate std;

    // No `init!`: the Embedded floor self-initializes on the first
    // `mask_format!` / `mask_write!` decrypt.

    #[test]
    fn mask_format_compiles_under_no_std() {
        let s = crate::mask_format!("no_std check: {}", 42);
        assert_eq!(s, "no_std check: 42");
    }

    #[test]
    fn mask_format_no_args_under_no_std() {
        let s = crate::mask_format!("plain literal");
        assert_eq!(s, "plain literal");
    }

    #[test]
    fn mask_write_compiles_under_no_std() {
        use core::fmt::Write as _;
        let mut buf = alloc::string::String::new();
        crate::mask_write!(buf, "write {}", 99).unwrap();
        assert_eq!(buf, "write 99");
    }
}
