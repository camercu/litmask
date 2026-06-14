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
//! ## Security levels
//!
//! | Configuration | Defeats |
//! |---|---|
//! | Zero-config build (keyless Embedded tier) | `strings`, casual binary inspection (Level 1) only — the key is recoverable from the artifact |
//! | `EnvVarProvider` | Above, key sourced from an env var, kept out of the binary |
//! | `FileProvider` | Above, key sourced from a file path |
//! | `init!(bind_to_machine)` (build-sealed) | Above + binary moved to a different machine |
//! | `init!(bind_to_machine + provider)` (two-factor) | Above + the external factor the binary alone never carries |
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
//! | Machine-ID binding | None | None | Yes (build-time seal via `init!(bind_to_machine)`) |
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
mod provider;
mod runtime;

pub(crate) use litmask_internal as internal;

pub use error::{InitError, KeyError};
pub use key::UnlockKey;
pub use litmask_internal::KEY_LEN;
pub(crate) use provider::EmbeddedProvider;
pub use provider::KeyProvider;

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

/// Internal helper: expand to `include_bytes!(...)` for the embedded
/// encrypted-`mask_key` wrapper at the caller's `OUT_DIR`. Shared by
/// [`init!`] and the `mask!` proc-macro to avoid duplicating the path
/// literal at both call sites.
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

/// Internal helper: expand to the build-sealed tier tag string
/// (`LITMASK_SEAL_TIER`, set by `litmask_build::emit`). Read at the
/// consumer's compile time — the same `cargo:rustc-env` the `init!`
/// proc-macro cross-checks against — and passed into [`__internal::__decrypt`]
/// so the lazy first-`mask!()` path can refuse to derive the Embedded
/// key on a higher-tier seal (an init-ordering bug) instead of failing
/// the wrapper AEAD check with a misleading decryption error.
#[doc(hidden)]
#[macro_export]
macro_rules! __seal_tier {
    () => {
        ::core::env!("LITMASK_SEAL_TIER")
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
        ::std::ffi::CString::new($crate::__internal::__decrypt(
            $blob,
            $wrapper,
            $crate::__seal_tier!(),
        ))
        .unwrap()
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

/// Internal dispatch for `weak_mask!(c"...")` expansion. Under `std`,
/// allocates a per-call-site `WeakCStrCell` cache and decodes via
/// `__weak_decode_cstr`. Under `no_std`, emits a `compile_error!`.
#[cfg(feature = "std")]
#[doc(hidden)]
#[macro_export]
macro_rules! __weak_decode_cstr_call {
    ($obf:expr, $wrapper:expr) => {{
        static __WEAK_CACHE: $crate::__internal::WeakCStrCell =
            $crate::__internal::WeakCStrCell::new();
        $crate::__internal::__weak_decode_cstr($obf, $wrapper, &__WEAK_CACHE)
    }};
}

#[cfg(not(feature = "std"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __weak_decode_cstr_call {
    ($obf:expr, $wrapper:expr) => {
        ::core::compile_error!(
            "weak_mask!(c\"...\") requires the `std` feature on the `litmask` crate; \
             enable it via `litmask = { features = [\"std\"] }`"
        )
    };
}

/// Internal dispatch for `init!(bind_to_machine)` expansion. The seal tier is
/// chosen at build time by `LITMASK_MACHINE_ID` presence, independent of
/// this crate's `machine-id` feature, so a `machine`-sealed build can pass
/// `init!`'s form↔tier cross-check while the feature is off. Without this
/// guard the expansion would reference the feature-gated
/// `__govern_machine` and fail with an opaque "cannot find function";
/// here the missing feature surfaces a directed message instead.
#[cfg(feature = "machine-id")]
#[doc(hidden)]
#[macro_export]
macro_rules! __govern_machine_call {
    ($wrapper:expr) => {
        $crate::__internal::__govern_machine($wrapper)
    };
}

#[cfg(not(feature = "machine-id"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __govern_machine_call {
    ($wrapper:expr) => {
        ::core::compile_error!(
            "init!(bind_to_machine) requires the `machine-id` feature on the `litmask` crate; \
             enable it via `litmask = { features = [\"machine-id\"] }`"
        )
    };
}

/// Internal dispatch for `init!(bind_to_machine + <provider>)` expansion. Like
/// [`__govern_machine_call!`], the two-factor seal tier is chosen at
/// build time by env-var presence, independent of this crate's
/// `machine-id` feature, so the form↔tier cross-check can pass while the
/// feature is off. This guard turns that case into a directed message
/// instead of an opaque "cannot find function" against the feature-gated
/// `__govern_machine_external`.
#[cfg(feature = "machine-id")]
#[doc(hidden)]
#[macro_export]
macro_rules! __govern_machine_external_call {
    ($wrapper:expr, $external:expr) => {
        $crate::__internal::__govern_machine_external($wrapper, $external)
    };
}

#[cfg(not(feature = "machine-id"))]
#[doc(hidden)]
#[macro_export]
macro_rules! __govern_machine_external_call {
    ($wrapper:expr, $external:expr) => {
        ::core::compile_error!(
            "init!(bind_to_machine + provider) requires the `machine-id` feature on the `litmask` \
             crate; enable it via `litmask = { features = [\"machine-id\"] }`"
        )
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
