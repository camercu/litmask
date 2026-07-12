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
//! litmask needs a one-line `build.rs` (it generates the per-build keys
//! every `mask!` reads), so add both crates and the build script before
//! the first call — see the [README quick
//! start](https://github.com/camercu/litmask#quick-start):
//!
//! ```sh
//! cargo add litmask
//! cargo add --build litmask-build
//! ```
//!
//! ```ignore
//! // build.rs
//! fn main() { litmask_build::emit(); }
//! ```
//!
//! ```no_run
//! // src/main.rs — the keyless Embedded tier self-initializes on the
//! // first `mask!()`.
//! println!("{}", litmask::mask!("sensitive data"));
//! ```
//!
//! For the project overview, the security-level ladder, the threat
//! scope, and how litmask compares to `obfstr` / `litcrypt`, see the
//! [project README](https://github.com/camercu/litmask#readme) and
//! [`docs/ARCHITECTURE.md`](https://github.com/camercu/litmask/blob/main/docs/ARCHITECTURE.md).
//! This module doc is the API reference.
//!
//! ## Choosing a macro
//!
//! The masking macros fall into three families (the sidebar lists every
//! one; the README has the [exhaustive
//! table](https://github.com/camercu/litmask#macros)):
//!
//! - **Real secrets** — [`mask!`] and its formatting / IO / inclusion
//!   variants ([`mask_format!`], [`mask_concat!`], [`mask_env!`],
//!   [`mask_include_str!`], `mask_write!`, `mask_println!`, …) decrypt
//!   through the AEAD pipeline and return owned values.
//! - **Bootstrap strings** — [`weak_mask!`] is the only macro usable
//!   *before* the runtime is unlocked (`strings(1)`-resistance only,
//!   returns `&'static`). Use it for the env-var names and paths a
//!   provider itself needs.
//! - **Zero-alloc** — `mask_stack!` (`unstable-stack` feature) decrypts
//!   into an inline, self-zeroizing buffer instead of the heap.
//!
//! Two derives round these out: [`MaskDebug`] masks `Debug`
//! type/field/variant names, and the `unstable-serde` feature adds masked serde
//! derives.
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
//! [ADR-0001](https://github.com/camercu/litmask/blob/main/docs/adr/0001-masking-crate-unlock-governance.md).
//!
//! ### Host setup for governed masking
//!
//! Install the CLI once (`cargo install litmask-cli` installs a `litmask`
//! binary), mint an unlock key with it, thread the key through the *build*
//! environment so every crate's `build.rs` seals against it, then install
//! it at startup with one governing [`init!`]:
//!
//! ```sh
//! key="$(litmask keygen)"
//! LITMASK_UNLOCK_KEY="$key" cargo build --release
//! ```
//!
//! ```ignore
//! // src/main.rs — sealed External tier (compile-checked against the seal).
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let provider = litmask::EnvVarProvider::new("LITMASK_UNLOCK_KEY");
//!     litmask::init!(provider)?; // one call unlocks the whole graph
//!     println!("{}", litmask::mask!("now backed by a runtime key"));
//!     Ok(())
//! }
//! ```
//!
//! `EnvVarProvider` re-sources the key at *run* time, so the same
//! `LITMASK_UNLOCK_KEY` must be in the binary's environment when it starts,
//! not only at build:
//!
//! ```sh
//! LITMASK_UNLOCK_KEY="$key" ./target/release/my_app
//! ```
//!
//! The Rust snippet is `ignore`d because `init!(provider)` only compiles
//! once the build environment has sealed a key-bearing tier; the
//! executable, test-exercised version lives in
//! [`examples/file_provider.rs`](https://github.com/camercu/litmask/blob/main/litmask/examples/file_provider.rs).
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
//! ### Stack-backed outputs (`unstable-stack` feature, experimental)
//!
//! **Experimental and semver-exempt** (`unstable-` prefix); may change or
//! vanish in any release.
//!
//! `mask_stack!` decrypts each literal into an inline `[u8; N]` (length
//! fixed at expansion) instead of a heap `String` / `Vec` / `CString`, and
//! the returned guard (`MaskStr` / `MaskBytes` / `MaskCStr`) zeroizes that
//! buffer on drop. Its distinguishing property is that the plaintext never
//! touches the heap — *not* a more thorough wipe: because a [`mask!`]
//! literal's length is known at compile time, its decrypt buffer is a
//! single exact-size allocation (no growth, no realloc), so
//! `Zeroizing<mask!("...")>` overwrites it just as completely. Reach for
//! `mask_stack!` when you want the secret kept off the heap entirely.
//!
//! ```no_run
//! # #[cfg(feature = "unstable-stack")] {
//! let pw = litmask::mask_stack!("hunter2"); // `MaskStr` guard, wiped on drop
//! assert_eq!(&*pw, "hunter2");              // derefs to `&str`
//! # }
//! ```
//!
//! The buffer lives on the stack, so [`mask!`] remains the right choice
//! for large literals; a literal whose buffer would exceed
//! `LITMASK_STACK_LIMIT` (default 4096 bytes) is a compile error. That
//! cap is a build-environment knob — raise it for a build with
//! `LITMASK_STACK_LIMIT=8192 cargo build`.
//! `MaskCStr` borrows `core::ffi::CStr` from its own buffer instead of
//! constructing a `CString`, so the C-string form needs no allocator *at
//! the call site* (unlike `mask!(c"...")`). The crate as a whole still
//! links `alloc` today, so this is not yet a fully heapless build. (All
//! gated behind the `unstable-stack` feature.)
//!
//! ## Feature flags
//!
//! The crate is `#![no_std]` + `alloc` from day one; the default `std`
//! feature gates only what genuinely requires `std`. `unstable-stack`,
//! `machine-id`, `unstable-serde`, and the cipher toggle
//! (`chacha20-poly1305` default vs `aes-gcm`) gate the rest. Each is
//! documented at its definition in
//! [`litmask/Cargo.toml`](https://github.com/camercu/litmask/blob/main/litmask/Cargo.toml);
//! the [README feature
//! table](https://github.com/camercu/litmask#features) is the canonical
//! list.

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
/// A custom [`KeyProvider`] constructs [`UnlockMaterial`] from its
/// sourced bytes before calling [`UnlockKey::derive`], so both the type
/// and its empty-rejection error ([`EmptyMaterial`]) are part of the
/// public surface — see the vault-style example on [`KeyProvider`].
pub use litmask_internal::{EmptyMaterial, UnlockMaterial};
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

// The macros' reference docs (prose, errors, panics) live on the
// definitions in `litmask-macros`; rustdoc merges them with the runnable
// `# Examples` below. The examples live here, not on the definitions,
// because doctests run in the crate that owns the item and this crate is
// the one with the `build.rs` artifacts a `mask!` expansion needs — the
// proc-macro crate has neither those nor a `litmask` dependency.

/// # Examples
///
/// ```
/// let s: String = litmask::mask!("secret");
/// assert_eq!(s, "secret");
/// let b: Vec<u8> = litmask::mask!(b"\x01\x02");
/// assert_eq!(b, vec![1, 2]);
/// ```
pub use litmask_macros::mask;

/// # Examples
///
/// ```
/// let who = "world";
/// assert_eq!(litmask::mask_format!("hi {who} {}", 1), "hi world 1");
/// ```
pub use litmask_macros::mask_format;

/// # Examples
///
/// ```
/// assert_eq!(litmask::mask_concat!("a", "b", "c"), "abc");
/// ```
pub use litmask_macros::mask_concat;

/// # Examples
///
/// ```
/// // resolved at build time, like stdlib `env!`:
/// let _pkg: String = litmask::mask_env!("CARGO_PKG_NAME");
/// ```
pub use litmask_macros::mask_env;

/// # Examples
///
/// ```
/// let v: Option<String> = litmask::mask_option_env!("DEFINITELY_UNSET_AT_BUILD");
/// assert!(v.is_none());
/// ```
pub use litmask_macros::mask_option_env;

/// # Examples
///
/// The path is resolved relative to the source file, so this cannot run as
/// a doctest:
///
/// ```ignore
/// let cfg: String = litmask::mask_include_str!("secret.txt");
/// ```
pub use litmask_macros::mask_include_str;

/// # Examples
///
/// ```ignore
/// let blob: Vec<u8> = litmask::mask_include_bytes!("key.bin");
/// ```
pub use litmask_macros::mask_include_bytes;

/// # Examples
///
/// ```
/// let here: String = litmask::mask_file!(); // masked equivalent of `file!()`
/// assert!(!here.is_empty());
/// ```
pub use litmask_macros::mask_file;

/// # Examples
///
/// ```
/// // the env-var NAME a provider reads during init! — metadata, not a secret:
/// let var: &'static str = litmask::weak_mask!("MY_APP_KEY");
/// assert_eq!(var, "MY_APP_KEY");
/// ```
pub use litmask_macros::weak_mask;

/// # Examples
///
/// ```
/// // identity outside `#[mask_all]`; an opt-out marker inside it:
/// let v: &'static str = litmask::unmasked!("v1");
/// assert_eq!(v, "v1");
/// ```
pub use litmask_macros::unmasked;

/// # Examples
///
/// ```
/// #[litmask::mask_all]
/// mod secrets {
///     pub fn banner() -> String {
///         format!("build {}", 1) // rewritten to mask_format!
///     }
/// }
/// assert_eq!(secrets::banner(), "build 1");
/// ```
pub use litmask_macros::mask_all;

/// # Examples
///
/// `#[mask_all]` would swap this type's `#[derive(Debug)]` for
/// [`MaskDebug`]; `#[unmasked_derive]` opts it back out to the plain
/// derive:
///
/// ```
/// #[litmask::mask_all]
/// mod m {
///     #[litmask::unmasked_derive]
///     #[derive(Debug)]
///     pub struct Marker;
/// }
/// assert_eq!(format!("{:?}", m::Marker), "Marker");
/// ```
pub use litmask_macros::unmasked_derive;

/// # Examples
///
/// The External form needs a key-bearing seal, so it cannot run at the
/// Embedded tier this crate's doctests build under:
///
/// ```ignore
/// let provider = litmask::EnvVarProvider::new("LITMASK_UNLOCK_KEY");
/// litmask::init!(provider)?; // host binary, External tier
/// ```
pub use litmask_macros::init;

/// Masks the type name **and** every field name (and, for enums, every
/// variant name) — the same three name kinds `#[derive(Debug)]` embeds
/// as cleartext. The `Creds` type name below is masked as well as the
/// `user` field; neither survives in `.rodata`.
///
/// # Examples
///
/// ```
/// #[derive(litmask::MaskDebug)]
/// struct Creds {          // `Creds` type name absent from .rodata
///     user: String,       // `user` field name absent from .rodata
/// }
/// // renders like `#[derive(Debug)]`, but the names are absent from .rodata:
/// assert_eq!(format!("{:?}", Creds { user: "bob".into() }), "Creds { user: \"bob\" }");
/// ```
pub use litmask_macros::MaskDebug;

/// Masks the type name **and** every field name (and, for enums, every
/// variant name) — the same names the plain `serde::Serialize` derive
/// passes to `serialize_struct` / `serialize_*_variant`. The `Config`
/// type name below is masked as well as the `host` / `port` fields;
/// none survive in `.rodata`.
///
/// # Examples
///
/// ```
/// #[derive(litmask::MaskSerialize)]
/// struct Config {         // `Config` type name absent from .rodata
///     host: String,       // `host` / `port` field names absent from .rodata
///     port: u16,
/// }
/// // wire output is byte-identical to `#[derive(Serialize)]`; names masked:
/// let json = serde_json::to_string(&Config { host: "h".into(), port: 80 }).unwrap();
/// assert_eq!(json, r#"{"host":"h","port":80}"#);
/// ```
#[cfg(feature = "unstable-serde")]
pub use litmask_macros::MaskSerialize;

/// Masks the type name **and** every field name (and, for enums, every
/// variant name) — the names the plain `serde::Deserialize` derive
/// embeds in its `FIELDS` arrays, field-matching arms, `expecting()`
/// text (`"struct Config"`), and `missing field` diagnostics. The
/// `Config` type name below is masked as well as the `host` / `port`
/// fields; none survive in `.rodata`.
///
/// # Examples
///
/// ```
/// #[derive(litmask::MaskDeserialize)]
/// struct Config {         // `Config` type name absent from .rodata
///     host: String,       // `host` / `port` field names absent from .rodata
///     port: u16,
/// }
/// // accepts the same input as `#[derive(Deserialize)]`; names masked:
/// let cfg: Config = serde_json::from_str(r#"{"host":"h","port":80}"#).unwrap();
/// assert_eq!((cfg.host.as_str(), cfg.port), ("h", 80));
/// ```
#[cfg(feature = "unstable-serde")]
pub use litmask_macros::MaskDeserialize;

/// Stack-backed, zero-alloc masking — see [`macro@mask_stack`],
/// [`MaskStr`], [`MaskBytes`], and [`MaskCStr`]. Gated behind the
/// `unstable-stack` feature.
///
/// # Examples
///
/// ```
/// let pw = litmask::mask_stack!("hunter2"); // `MaskStr<N>`, wiped on drop
/// assert_eq!(&*pw, "hunter2"); // derefs to `str`
/// ```
#[cfg(feature = "unstable-stack")]
pub use litmask_macros::mask_stack;
#[cfg(feature = "unstable-stack")]
pub use runtime::stack::{MaskBytes, MaskCStr, MaskStr};

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
///
/// # Examples
///
/// ```
/// use core::fmt::Write as _;
/// let mut buf = String::new();
/// litmask::mask_write!(&mut buf, "x = {}", 42).unwrap();
/// assert_eq!(buf, "x = 42");
/// ```
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
///
/// # Examples
///
/// ```
/// use core::fmt::Write as _;
/// let mut buf = String::new();
/// litmask::mask_writeln!(&mut buf, "line {}", 1).unwrap();
/// assert_eq!(buf, "line 1\n");
/// ```
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
///
/// # Examples
///
/// ```
/// litmask::mask_print!("loaded {} entries\n", 3);
/// ```
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
///
/// # Examples
///
/// ```
/// let user = "alice";
/// litmask::mask_println!("welcome, {user}");
/// ```
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

/// Print a `mask_format!`-encrypted format string to stderr.
///
/// Thin wrapper: `mask_eprint!("fmt", args)` expands to
/// `eprint!("{}", mask_format!("fmt", args))`.
///
/// **Security note:** the decrypted text is printed in the clear to
/// stderr. litmask protects literals at rest in the binary; once
/// printed, the output is unprotected.
///
/// # Examples
///
/// ```
/// litmask::mask_eprint!("error code {}\n", 7);
/// ```
#[cfg(feature = "std")]
#[macro_export]
macro_rules! mask_eprint {
    ($($args:tt)*) => {
        ::std::eprint!("{}", $crate::mask_format!($($args)*))
    };
}

/// Print a `mask_format!`-encrypted format string plus newline to
/// stderr.
///
/// Thin wrapper: `mask_eprintln!("fmt", args)` expands to
/// `eprintln!("{}", mask_format!("fmt", args))`. The no-argument form
/// `mask_eprintln!()` prints a bare newline (no masking needed).
///
/// **Security note:** the decrypted text is printed in the clear to
/// stderr. litmask protects literals at rest in the binary; once
/// printed, the output is unprotected.
///
/// # Examples
///
/// ```
/// let user = "alice";
/// litmask::mask_eprintln!("login failed for {user}");
/// ```
#[cfg(feature = "std")]
#[macro_export]
macro_rules! mask_eprintln {
    () => {
        ::std::eprintln!()
    };
    ($($args:tt)*) => {
        ::std::eprintln!("{}", $crate::mask_format!($($args)*))
    };
}

/// Panic with a `mask_format!`-encrypted message.
///
/// Thin wrapper: `mask_panic!("fmt", args)` expands to
/// `panic!("{}", mask_format!("fmt", args))`. The no-argument form
/// `mask_panic!()` forwards to `panic!()` (the default "explicit
/// panic" message, nothing to mask).
///
/// Mirrors what `#[mask_all]` does to a bare `panic!` inside its
/// scope; this is the standalone form for code outside a masked
/// module.
///
/// **Security note:** the decrypted message is emitted in the clear to
/// the panic handler (typically stderr) and may be captured by a panic
/// hook. litmask protects the literal at rest in the binary; once the
/// panic fires, the message is unprotected.
///
/// Available in `no_std` + `alloc` builds.
///
/// # Examples
///
/// ```should_panic
/// litmask::mask_panic!("invariant {} violated", "X");
/// ```
#[macro_export]
macro_rules! mask_panic {
    () => {
        ::core::panic!()
    };
    ($($args:tt)+) => {
        ::core::panic!("{}", $crate::mask_format!($($args)+))
    };
}

/// `todo!` with a `mask_format!`-encrypted message.
///
/// Thin wrapper: `mask_todo!("fmt", args)` expands to
/// `todo!("{}", mask_format!("fmt", args))`. The stdlib "not yet
/// implemented" prefix stays in cleartext (ubiquitous boilerplate, not
/// a user secret); only the supplied message is masked. The
/// no-argument form `mask_todo!()` forwards to `todo!()`.
///
/// **Security note:** see [`mask_panic!`] — the decrypted message is
/// emitted in the clear when the panic fires.
///
/// Available in `no_std` + `alloc` builds.
///
/// # Examples
///
/// ```should_panic
/// litmask::mask_todo!("wire up {}", "the backend");
/// ```
#[macro_export]
macro_rules! mask_todo {
    () => {
        ::core::todo!()
    };
    ($($args:tt)+) => {
        ::core::todo!("{}", $crate::mask_format!($($args)+))
    };
}

/// `unimplemented!` with a `mask_format!`-encrypted message.
///
/// Thin wrapper: `mask_unimplemented!("fmt", args)` expands to
/// `unimplemented!("{}", mask_format!("fmt", args))`. The stdlib "not
/// implemented" prefix stays in cleartext; only the supplied message
/// is masked. The no-argument form `mask_unimplemented!()` forwards to
/// `unimplemented!()`.
///
/// **Security note:** see [`mask_panic!`] — the decrypted message is
/// emitted in the clear when the panic fires.
///
/// Available in `no_std` + `alloc` builds.
///
/// # Examples
///
/// ```should_panic
/// litmask::mask_unimplemented!("variant {} not handled", 3);
/// ```
#[macro_export]
macro_rules! mask_unimplemented {
    () => {
        ::core::unimplemented!()
    };
    ($($args:tt)+) => {
        ::core::unimplemented!("{}", $crate::mask_format!($($args)+))
    };
}

/// `unreachable!` with a `mask_format!`-encrypted message.
///
/// Thin wrapper: `mask_unreachable!("fmt", args)` expands to
/// `unreachable!("{}", mask_format!("fmt", args))`. The stdlib
/// "internal error: entered unreachable code" prefix stays in
/// cleartext; only the supplied message is masked. The no-argument
/// form `mask_unreachable!()` forwards to `unreachable!()`.
///
/// **Security note:** see [`mask_panic!`] — the decrypted message is
/// emitted in the clear when the panic fires.
///
/// Available in `no_std` + `alloc` builds.
///
/// # Examples
///
/// ```should_panic
/// let state = "corrupt";
/// litmask::mask_unreachable!("parser reached {state} state");
/// ```
#[macro_export]
macro_rules! mask_unreachable {
    () => {
        ::core::unreachable!()
    };
    ($($args:tt)+) => {
        ::core::unreachable!("{}", $crate::mask_format!($($args)+))
    };
}

#[doc(hidden)]
pub mod __internal {
    //! Symbols required by macro expansion. Not part of the stable API.
    #[cfg(feature = "unstable-stack")]
    pub use crate::runtime::stack::{
        __decrypt_stack_bytes, __decrypt_stack_cstr, __decrypt_stack_str,
    };
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

    // Locks the "Available in `no_std` + `alloc` builds" claim on the
    // panic family's rustdoc: these expand through `::core::` and must
    // carry the masked message without pulling in `std`.
    fn panic_message(f: impl FnOnce() + std::panic::UnwindSafe) -> alloc::string::String {
        use alloc::string::{String, ToString as _};
        let prev = std::panic::take_hook();
        std::panic::set_hook(std::boxed::Box::new(|_| {}));
        let payload = std::panic::catch_unwind(f).err().unwrap();
        std::panic::set_hook(prev);
        if let Some(s) = payload.downcast_ref::<String>() {
            s.clone()
        } else if let Some(s) = payload.downcast_ref::<&str>() {
            s.to_string()
        } else {
            unreachable!()
        }
    }

    // Cover every member of the family: the stdlib panic macros all live
    // in `core`, so each masked wrapper must work under `no_std` too.

    #[test]
    fn mask_panic_under_no_std() {
        let msg = panic_message(|| crate::mask_panic!("invariant {} broke", 7));
        assert_eq!(msg, "invariant 7 broke");
    }

    #[test]
    fn mask_todo_under_no_std() {
        let msg = panic_message(|| crate::mask_todo!("wire {}", "backend"));
        assert_eq!(msg, "not yet implemented: wire backend");
    }

    #[test]
    fn mask_unimplemented_under_no_std() {
        let msg = panic_message(|| crate::mask_unimplemented!("variant {}", 3));
        assert_eq!(msg, "not implemented: variant 3");
    }

    #[test]
    fn mask_unreachable_under_no_std() {
        let msg = panic_message(|| crate::mask_unreachable!("state {}", 3));
        assert_eq!(msg, "internal error: entered unreachable code: state 3");
    }
}
