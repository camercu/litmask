//! Internal proc-macro crate for `litmask`.
//!
//! Users add `litmask` as a dependency, never this crate directly. The
//! public `litmask` crate re-exports the macros here.
//!
//! `#[proc_macro]` attributes are required by rustc to live in the
//! crate root, so this file only carries the four entry points. The
//! input grammar and expansion logic for each macro lives in its own
//! submodule:
//!
//! - [`mask!`] — AEAD-encrypt a literal at compile time.
//! - [`unmasked!`] — identity wrapper marking an opt-out literal.
//! - [`maskfmt!`] — masked format-string template.
//! - [`weak_mask!`] — XOR-against-wrapper anti-`strings(1)` obfuscation.

use proc_macro::TokenStream;

mod common;
mod mask;
mod mask_all;
mod maskfmt;
mod unmasked;
mod weak_mask;

/// Mask a string literal, byte string literal, or C string literal at
/// compile time. The expansion is a runtime decryption call whose
/// return type depends on the literal kind:
///
/// - `mask!("...")` returns `String`.
/// - `mask!(b"...")` returns `Vec<u8>`.
/// - `mask!(c"...")` returns `CString`. Requires the `litmask` crate's
///   `std` feature — `CString` is std-only.
///
/// `mask!` additionally accepts two built-in macro invocations as
/// inputs, resolved at proc-macro time:
///
/// - `mask!(include_str!("path"))` reads the file at proc-macro time
///   and masks its contents. Paths are resolved relative to
///   `CARGO_MANIFEST_DIR`. Edits to the file do not currently trigger
///   automatic rebuilds; touch a source file or `cargo clean` to pick
///   them up.
/// - `mask!(concat!(args...))` flattens each argument at proc-macro
///   time. All arguments must be string literals; mixed literal kinds
///   are rejected at compile time.
///
/// # Panics
///
/// Panics during macro expansion (not at the user's runtime) if:
///
/// - `OUT_DIR` is unset (the caller's crate is missing a `build.rs`
///   that invokes `litmask_build::emit()`).
/// - `litmask_key.bin` or `litmask_seed.bin` cannot be read from
///   `OUT_DIR`, or have the wrong length.
/// - ChaCha20-Poly1305 encryption fails for the literal value
///   (cryptographically extraordinary; never observed in practice).
#[proc_macro]
pub fn mask(input: TokenStream) -> TokenStream {
    mask::expand(input)
}

/// Identity macro that accepts one string, byte string, or C string
/// literal and expands to that literal unchanged. Exists so
/// `#[mask_all]` (Task 12) and `#[mask_all(strict)]` (Task 14) can
/// recognize it as an explicit opt-out marker — a literal wrapped
/// in `unmasked!` is left alone by the deep-rewriting attribute.
///
/// Zero runtime overhead: the expansion is the bare literal token,
/// so the result is `&'static str` / `&'static [u8; N]` /
/// `&'static CStr` exactly as if the wrapper macro were absent.
#[proc_macro]
pub fn unmasked(input: TokenStream) -> TokenStream {
    unmasked::expand(input)
}

/// Build a runtime `String` by masking each literal fragment of the
/// template via [`mask!`] and splicing in the formatted positional
/// arguments. The template is parsed at proc-macro time; only the
/// per-placeholder format specs (e.g. `{:.2}`, `{:?}`) appear in the
/// compiled binary — the template text never does.
///
/// Task 10 supports positional placeholders only. Named arguments
/// (`{name}`) and implicit captures (`{var}`) land in Task 11; the
/// parser rejects them with a typed error today.
///
/// # Compile errors
///
/// - Non-literal template → §1.9.6 substring "maskfmt! requires a
///   string literal template at the call site".
/// - Named / implicit-capture placeholder → deferred-feature error.
/// - Positional index out of range → typed error.
///
/// # Panics
///
/// Inherits [`mask!`]'s expansion-time panic policy (missing
/// `OUT_DIR`, unreadable build artifact, AEAD failure).
#[proc_macro]
pub fn maskfmt(input: TokenStream) -> TokenStream {
    maskfmt::expand(input)
}

/// Obfuscate a string literal at compile time using XOR against the
/// per-build encrypted-`mask_key` wrapper bytes. Expand to code that
/// decodes back to `&'static str` on first runtime access and caches
/// the result for the program's lifetime.
///
/// `weak_mask!()` is weaker than [`mask!`]: there is no AEAD
/// authentication, and both ciphertext and key material live in the
/// same compiled binary, so a Level-2 attacker (disassembler + manual
/// decode) can recover the plaintext. Use `weak_mask!()` only for
/// non-secret strings that need anti-`strings(1)` protection and
/// cannot wait for `init!()` to run (env-var names, default file
/// paths, etc.). Real secrets always go through [`mask!`].
///
/// # Panics
///
/// Panics at proc-macro expansion time if `OUT_DIR` is unset or
/// `litmask_wrapper.bin` cannot be read; these indicate a missing
/// `build.rs` invoking `litmask_build::emit()`.
#[proc_macro]
pub fn weak_mask(input: TokenStream) -> TokenStream {
    weak_mask::expand(input)
}

/// Apply `mask!` recursively to every bare string-shaped literal
/// expression inside the attributed module. Walks nested modules,
/// functions, blocks, and closures (§2.3.1.5). Skips literals inside
/// `mask!` / `maskfmt!` / `unmasked!` / `weak_mask!` invocations
/// (already explicit) and inside `dbg!` / `stringify!` / `assert_eq!`
/// / `assert_ne!` per §2.3.2.6.
///
/// Task 12 covers bare-literal rewriting + the skip-macro list.
/// Pattern-position / `const` + `static` initializer skips + the
/// ghost-deprecation warning emission land in follow-up commits.
/// The full `format!`/`println!`/`panic!`/`include_str!`/`concat!`/
/// user-macro substitution table is Task 13; `#[mask_all(strict)]`
/// is Task 14.
///
/// # Panics
///
/// Panics during macro expansion if applied to anything other than a
/// module item (`#[mask_all] mod ...`) — `syn` reports the parse
/// error at the attribute's call site.
#[proc_macro_attribute]
pub fn mask_all(attr: TokenStream, item: TokenStream) -> TokenStream {
    mask_all::expand(attr, item)
}
