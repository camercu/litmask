//! Internal proc-macro crate for `litmask`.
//!
//! Users add `litmask` as a dependency, never this crate directly. The
//! public `litmask` crate re-exports the macros here.
//!
//! `#[proc_macro]` attributes are required by rustc to live in the
//! crate root, so this file only carries the entry points. The input
//! grammar and expansion logic for each macro lives in its own
//! submodule:
//!
//! - [`mask!`] — AEAD-encrypt a literal at compile time.
//! - [`unmasked!`] — identity wrapper marking an opt-out literal.
//! - [`maskfmt!`] — masked format-string template.
//! - [`weak_mask!`] — XOR-against-wrapper anti-`strings(1)` obfuscation.
//! - [`macro@mask_all`] — module-level attribute that rewrites every
//!   masking-eligible literal in the attributed module.

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
/// literal and expands to that literal unchanged. Used as an explicit
/// opt-out marker: a literal wrapped in `unmasked!` is left alone by
/// [`macro@mask_all`] (which would otherwise rewrite it).
///
/// Zero runtime overhead: the expansion is the bare literal token,
/// so the result is `&'static str` / `&'static [u8; N]` /
/// `&'static CStr` exactly as if the wrapper macro were absent.
#[proc_macro]
pub fn unmasked(input: TokenStream) -> TokenStream {
    unmasked::expand(input)
}

/// Build a runtime `String` by masking each literal fragment of the
/// template via [`mask!`] and splicing in the formatted arguments at
/// runtime. The template is parsed at proc-macro time; only the
/// per-placeholder format specs (e.g. `{:.2}`, `{:?}`) appear in the
/// compiled binary — the template text never does.
///
/// Supports positional placeholders (`{}`, `{N}`), named arguments
/// (`maskfmt!("{x}", x = e)`), implicit captures (`{var}` where
/// `var` is a local in scope), and dynamic width/precision
/// (`{:>w$}`, `{:.p$}`). Placeholder names are rewritten to
/// positional references at proc-macro time so the names never
/// survive into the compiled output.
///
/// # Compile errors
///
/// - Non-literal template — `maskfmt!` cannot mask a runtime-built
///   format string; use [`mask!`] for that case.
/// - Positional argument with no matching placeholder, or
///   placeholder index out of range — mirrors `format!`'s
///   compile-time checks.
/// - Duplicate named argument.
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

/// Module-level attribute that recursively rewrites every
/// masking-eligible literal in the attributed module. Each direct
/// string-shaped literal becomes a [`mask!`] call, and common
/// formatting / output / panic / assert macros are rewritten to use
/// [`maskfmt!`] for their templates.
///
/// Recognized macro families:
///
/// - `format!(lit, ...)` → `maskfmt!(lit, ...)`
/// - `println!` / `eprintln!` / `print!` / `eprint!` with a literal
///   template are wrapped so the masked formatted result is written
///   through the original macro.
/// - `write!` / `writeln!` are wrapped analogously, with the writer
///   left as the first argument.
/// - `panic!` / `todo!` / `unimplemented!` / `unreachable!` with a
///   literal message are wrapped so the panic still fires with the
///   same message text at runtime.
/// - `assert!` / `assert_eq!` / `assert_ne!` with a custom-message
///   argument: the message is masked while the assertion still
///   fires. The `debug_assert!` family is **not** masked — its
///   body is dead-code-eliminated in release builds via
///   `cfg!(debug_assertions)`, so masking would only add a
///   `.rodata` blob and a runtime decrypt that's never observed in
///   shipping binaries.
/// - `include_str!(...)` and `concat!(...)` are wrapped in `mask!()`
///   so their compile-time-resolved strings are masked.
/// - `dbg!`, `stringify!`, `compile_error!`, `cfg!`, `file!`,
///   `line!`, `column!`, `module_path!`, the no-message forms of
///   `assert!` / `assert_eq!` / `assert_ne!`, and **all** forms of
///   the `debug_assert!` family are recognized as diagnostic-only
///   and skipped silently — their literals either serve compile-
///   time / developer-facing purposes that never reach shipping
///   binaries, or are dead-code-eliminated in release builds.
/// - Qualified macro paths (`std::format!`, `core::dbg!`, etc.) are
///   recognized by matching the last path segment.
///
/// Literals are left untouched (with a per-occurrence warning) when:
///
/// - The literal appears in a pattern position (`match`, `if let`,
///   `while let`) — patterns cannot accept macro invocations.
/// - The literal initializes a `const` or `static` — `mask!()`
///   returns a runtime value and cannot be evaluated at compile
///   time.
/// - The literal is an argument to `mask!` / `maskfmt!` /
///   `unmasked!` / `weak_mask!` — the user has already chosen
///   explicitly.
/// - The literal is an argument to a recognized diagnostic-only
///   macro (`dbg!`, `stringify!`, `compile_error!`, `cfg!`, `file!`,
///   `line!`, `column!`, `module_path!`, or any of the assert family
///   in no-message form) — these serve compile-time or developer
///   purposes and never embed the literal as user-facing data.
/// - The literal is an argument to a user-defined or otherwise
///   unrecognized macro — the walker cannot rewrite literals inside
///   arbitrary macro bodies safely.
/// - The template argument of `format!` / `println!` / `panic!`
///   etc. is not itself a string literal — runtime template
///   assembly leaves the formatted output unreachable to
///   `mask_all!`.
///
/// Warnings are emitted as `deprecated` lints so they surface in
/// `cargo build` output without changing build success on stable
/// `#[mask_all]`. Each warning's note includes a tag identifying
/// the skip kind (`pattern_position`, `const_initializer`,
/// `static_initializer`, `non_literal_template`,
/// `unrecognized_macro`) so the user can grep for them.
///
/// # Panics
///
/// Panics during macro expansion if applied to anything other than a
/// module item — `syn` reports the parse error at the attribute's
/// call site.
#[proc_macro_attribute]
pub fn mask_all(attr: TokenStream, item: TokenStream) -> TokenStream {
    mask_all::expand(attr, item)
}
