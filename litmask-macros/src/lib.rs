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
//! - [`mask_format!`] — masked format-string template.
//! - [`weak_mask!`] — XOR-against-wrapper anti-`strings(1)` obfuscation.
//! - [`macro@mask_all`] — module-level attribute that rewrites every
//!   masking-eligible literal in the attributed module.

use proc_macro::TokenStream;

mod common;
mod mask;
mod mask_all;
mod mask_concat;
mod mask_env;
mod mask_file;
mod mask_format;
mod mask_include_bytes;
mod mask_include_str;
mod mask_option_env;
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
/// `mask!` accepts ONLY the three literal kinds above. For file
/// inclusion, concatenation, environment variables, or the source
/// path, use the dedicated companions: [`macro@mask_include_str`],
/// [`macro@mask_include_bytes`], [`macro@mask_concat`],
/// [`macro@mask_env`], [`macro@mask_option_env`], [`macro@mask_file`].
///
/// # Errors
///
/// - Non-literal input (including macro invocations such as
///   `include_str!`, `concat!`, `env!`, or user-defined macros):
///   `mask! accepts string, byte string, or C string literals`.
/// - Use in `const` / `static` initializers: rustc's natural `E0015`
///   (`mask!()` returns a runtime value).
/// - Use in pattern positions (`match` arm, `if let`, `while let`):
///   rustc's natural "expected pattern" diagnostic.
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

/// Mask the UTF-8 contents of a file at compile time. The file is
/// read by the proc-macro relative to the consumer crate's
/// `CARGO_MANIFEST_DIR`; its bytes are AEAD-encrypted into a blob
/// embedded in the binary, and the macro expands to a runtime
/// decrypt call returning `String`. The plaintext never appears in
/// the compiled binary's `.rodata`.
///
/// # Rebuild on file change
///
/// Cargo does NOT automatically rebuild when the included file
/// changes on disk — proc-macros read files via `std::fs` outside
/// of rustc's normal dependency-tracking. Workarounds:
///
/// - `cargo clean` (heavy).
/// - Touch any source file in the consumer crate to invalidate the
///   incremental cache.
/// - Have the consumer crate's `build.rs` print
///   `cargo:rerun-if-changed=PATH` for the included file.
///
/// Stdlib `include_str!` is rebuild-tracked by the compiler because
/// it's a compiler builtin; `proc_macro::tracked_path::path` is the
/// stable-future equivalent but remains nightly-only.
///
/// # Errors
///
/// - Non-string-literal argument: `mask_include_str! requires a
///   string literal path`.
/// - File read failure (missing, unreadable, etc.):
///   `mask_include_str!: could not read PATH: REASON`.
///
/// # Panics
///
/// Same proc-macro-time panic conditions as [`mask!`] for missing
/// `OUT_DIR`, key/seed files, etc.
#[proc_macro]
pub fn mask_include_str(input: TokenStream) -> TokenStream {
    mask_include_str::expand(input)
}

/// Mask the raw bytes of a file at compile time. The file is read
/// by the proc-macro relative to the consumer crate's
/// `CARGO_MANIFEST_DIR`; its bytes are AEAD-encrypted and the macro
/// expands to a runtime decrypt call returning `Vec<u8>`. The
/// plaintext bytes never appear in the compiled binary's
/// `.rodata`.
///
/// # Rebuild on file change
///
/// Same caveat as [`macro@mask_include_str`]: cargo does not auto-
/// rebuild when the included file changes. See that macro's
/// rustdoc for the workaround options.
///
/// # Errors
///
/// - Non-string-literal argument: `mask_include_bytes! requires a
///   string literal path`.
/// - File read failure: `mask_include_bytes!: could not read PATH:
///   REASON`.
#[proc_macro]
pub fn mask_include_bytes(input: TokenStream) -> TokenStream {
    mask_include_bytes::expand(input)
}

/// Concatenate string literals and the compile-time-resolvable
/// macros `concat!` / `include_str!` / `env!` at proc-macro time,
/// then AEAD-encrypt the concatenated string and expand to a
/// runtime decrypt call returning `String`.
///
/// Replaces the prior `mask!(concat!(...))` shim with a direct
/// grammar that `#[mask_all]` can address by name.
///
/// # Errors
///
/// - Empty argument list: `mask_concat! requires at least one
///   argument`.
/// - Argument that is not a string literal / `concat!` /
///   `include_str!` / `env!`: `mask_concat! arguments must be
///   string literals or compile-time-resolvable string macros`.
/// - Nested `include_str!` file-read failure or nested `env!` of
///   an unset variable: propagated as a compile error with the
///   underlying cause.
#[proc_macro]
pub fn mask_concat(input: TokenStream) -> TokenStream {
    mask_concat::expand(input)
}

/// Mask a build-time environment-variable value at compile time.
/// Mirrors stdlib `env!`'s must-succeed contract: an unset variable
/// is a compile error.
///
/// # Errors
///
/// - Non-string-literal argument: `mask_env! requires a string
///   literal name`.
/// - Env var unset: `mask_env!: environment variable NAME is not
///   set`.
#[proc_macro]
pub fn mask_env(input: TokenStream) -> TokenStream {
    mask_env::expand(input)
}

/// Mask a build-time environment-variable value at compile time,
/// returning `Some(String)` when set and `None::<String>` when
/// unset. Mirrors stdlib `option_env!`'s contract — the unset case
/// is a legitimate runtime `None`, not a compile error.
///
/// # Errors
///
/// - Non-string-literal argument: `mask_option_env! requires a
///   string literal name`.
#[proc_macro]
pub fn mask_option_env(input: TokenStream) -> TokenStream {
    mask_option_env::expand(input)
}

/// Mask the call site's source-file path at compile time. The
/// proc-macro reads `proc_macro::Span::call_site().file()`,
/// canonicalizes it relative to the consumer crate's
/// `CARGO_MANIFEST_DIR` for reproducibility across checkouts at
/// different absolute filesystem locations, AEAD-encrypts the
/// result, and expands to a runtime decrypt call returning
/// `String`.
///
/// The raw source path never appears in the compiled binary's
/// `.rodata`. Note: `core::panic::Location::caller()` independently
/// embeds source paths at every panic site (`.unwrap()`,
/// `.expect("...")`, etc.); `mask_file!` masks only its own
/// explicit invocations, not the implicit panic-site embedding.
///
/// # Errors
///
/// - Non-empty argument list: `mask_file! takes no arguments`.
#[proc_macro]
pub fn mask_file(input: TokenStream) -> TokenStream {
    mask_file::expand(input)
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
/// (`mask_format!("{x}", x = e)`), implicit captures (`{var}` where
/// `var` is a local in scope), and dynamic width/precision
/// (`{:>w$}`, `{:.p$}`). Placeholder names are rewritten to
/// positional references at proc-macro time so the names never
/// survive into the compiled output.
///
/// # Compile errors
///
/// - Non-literal template — `mask_format!` cannot mask a runtime-built
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
pub fn mask_format(input: TokenStream) -> TokenStream {
    mask_format::expand(input)
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
/// [`mask_format!`] for their templates.
///
/// Recognized macro families:
///
/// - `format!(lit, ...)` → `mask_format!(lit, ...)`
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
/// - The following stdlib macros are rewritten to their dedicated
///   masking counterparts (the macro path is swapped; arguments
///   flow through unchanged):
///
///   | Original | Rewritten to |
///   |---|---|
///   | `include_str!` | [`macro@mask_include_str`] |
///   | `include_bytes!` | [`macro@mask_include_bytes`] |
///   | `concat!` | [`macro@mask_concat`] |
///   | `env!` | [`macro@mask_env`] |
///   | `option_env!` | [`macro@mask_option_env`] |
///   | `file!()` | [`macro@mask_file`] |
///
/// - `dbg!`, `stringify!`, `compile_error!`, `cfg!`, `line!`,
///   `column!`, `module_path!`, the no-message forms of `assert!` /
///   `assert_eq!` / `assert_ne!`, and **all** forms of the
///   `debug_assert!` family are recognized as diagnostic-only and
///   skipped silently — their literals either serve compile-time /
///   developer-facing purposes that never reach shipping binaries,
///   or are dead-code-eliminated in release builds.
///
/// # Return-type side effects
///
/// The macro rewrites above SHIFT return types compared to the
/// stdlib originals, because masked values are runtime-decrypted
/// and therefore must be owned rather than `&'static`:
///
/// | Original return type | Rewritten return type |
/// |---|---|
/// | `&'static str` (`file!`, `env!`, `include_str!`) | `String` |
/// | `Option<&'static str>` (`option_env!`) | `Option<String>` |
/// | `&'static [u8; N]` (`include_bytes!`) | `Vec<u8>` |
/// | `&'static str` (`concat!`) | `String` |
///
/// User code that takes the original `&'static` form (e.g.,
/// `let p: &'static str = file!();` or pattern-matching the static
/// shape) will not compile under `#[mask_all]`. Wrap the call site
/// with `unmasked!(file!())` to opt that one position out of the
/// rewrite and keep the stdlib return type.
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
/// - The literal is an argument to `mask!` / `mask_format!` /
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
/// `cargo build` output without changing build success. Each
/// warning's note includes a tag identifying the skip kind
/// (`pattern_position`, `const_initializer`, `static_initializer`,
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
