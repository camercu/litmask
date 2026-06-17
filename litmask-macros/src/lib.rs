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
mod derive_support;
mod init;
mod mask;
mod mask_all;
mod mask_concat;
mod mask_debug;
#[cfg(feature = "unstable-serde")]
mod mask_deserialize;
mod mask_env;
mod mask_file;
mod mask_format;
mod mask_include_bytes;
mod mask_include_str;
mod mask_option_env;
#[cfg(feature = "unstable-serde")]
mod mask_serialize;
#[cfg(feature = "unstable-stack")]
mod mask_stack;
#[cfg(feature = "unstable-serde")]
mod serde_attrs;
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
/// # Wiping the decrypted output
///
/// The returned value is an ordinary `String` / `Vec<u8>`, freed without
/// overwriting — its plaintext lingers in residual memory after drop.
/// Wrap it in `litmask::Zeroizing` to overwrite the buffer on drop:
///
/// ```ignore
/// let token = litmask::Zeroizing::new(litmask::mask!("super-secret"));
/// assert_eq!(token.as_str(), "super-secret"); // derefs to `str`
/// ```
///
/// This is memory-remanence hygiene (shrinks the window a dropped secret
/// is recoverable from a core dump, swap, or hibernation image); it does
/// not defend against a live debugger or prevent re-derivation, and any
/// `.clone()` / `format!` / print copy escapes the wrapper. `mask!(c"…")`
/// (`CString`) is not wrappable this way — decrypt as `mask!("…")`, wrap
/// the `String`, and build a transient `CString` at the FFI boundary.
///
/// # Errors
///
/// Expansion fails with a `compile_error!` when the input is not one
/// of the three accepted literal kinds — including macro invocations
/// such as `include_str!`, `concat!`, `env!`, or user-defined macros.
/// Two misuses surface as rustc's own diagnostics instead: a `const` /
/// `static` initializer is `E0015` (`mask!()` is a runtime value), and
/// a pattern position (`match` arm, `if let`, `while let`) is the
/// natural "expected pattern" error.
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

/// Stack-backed, zero-alloc counterpart of [`macro@mask`]: decrypt a
/// literal into an inline `[u8; N]` (length fixed at expansion) rather
/// than a heap `String` / `Vec` / `CString`. The expansion returns a
/// guard that derefs to the value and zeroizes its buffer on drop:
///
/// - `mask_stack!("...")` returns `litmask::MaskStr<N>` (derefs to `str`).
/// - `mask_stack!(b"...")` returns `litmask::MaskBytes<N>` (derefs to `[u8]`).
/// - `mask_stack!(c"...")` returns `litmask::MaskCStr<N>` (derefs to `CStr`).
///
/// Because nothing is heap-allocated, no allocator reuse can leave an
/// unscrubbed copy of the plaintext behind — the only copy lives in the
/// guard and is wiped on drop.
///
/// Accepts the same three literal kinds as [`macro@mask`]. Prefer
/// [`macro@mask`] for large literals: the inline buffer lives on the stack
/// (the `LITMASK_STACK_LIMIT` cap guards against accidental overflow).
///
/// # Errors / Panics
///
/// Same expansion-time and runtime contract as [`macro@mask`].
#[cfg(feature = "unstable-stack")]
#[proc_macro]
pub fn mask_stack(input: TokenStream) -> TokenStream {
    mask_stack::expand(input)
}

/// Install a process-global **governing provider**
/// ([ADR-0001](https://github.com/camercu/litmask/blob/main/docs/adr/0001-masking-crate-unlock-governance.md))
/// and eagerly unlock the host's own wrapper through it. Once installed, the lazy path
/// unlocks every other masking crate's wrapper through the same provider —
/// governed masking across the dependency graph under a uniform seal.
///
/// There is no bare `init!()`: the keyless **Embedded** tier
/// self-initializes on the first `mask!()`. The governing forms select the
/// keying tier:
///
/// - `init!(<provider-expr>)` — `External`, taking any
///   `litmask::KeyProvider` value.
/// - `init!(bind_to_machine)` — `Machine`.
/// - `init!(bind_to_machine + <provider-expr>)` — `MachineExternal`.
///
/// Each expands at the call site so it can `include_bytes!` the embedded
/// `mask_key` wrapper from the calling crate's `OUT_DIR`, and returns
/// `Result<(), litmask::InitError>`; calling `litmask::init!(provider)?`
/// at startup surfaces initialization failures as a `Result` rather than a
/// panic deep in the first `mask!()` call.
///
/// A proc-macro (not `macro_rules!`) so it can read the
/// build-authoritative `LITMASK_SEAL_TIER` tag and cross-check the
/// form against the sealed tier.
///
/// Repeat calls are idempotent (`Ok(())`; the first governor wins).
///
/// # Errors
///
/// Emits a §1.9.6 `compile_error!` carrying `init! tier-mismatch` when
/// the call form and the build's sealed tier disagree, or when no tier
/// was set at all (no `litmask_build::emit()` in the caller's
/// `build.rs`).
#[proc_macro]
pub fn init(input: TokenStream) -> TokenStream {
    init::expand(&input)
}

/// Mask the UTF-8 contents of a file at compile time. The path is
/// resolved relative to the source file containing the invocation
/// (like stdlib `include_str!`); its bytes are AEAD-encrypted into a
/// blob embedded in the binary, and the macro expands to a runtime
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
/// Expansion fails when the argument is not a string-literal path, or
/// when the file cannot be read (missing, unreadable, etc.); the
/// diagnostic names the path and the underlying cause.
///
/// # Panics
///
/// Same proc-macro-time panic conditions as [`mask!`] for missing
/// `OUT_DIR`, key/seed files, etc.
#[proc_macro]
pub fn mask_include_str(input: TokenStream) -> TokenStream {
    mask_include_str::expand(input)
}

/// Mask the raw bytes of a file at compile time. The path is
/// resolved relative to the source file containing the invocation
/// (like stdlib `include_bytes!`); its bytes are AEAD-encrypted and
/// the macro expands to a runtime decrypt call returning `Vec<u8>`.
/// The plaintext bytes never appear in the compiled binary's
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
/// Same conditions as [`macro@mask_include_str`]: a non-string-literal
/// path argument, or a file that cannot be read.
///
/// # Panics
///
/// Same proc-macro-time panic conditions as [`mask!`] for missing
/// `OUT_DIR`, key/seed files, etc.
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
/// Expansion fails on an empty argument list, on an argument that is
/// neither a string literal nor a compile-time-resolvable string macro
/// (`concat!` / `include_str!` / `env!`), or when a nested
/// `include_str!` cannot read its file or a nested `env!` names an
/// unset variable (the underlying cause is propagated).
///
/// # Panics
///
/// Same proc-macro-time panic conditions as [`mask!`] for missing
/// `OUT_DIR`, key/seed files, etc.
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
/// Mirrors stdlib `env!`: expansion fails when the argument is not a
/// string-literal name, or when the named variable is unset at build
/// time.
///
/// # Panics
///
/// Same proc-macro-time panic conditions as [`mask!`] for missing
/// `OUT_DIR`, key/seed files, etc.
#[proc_macro]
pub fn mask_env(input: TokenStream) -> TokenStream {
    mask_env::expand(input)
}

/// Mask a build-time environment-variable value at compile time,
/// returning `Some(String)` when set and `None::<String>` when
/// unset. Mirrors stdlib `option_env!`'s contract exactly — an unset
/// variable is a legitimate runtime `None`, but a variable that is
/// present with a non-UTF-8 value is a compile error (NOT `None`).
///
/// # Errors
///
/// Expansion fails when the argument is not a string-literal name, or
/// when the named variable is present but not valid UTF-8 — matching
/// stdlib `option_env!`, which also rejects a non-Unicode value at
/// compile time rather than yielding `None`. An *unset* variable is a
/// legitimate runtime `None`, not an error.
///
/// # Panics
///
/// Same proc-macro-time panic conditions as [`mask!`] for missing
/// `OUT_DIR`, key/seed files, etc.
#[proc_macro]
pub fn mask_option_env(input: TokenStream) -> TokenStream {
    mask_option_env::expand(input)
}

/// Mask the call site's source-file path at compile time. The
/// proc-macro reads `proc_macro::Span::call_site().file()`,
/// AEAD-encrypts that path, and expands to a runtime decrypt call
/// returning `String`. The decrypted value mirrors stdlib `file!()`
/// exactly — the same path at the same span — only masked.
///
/// The `CARGO_MANIFEST_DIR`-relative stripping (§1.5.2) is applied
/// solely to the per-call-site nonce derivation, for reproducible
/// builds across checkouts at different absolute paths; it does NOT
/// alter the value handed back to the caller.
///
/// The raw source path never appears in the compiled binary's
/// `.rodata`. Note: `core::panic::Location::caller()` independently
/// embeds source paths at every panic site (`.unwrap()`,
/// `.expect("...")`, etc.); `mask_file!` masks only its own
/// explicit invocations, not the implicit panic-site embedding.
///
/// # Errors
///
/// Expansion fails when given any arguments — `mask_file!` takes none.
///
/// # Panics
///
/// Same proc-macro-time panic conditions as [`mask!`] for missing
/// `OUT_DIR`, key/seed files, etc.
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

/// Pre-`init!()` string obfuscation via XOR against the per-build
/// wrapper bytes. Expand to code that decodes back to `&'static str`
/// on first runtime access and caches the result for the program's
/// lifetime.
///
/// `weak_mask!()` is the **only** masking macro that works before
/// `init!` has run. Use it **exclusively** for bootstrap-phase
/// strings that must be readable before the AEAD mask-key cell is
/// populated — env-var names, default file paths, and other
/// non-secret metadata that the provider needs during init.
///
/// `weak_mask!()` is strictly weaker than [`mask!`]: there is no AEAD
/// authentication, and both ciphertext and key material live in the
/// same compiled binary, so a Level-2 attacker (disassembler + manual
/// decode) can recover the plaintext. Real secrets always go through
/// [`mask!`] after `init!()` has succeeded.
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
/// It also swaps each type's plain `#[derive(Debug)]` for [`MaskDebug`]
/// and — under the `unstable-serde` feature — `#[derive(Serialize)]` /
/// `#[derive(Deserialize)]` for `MaskSerialize` / `MaskDeserialize`, so
/// the container / field / variant *names* don't re-enter `.rodata` as
/// cleartext. Annotate a type with [`macro@unmasked_derive`] to keep its
/// plain derives.
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
/// - Qualified macro paths (`std::format!`, `core::dbg!`, etc.) are
///   recognized by matching the last path segment.
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

/// Opt a single struct or enum out of `#[mask_all]`'s derive-swapping.
///
/// `#[mask_all]` rewrites a type's plain `#[derive(Serialize)]` /
/// `#[derive(Deserialize)]` (under `unstable-serde`) and
/// `#[derive(Debug)]` to litmask's masking derives so the type's names
/// don't land in `.rodata` as cleartext. Annotate a type with
/// `#[unmasked_derive]` to keep its plain derives instead — useful when
/// the type relies on a `#[serde(...)]` attribute the masking derives
/// don't yet support, or when a plain `Debug` is intentionally wanted.
///
/// `#[mask_all]` consumes the marker, so it leaves no trace in the
/// expansion. Outside a `#[mask_all]` module the attribute is an
/// identity no-op, so it is always valid to write.
#[proc_macro_attribute]
pub fn unmasked_derive(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

/// **EXPERIMENTAL** (`unstable-serde` feature, semver-exempt): derive
/// a `serde::Serialize` impl whose struct and field names are
/// AEAD-masked at compile time instead of embedded as cleartext
/// `&'static str` data in the binary.
///
/// Serialized output is byte-identical to plain
/// `#[derive(serde::Serialize)]` for every serde format: the
/// expansion goes through `serialize_struct`, decrypting each name on
/// first use and caching it for the process lifetime (one leaked
/// allocation per name).
///
/// Supports every struct shape (named-field, tuple, newtype, unit)
/// and enums, including uninhabited ones. Generic types are supported
/// — each type parameter is bounded `Serialize`, mirroring the plain
/// derive. Pair with [`MaskDeserialize`] and [`MaskDebug`]; a plain
/// `#[derive(serde::Deserialize)]` or `#[derive(Debug)]` on the same
/// type re-embeds every name in the binary and defeats this derive's
/// purpose.
///
/// # Supported `#[serde(...)]` attributes
///
/// `rename` / `rename_all` (with `serialize`/`deserialize` split),
/// `skip` / `skip_serializing` / `skip_serializing_if`, `serialize_with`
/// / `with`, `bound`, and `transparent`. Each stays wire-identical to
/// the plain derive. Any other key (e.g. `flatten`, enum `tag` /
/// `untagged` / `content`) is reject-loud rather than silently ignored;
/// `serialize_with` / `with` is not yet supported on a generic type. Use
/// a plain `#[derive(Serialize)]` (or `#[unmasked_derive]` under
/// `#[mask_all]`) for those.
///
/// # Errors
///
/// Emits a §1.9.6 `compile_error!` (`MaskSerialize! grammar` /
/// `invalid-arg`) for any unsupported input shape or attribute, rather
/// than silently degrading to cleartext names.
///
/// # Panics
///
/// Inherits [`mask!`]'s expansion-time panic policy (missing
/// `OUT_DIR`, unreadable build artifact, AEAD failure). At runtime,
/// the first serialization panics if decryption fails — same policy
/// as [`mask!`], so run `init!` before serializing on tiers above
/// Embedded.
// `attributes(serde)` registers the helper attribute so rustc parses
// `#[serde(...)]` on the input instead of erroring "cannot find
// attribute" — the derive then honors the supported subset and
// reject-louds the rest with a §1.9.6 diagnostic.
#[cfg(feature = "unstable-serde")]
#[proc_macro_derive(MaskSerialize, attributes(serde))]
pub fn mask_serialize(input: TokenStream) -> TokenStream {
    mask_serialize::expand(input)
}

/// Derive a `serde::Deserialize` impl whose type and field names are
/// AEAD-masked at compile time instead of embedded as cleartext
/// `&'static str` data in the binary (`FIELDS` arrays, field-visitor
/// match arms, `expecting()` texts, `missing_field` diagnostics).
///
/// Behavior is identical to plain `#[derive(serde::Deserialize)]` for
/// every serde format — same accepted inputs, same values, same error
/// messages — with each name decrypted on first use and cached for
/// the process lifetime (one leaked allocation per name).
///
/// Supports every struct shape (named-field, tuple, newtype, unit)
/// and enums, including uninhabited ones. Generic types are supported
/// — each type parameter is bounded `Deserialize<'de>` — and `&str` /
/// `&[u8]` fields borrow from the input, both mirroring the plain
/// derive. Pair with [`MaskSerialize`] and [`MaskDebug`]; a plain
/// serde derive or `#[derive(Debug)]` on the same type re-embeds
/// every name in the binary and defeats this derive's purpose.
///
/// # Supported `#[serde(...)]` attributes
///
/// `rename` / `rename_all` (with `serialize`/`deserialize` split),
/// `skip` / `skip_deserializing`, `default` (and `default = "path"`),
/// `alias`, `deserialize_with` / `with`, `deny_unknown_fields`, `bound`,
/// and `transparent`. Each stays behavior-identical to the plain derive.
/// Any other key (e.g. `flatten`, enum `tag` / `untagged` / `content`,
/// variant `alias`) is reject-loud; `deserialize_with` / `with` is not
/// yet supported on a generic type. Use a plain `#[derive(Deserialize)]`
/// (or `#[unmasked_derive]` under `#[mask_all]`) for those.
///
/// # Errors
///
/// Emits a §1.9.6 `compile_error!` (`MaskDeserialize! grammar` /
/// `invalid-arg`) for any unsupported input shape or attribute, rather
/// than silently degrading to cleartext names.
///
/// # Panics
///
/// Inherits [`mask!`]'s expansion-time panic policy (missing
/// `OUT_DIR`, unreadable build artifact, AEAD failure). At runtime,
/// the first deserialization panics if decryption fails — same policy
/// as [`mask!`], so run `init!` before deserializing on tiers above
/// Embedded.
// `attributes(serde)` registers the helper attribute so rustc parses
// `#[serde(...)]` on the input instead of erroring "cannot find
// attribute" — the derive then honors the supported subset and
// reject-louds the rest with a §1.9.6 diagnostic.
#[cfg(feature = "unstable-serde")]
#[proc_macro_derive(MaskDeserialize, attributes(serde))]
pub fn mask_deserialize(input: TokenStream) -> TokenStream {
    mask_deserialize::expand(input)
}

/// Derive a `core::fmt::Debug` impl whose type and field names are
/// AEAD-masked at compile time instead of embedded as cleartext
/// `&'static str` data in the binary.
///
/// Formatted output (`{:?}` and `{:#?}`) is byte-identical to plain
/// `#[derive(Debug)]`. Names are decrypted on each `fmt` call and
/// dropped afterwards — nothing is cached or leaked, and the derive
/// works in `no_std` + `alloc` builds.
///
/// # Errors
///
/// Emits a §1.9.6 `compile_error!` (`MaskDebug! grammar`) for any
/// unsupported input shape, rather than silently degrading to
/// cleartext names.
///
/// # Panics
///
/// Inherits [`mask!`]'s expansion-time panic policy (missing
/// `OUT_DIR`, unreadable build artifact, AEAD failure). At runtime,
/// formatting panics if decryption fails — same policy as [`mask!`],
/// so run `init!` before formatting on tiers above Embedded.
#[proc_macro_derive(MaskDebug)]
pub fn mask_debug(input: TokenStream) -> TokenStream {
    mask_debug::expand(input)
}
