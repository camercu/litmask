//! Helpers shared across the `mask`, `weak_mask`, `mask_format`, and
//! `unmasked` macros: `OUT_DIR` artifact loading + byte-string literal
//! emission. Each per-macro module owns its own input grammar and
//! expansion logic; this module owns the small set of utilities that
//! cross those seams.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use proc_macro2::TokenStream;
use quote::{ToTokens, quote};
use syn::ext::IdentExt;
use syn::parse::ParseStream;
use syn::{LitByteStr, LitCStr, LitStr};
use zeroize::{Zeroize, Zeroizing};

use litmask_internal::{
    CURRENT_CIPHER, KEY_LEN, NONCE_LEN, TAG_LEN, aead_encrypt, nonce_for_call_site,
};

/// Closed set of failure tags from spec §1.9.6. Every litmask compile
/// error carries the invoking macro name plus one of these tags so
/// downstream tooling can pattern-match `<macro>! <tag>` without
/// depending on prose wording.
#[derive(Clone, Copy)]
pub(crate) enum FailTag {
    NonLiteral,
    ReadFailure,
    Unset,
    UnicodeFailure,
    InvalidArg,
    ArgsNotAllowed,
    DuplicateName,
    PositionalAfterNamed,
    PositionalUnused,
    NamedUnused,
    PositionalOutOfRange,
    InvalidPlaceholder,
    TemplateSyntax,
    TierMismatch,
    Grammar,
}

impl FailTag {
    fn slug(self) -> &'static str {
        match self {
            Self::NonLiteral => "non-literal",
            Self::ReadFailure => "read-failure",
            Self::Unset => "unset",
            Self::UnicodeFailure => "unicode-failure",
            Self::InvalidArg => "invalid-arg",
            Self::ArgsNotAllowed => "args-not-allowed",
            Self::DuplicateName => "duplicate-name",
            Self::PositionalAfterNamed => "positional-after-named",
            Self::PositionalUnused => "positional-unused",
            Self::NamedUnused => "named-unused",
            Self::PositionalOutOfRange => "positional-out-of-range",
            Self::InvalidPlaceholder => "invalid-placeholder",
            Self::TemplateSyntax => "template-syntax",
            Self::TierMismatch => "tier-mismatch",
            Self::Grammar => "grammar",
        }
    }
}

/// Construct a `syn::Error` matching the §1.9.6 format
/// `<macro_name>! <tag>: <detail>` (detail omitted when empty).
/// The single emission path keeps every litmask compile error
/// consistent without forcing callers to remember the exact wire
/// shape.
pub(crate) fn compile_error(
    span: proc_macro2::Span,
    macro_name: &str,
    tag: FailTag,
    detail: &str,
) -> syn::Error {
    let msg = if detail.is_empty() {
        format!("{macro_name}! {}", tag.slug())
    } else {
        format!("{macro_name}! {}: {detail}", tag.slug())
    };
    syn::Error::new(span, msg)
}

/// Parse a `proc_macro::TokenStream` as a single `LitStr` argument,
/// or return a §1.9.6 `non-literal` compile error. Used by every
/// path-or-name-shaped mask_*! macro that takes one string literal.
pub(crate) fn require_lit_str(
    input: proc_macro::TokenStream,
    macro_name: &str,
    detail: &str,
) -> Result<LitStr, syn::Error> {
    match syn::parse::<LitStr>(input) {
        Ok(lit) => Ok(lit),
        Err(e) => Err(compile_error(
            e.span(),
            macro_name,
            FailTag::NonLiteral,
            detail,
        )),
    }
}

/// Parse `input` as a single-string-literal path argument, resolve it
/// the way stdlib `include_str!` does — relative to the source file
/// containing the invocation (see [`include_relative_path`]) — and
/// read the file via `reader`. Returns the parsed `LitStr` (for
/// span-preserving downstream emission) plus the read content on
/// success.
///
/// `reader` decides the read shape: pass `std::fs::read_to_string` for
/// `mask_include_str!` (UTF-8 validated at proc-macro time) or
/// `std::fs::read` for `mask_include_bytes!` (raw bytes). The signature
/// preserves UTF-8 fail-fast semantics — invalid UTF-8 in an
/// `include_str!`-shaped file fails the compile, not the user's
/// runtime.
///
/// Error detail echoes the user's literal path, not the resolved
/// path, so trybuild snapshots stay portable and local FS layout
/// doesn't leak into diagnostics.
pub(crate) fn read_lit_str_path<T>(
    input: proc_macro::TokenStream,
    macro_name: &'static str,
    reader: impl FnOnce(&std::path::Path) -> std::io::Result<T>,
) -> Result<(LitStr, T), syn::Error> {
    let path_lit = require_lit_str(input, macro_name, "requires a string literal path")?;
    let path_str = path_lit.value();
    let call_file = proc_macro::Span::call_site().file();
    let resolved = include_relative_path(&call_file, &path_str);
    let content = reader(&resolved).map_err(|e| {
        compile_error(
            path_lit.span(),
            macro_name,
            FailTag::ReadFailure,
            &format!("could not read `{path_str}`: {e}"),
        )
    })?;
    Ok((path_lit, content))
}

/// Resolve an `include_str!`/`include_bytes!`-style path argument the
/// way stdlib does: relative to the directory of the source file that
/// contains the macro invocation, NOT the crate manifest. `call_file`
/// is `proc_macro::Span::file()` of the call site, which rustc
/// expresses relative to its own working directory; joining the user
/// path onto that file's parent reproduces the compiler's own
/// resolution, so `mask_include_str!` is a drop-in for `include_str!`.
///
/// The returned path is left in the same (relative-or-absolute) form
/// as `call_file`; a relative result reads correctly because the
/// proc-macro process shares rustc's working directory.
pub(crate) fn include_relative_path(call_file: &str, user_path: &str) -> PathBuf {
    std::path::Path::new(call_file)
        .parent()
        .unwrap_or_else(|| std::path::Path::new(""))
        .join(user_path)
}

/// Map a `std::env::var` failure to its §1.9.6 `(tag, detail)` pair.
/// Single source of truth for the env-var diagnostic wording shared by
/// `mask_env!`, `mask_option_env!`, and `mask_concat!`'s nested `env!`.
/// `prefix` distinguishes a direct macro ("") from a nested form
/// ("nested env!: ").
pub(crate) fn env_failure(err: &std::env::VarError, name: &str, prefix: &str) -> (FailTag, String) {
    match err {
        std::env::VarError::NotPresent => (
            FailTag::Unset,
            format!("{prefix}environment variable `{name}` is not set"),
        ),
        std::env::VarError::NotUnicode(_) => (
            FailTag::UnicodeFailure,
            format!(
                "{prefix}environment variable `{name}` is set but its value is not valid UTF-8"
            ),
        ),
    }
}

/// Cached `CARGO_MANIFEST_DIR` value. Read once on first access and
/// reused for every subsequent call in the proc-macro process.
pub(crate) fn manifest_dir() -> Option<&'static str> {
    static CACHE: OnceLock<Option<String>> = OnceLock::new();
    CACHE
        .get_or_init(|| std::env::var("CARGO_MANIFEST_DIR").ok())
        .as_deref()
}

/// Process-lifetime cache of `OUT_DIR` artifact contents keyed by file
/// name. `Zeroizing<Vec<u8>>` keeps the type-level signal that the
/// cached buffers carry secret material (`litmask_key.bin`,
/// `litmask_seed.bin`); statics don't run `Drop`, but the wrap covers
/// any code path that evicts an entry.
type ArtifactCache = Mutex<HashMap<&'static str, Zeroizing<Vec<u8>>>>;

/// Load a fixed-size build artifact from the caller crate's `OUT_DIR`.
/// Cached per `name` for the lifetime of the proc-macro process — the
/// same file is read at most once per crate compile, regardless of how
/// many `mask!()` / `weak_mask!()` invocations the crate contains.
///
/// Two of the cached files carry secret key material
/// (`litmask_key.bin`, `litmask_seed.bin`); wrapping each cached `Vec`
/// in `Zeroizing` ensures the underlying heap buffer is wiped on drop.
/// Rust statics never run their `Drop`, so this is defense-in-depth
/// rather than active wipe — it covers any future code path that
/// evicts entries from the cache, and signals the security
/// expectation at the type level.
///
/// Panics at proc-macro expansion time with a diagnostic message if
/// `OUT_DIR` is unset, the file is missing or unreadable, or its
/// length differs from `N` — each of which indicates a missing or
/// out-of-date `litmask_build::emit()` invocation in the caller's
/// `build.rs`.
pub(crate) fn load_out_dir_artifact<const N: usize>(name: &'static str) -> [u8; N] {
    static CACHE: OnceLock<ArtifactCache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().expect("artifact cache mutex poisoned");
    let bytes = map.entry(name).or_insert_with(|| read_out_dir_file(name));
    bytes
        .as_slice()
        .try_into()
        .unwrap_or_else(|_| panic!("litmask: {name} expected {N} bytes, found {}", bytes.len()))
}

fn read_out_dir_file(name: &str) -> Zeroizing<Vec<u8>> {
    let out_dir = std::env::var_os("OUT_DIR")
        .expect("litmask: OUT_DIR not set; did you add a build.rs running litmask_build::emit()?");
    let path = PathBuf::from(out_dir).join(name);
    let bytes = fs::read(&path).unwrap_or_else(|e| {
        panic!(
            "litmask: failed to read {name} from OUT_DIR ({}): {e}; did your build.rs run litmask_build::emit()?",
            path.display(),
        )
    });
    Zeroizing::new(bytes)
}

/// Shared `#[proc_macro_derive]` entry shim: parse the input as
/// `DeriveInput`, run `try_expand`, lower errors via
/// `to_compile_error`. Single owner of the derive error-handling
/// idiom, so span or diagnostic changes land in every derive at once.
pub(crate) fn expand_derive(
    input: proc_macro::TokenStream,
    try_expand: impl FnOnce(&syn::DeriveInput) -> syn::Result<TokenStream>,
) -> proc_macro::TokenStream {
    let derive_input: syn::DeriveInput = match syn::parse(input) {
        Ok(parsed) => parsed,
        Err(e) => return e.to_compile_error().into(),
    };
    match try_expand(&derive_input) {
        Ok(tokens) => tokens.into(),
        Err(e) => e.to_compile_error().into(),
    }
}

/// Bound every type parameter with `bound`, mirroring the plain
/// derives' bound model: `struct Envelope<T>` gets the impl iff
/// `T: Bound`. Bounds land in the where-clause so the impl header
/// stays valid for params that already carry inline bounds.
pub(crate) fn with_trait_bounds(mut generics: syn::Generics, bound: &syn::Path) -> syn::Generics {
    let predicates: Vec<syn::WherePredicate> = generics
        .type_params()
        .map(|param| {
            let ident = &param.ident;
            syn::parse_quote!(#ident: #bound)
        })
        .collect();
    generics.make_where_clause().predicates.extend(predicates);
    generics
}

/// Apply trait bounds to `generics`: with no `#[serde(bound = "...")]`
/// override, fall back to [`with_trait_bounds`] (the default per-param
/// `T: Bound`); with an override, add exactly the user's predicates and
/// skip the default — matching serde's `bound` semantics.
#[cfg(feature = "unstable-serde")]
pub(crate) fn apply_bounds(
    generics: syn::Generics,
    default_bound: &syn::Path,
    custom: Option<&[syn::WherePredicate]>,
) -> syn::Generics {
    match custom {
        Some(predicates) => {
            let mut generics = generics;
            generics
                .make_where_clause()
                .predicates
                .extend(predicates.iter().cloned());
            generics
        }
        None => with_trait_bounds(generics, default_bound),
    }
}

/// AEAD-mask an arbitrary resolved name, emitting a runtime decrypt
/// expression returning `String`. The serde derives pass the name a
/// field/variant/container resolves to after `#[serde(rename = ...)]`;
/// `mask_ident` is the bare-ident path on top of this.
pub(crate) fn mask_name(span: proc_macro2::Span, name: &str) -> TokenStream {
    mask_str(span, name.as_bytes().to_vec())
}

/// AEAD-mask an identifier's name, emitting a runtime decrypt
/// expression returning `String`. Single owner of the masking
/// derives' raw-ident contract: `r#type` renders/serializes as
/// `type`, never with the raw prefix — matching the plain derives.
pub(crate) fn mask_ident(ident: &syn::Ident) -> TokenStream {
    mask_name(ident.span(), &ident.unraw().to_string())
}

/// Emit a `&'static str` expression yielding a masked resolved name at
/// runtime: decrypt the AEAD blob once, leak the `String`, cache in a
/// `OnceLock`. The serde derives need `&'static str` names
/// (`serialize_field`, `Error::missing_field`, ...), which a
/// runtime-decrypted name can only satisfy by leaking; the cache
/// bounds the leak to one allocation per use site. (`MaskDebug` uses
/// bare `mask_ident` instead — the `Formatter` API takes `&str`, so
/// it never needs the leak.)
#[cfg(feature = "unstable-serde")]
pub(crate) fn masked_static_name(span: proc_macro2::Span, name: &str) -> TokenStream {
    let decrypt = mask_name(span, name);
    quote! {
        {
            static __LITMASK_NAME: ::std::sync::OnceLock<&'static str> =
                ::std::sync::OnceLock::new();
            *__LITMASK_NAME.get_or_init(|| ::std::boxed::Box::leak(
                (#decrypt).into_boxed_str(),
            ))
        }
    }
}

/// Emit a byte slice as a byte-string literal token (`b"..."`), typed
/// `&'static [u8; N]`. Used by the `mask!` and `weak_mask!` expansions
/// to inline the encrypted / obfuscated bytes as a `const` in the
/// caller's code. A byte-string literal is one token regardless of
/// length, so it keeps macro expansion and downstream parsing cheap
/// for large blobs (e.g. `mask_include_bytes!` of a sizeable file) —
/// a comma-separated `[u8; N]` array literal would emit `N` tokens.
pub(crate) fn byte_string_literal(bytes: &[u8]) -> TokenStream {
    let lit = proc_macro2::Literal::byte_string(bytes);
    quote! { #lit }
}

/// The three string-like literal kinds accepted by `mask!`,
/// `unmasked!`, and `weak_mask!`. Each variant preserves the
/// literal's source span so per-call-site nonce derivation works
/// even when `#[mask_all]` synthesizes multiple `mask!` calls
/// within one expansion.
pub(crate) enum StringLiteral {
    Str(LitStr),
    ByteStr(LitByteStr),
    CStr(LitCStr),
}

impl StringLiteral {
    pub(crate) fn parse_from(input: ParseStream, macro_name: &str) -> syn::Result<Self> {
        if input.peek(LitStr) {
            return input.parse().map(Self::Str);
        }
        if input.peek(LitByteStr) {
            return input.parse().map(Self::ByteStr);
        }
        if input.peek(LitCStr) {
            return input.parse().map(Self::CStr);
        }
        Err(compile_error(
            input.span(),
            macro_name,
            FailTag::NonLiteral,
            "accepts string, byte string, or C string literals",
        ))
    }
}

impl ToTokens for StringLiteral {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        match self {
            Self::Str(lit) => lit.to_tokens(tokens),
            Self::ByteStr(lit) => lit.to_tokens(tokens),
            Self::CStr(lit) => lit.to_tokens(tokens),
        }
    }
}

/// Parse a `proc_macro::TokenStream` as a [`StringLiteral`]. Returns a
/// `syn::Error` on failure; callers lower it to a token stream at the
/// `expand` boundary via `.to_compile_error().into()`, matching the
/// error-handling idiom used by every other `mask_*!` macro.
pub(crate) fn parse_string_literal(
    input: proc_macro::TokenStream,
    macro_name: &str,
) -> syn::Result<StringLiteral> {
    syn::parse::Parser::parse(
        |stream: ParseStream| StringLiteral::parse_from(stream, macro_name),
        input,
    )
}

/// Strip the consumer crate's `CARGO_MANIFEST_DIR` prefix from a
/// `proc_macro::Span::file()` result so the nonce derivation in
/// §1.5.2 sees a path that's stable across checkouts of the same
/// source at different absolute filesystem locations.
///
/// `Span::file()` returns whatever rustc received — typically an
/// absolute path under the consumer crate. Two CI runs that clone
/// the repo to `/work/abc` vs `/work/def` would otherwise produce
/// different nonces for the same `mask!()` call, breaking
/// reproducibility (§2.1.1.8).
///
/// The strip is path-aware: a prefix only matches at a directory
/// boundary, so `manifest_dir = "/foo/bar"` does not strip
/// `/foo/bar2/src/lib.rs`. Handles both unix and Windows separators
/// since `Span::file()` mirrors the host's path style.
///
/// Returns `raw_file` unchanged when `manifest_dir` is `None` /
/// empty, or when no prefix match exists — both cases degrade
/// gracefully (the nonce remains correct, only the path-stability
/// property is forfeited).
pub(crate) fn canonicalize_file_path(raw_file: String, manifest_dir: Option<&str>) -> String {
    let Some(dir) = manifest_dir else {
        return raw_file;
    };
    if dir.is_empty() {
        return raw_file;
    }
    for sep in ['/', '\\'] {
        let mut prefix = String::with_capacity(dir.len() + 1);
        prefix.push_str(dir);
        prefix.push(sep);
        if let Some(rest) = raw_file.strip_prefix(&prefix) {
            return rest.to_string();
        }
    }
    raw_file
}

/// Return type of a masking macro's runtime expansion. Drives the
/// decrypt-and-construct expression emitted alongside the encrypted
/// blob constant. Private to this module — callers select via the
/// typed [`mask_str`] / [`mask_bytes`] / [`mask_cstr`] helpers.
#[derive(Clone, Copy)]
enum MaskKind {
    /// `String` from UTF-8 bytes.
    Str,
    /// `Vec<u8>` from raw bytes.
    Bytes,
    /// `CString` from UTF-8 bytes (NUL re-added at decode time).
    CStr,
}

/// AEAD-encrypt `plaintext` under the build's `mask_key` and emit a
/// runtime decrypt expression returning `String` (UTF-8). Used by
/// every masking macro whose output is a string: `mask!("text")`,
/// `mask_include_str!`, `mask_concat!`, `mask_env!`,
/// `mask_option_env!`'s `Some` branch, `mask_file!`,
/// `mask_format!`'s per-fragment masking.
pub(crate) fn mask_str(span: proc_macro2::Span, plaintext: Vec<u8>) -> TokenStream {
    mask_plaintext(plaintext, span, MaskKind::Str)
}

/// AEAD-encrypt `plaintext` and emit a runtime decrypt expression
/// returning `Vec<u8>`. Used by `mask!(b"...")` and
/// `mask_include_bytes!`.
pub(crate) fn mask_bytes(span: proc_macro2::Span, plaintext: Vec<u8>) -> TokenStream {
    mask_plaintext(plaintext, span, MaskKind::Bytes)
}

/// AEAD-encrypt `plaintext` and emit a runtime decrypt expression
/// returning `CString` (NUL re-added at decode time). Used by
/// `mask!(c"...")`. The NUL terminator is dropped from `plaintext`
/// before encryption and reconstituted via `__decrypt_cstring_call!`
/// at the user's call site; that macro emits a `compile_error!`
/// under `--no-default-features`.
pub(crate) fn mask_cstr(span: proc_macro2::Span, plaintext: Vec<u8>) -> TokenStream {
    mask_plaintext(plaintext, span, MaskKind::CStr)
}

/// Encrypt `plaintext` under the build's `mask_key` keyed on the
/// `(file, line, column, plaintext)` tuple of `span` (spec §1.5.2),
/// then emit a `{ const __LITMASK_BLOB = ...; decrypt(...) }` block
/// that returns a value of the kind-appropriate type at runtime.
///
/// Shared body for every call-site masking macro. Handles key/seed
/// loading, nonce derivation, AEAD encryption, secret zeroization,
/// and the runtime decrypt expression for the requested return type.
///
/// `plaintext` is zeroized on return; callers MUST NOT rely on
/// reading the buffer afterwards.
fn mask_plaintext(mut plaintext: Vec<u8>, span: proc_macro2::Span, kind: MaskKind) -> TokenStream {
    let mut mask_key = load_out_dir_artifact::<KEY_LEN>("litmask_key.bin");
    let mut seed = load_out_dir_artifact::<KEY_LEN>("litmask_seed.bin");

    let pm_span = span.unwrap();
    let file = canonicalize_file_path(pm_span.file(), manifest_dir());
    let line = u32::try_from(pm_span.line()).unwrap_or(u32::MAX);
    let column = u32::try_from(pm_span.column()).unwrap_or(u32::MAX);
    let nonce = nonce_for_call_site(&seed, &file, line, column, &plaintext);
    seed.zeroize();

    let ciphertext_and_tag = aead_encrypt(CURRENT_CIPHER, &mask_key, &nonce, &plaintext)
        .expect("AEAD encryption failed during litmask macro expansion");
    // The proc-macro server is a long-lived dylib; build-time key
    // material lingers in process memory if not explicitly cleared.
    // `litmask-build::emit` already zeroizes its copies — mirror
    // that discipline here for every expansion.
    mask_key.zeroize();
    plaintext.zeroize();

    let blob: Vec<u8> = [nonce.as_slice(), &ciphertext_and_tag].concat();
    let blob_lit = byte_string_literal(&blob);
    let blob_len = blob.len();
    // Wire-format contract: every blob is `nonce (NONCE_LEN) ||
    // ciphertext (plaintext.len()) || tag (TAG_LEN)`. plaintext was
    // zeroized above, but its prior length equals blob_len - NONCE_LEN
    // - TAG_LEN; assert the relationship so future changes to the
    // concat shape trip a test-time panic.
    debug_assert!(blob_len >= NONCE_LEN + TAG_LEN);
    debug_assert_eq!(blob_len, NONCE_LEN + ciphertext_and_tag.len());
    let blob_ident = syn::Ident::new("__LITMASK_BLOB", proc_macro2::Span::mixed_site());
    let wrapper = quote! { ::litmask::__wrapper_bytes!() };
    let seal_tier = quote! { ::litmask::__seal_tier!() };
    let decrypt_expr = match kind {
        // One opaque runtime call, no `String` in the expansion: the
        // type's rendered name in consumer-side diagnostics (`String`
        // vs the `__String` alias) varies with the consumer's dep
        // graph, which broke trybuild snapshot stability for const /
        // static misuse fixtures.
        MaskKind::Str => quote! {
            ::litmask::__internal::__decrypt_string(#blob_ident, #wrapper, #seal_tier)
        },
        MaskKind::Bytes => quote! {
            ::litmask::__internal::__decrypt(#blob_ident, #wrapper, #seal_tier)
        },
        MaskKind::CStr => quote! {
            ::litmask::__decrypt_cstring_call!(#blob_ident, #wrapper)
        },
    };

    quote! {
        {
            const #blob_ident: &[u8; #blob_len] = #blob_lit;
            #decrypt_expr
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // `env_failure` is the pure decision function behind the env
    // macros' diagnostics: given a `VarError`, it picks the §1.9.6 tag
    // and message. Testing it here (rather than driving the macros with
    // a mutated process environment) mirrors the `parse_env_value`
    // precedent in `litmask/src/provider/env.rs` — the workspace
    // `forbid(unsafe_code)` lint rules out the `env::set_var` approach
    // a macro-level test would need. The tag classification is the
    // externally-visible behavior #3 changed: `NotUnicode` is now an
    // error category, not a silent `None`.
    #[test]
    fn env_failure_not_present_classifies_as_unset() {
        let (tag, detail) = env_failure(&std::env::VarError::NotPresent, "FOO", "");
        assert!(matches!(tag, FailTag::Unset));
        assert_eq!(detail, "environment variable `FOO` is not set");
    }

    #[test]
    fn env_failure_not_unicode_classifies_as_unicode_failure() {
        let err = std::env::VarError::NotUnicode(std::ffi::OsString::from("x"));
        let (tag, detail) = env_failure(&err, "FOO", "");
        assert!(matches!(tag, FailTag::UnicodeFailure));
        assert_eq!(
            detail,
            "environment variable `FOO` is set but its value is not valid UTF-8"
        );
    }

    #[test]
    fn env_failure_prefix_is_prepended() {
        let (_, detail) = env_failure(&std::env::VarError::NotPresent, "BAR", "nested env!: ");
        assert_eq!(detail, "nested env!: environment variable `BAR` is not set");
    }

    #[test]
    fn canonicalize_strips_unix_manifest_dir_prefix() {
        let result = canonicalize_file_path(
            "/users/alice/repo/src/lib.rs".to_string(),
            Some("/users/alice/repo"),
        );
        assert_eq!(result, "src/lib.rs");
    }

    #[test]
    fn canonicalize_strips_windows_manifest_dir_prefix() {
        let result = canonicalize_file_path(
            r"C:\Users\alice\repo\src\lib.rs".to_string(),
            Some(r"C:\Users\alice\repo"),
        );
        assert_eq!(result, r"src\lib.rs");
    }

    #[test]
    fn canonicalize_returns_path_unchanged_when_no_prefix_match() {
        let result =
            canonicalize_file_path("/other/path/lib.rs".to_string(), Some("/users/alice/repo"));
        assert_eq!(result, "/other/path/lib.rs");
    }

    #[test]
    fn canonicalize_returns_path_unchanged_when_no_env_var() {
        let result = canonicalize_file_path("/some/path/lib.rs".to_string(), None);
        assert_eq!(result, "/some/path/lib.rs");
    }

    #[test]
    fn canonicalize_returns_path_unchanged_when_manifest_dir_empty() {
        let result = canonicalize_file_path("src/lib.rs".to_string(), Some(""));
        assert_eq!(result, "src/lib.rs");
    }

    #[test]
    fn canonicalize_returns_path_unchanged_when_no_trailing_separator() {
        // raw_file equals manifest_dir with no separator after; the
        // strip MUST fail rather than produce an empty string.
        let result =
            canonicalize_file_path("/users/alice/repo".to_string(), Some("/users/alice/repo"));
        assert_eq!(result, "/users/alice/repo");
    }

    #[test]
    fn canonicalize_does_not_strip_partial_prefix() {
        // manifest_dir prefix matches a sibling directory name —
        // MUST NOT strip ("/foo/bar" is not a prefix of "/foo/bar2").
        let result = canonicalize_file_path("/foo/bar2/src/lib.rs".to_string(), Some("/foo/bar"));
        assert_eq!(result, "/foo/bar2/src/lib.rs");
    }
}
