//! Helpers shared across the `mask`, `weak_mask`, `mask_fmt`, and
//! `unmasked` macros: `OUT_DIR` artifact loading + byte-array token
//! emission. Each per-macro module owns its own input grammar and
//! expansion logic; this module owns the small set of utilities that
//! cross those seams.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

use proc_macro2::TokenStream;
use quote::quote;
use zeroize::{Zeroize, Zeroizing};

use litmask_internal::{CipherId, KEY_LEN, aead_encrypt, nonce_for_call_site};

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

/// Emit a byte slice as a `[u8; N]` array literal token. Used by the
/// `mask!` and `weak_mask!` expansions to inline the encrypted /
/// obfuscated bytes as a `const` array in the caller's code.
pub(crate) fn byte_array_token(bytes: &[u8]) -> TokenStream {
    quote! { [ #(#bytes),* ] }
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
/// Return type of a masking macro's runtime expansion. Drives the
/// decrypt-and-construct expression emitted alongside the encrypted
/// blob constant.
#[derive(Clone, Copy)]
pub(crate) enum MaskKind {
    /// `String` from UTF-8 bytes — `mask!("text")`, `mask_include_str!`,
    /// `mask_concat!`, `mask_env!`, `mask_option_env!`'s `Some` branch,
    /// `mask_file!`.
    Str,
    /// `Vec<u8>` from raw bytes — `mask!(b"...")`, `mask_include_bytes!`.
    Bytes,
    /// `CString` from UTF-8 bytes (NUL re-added at decode time) —
    /// `mask!(c"...")`.
    CStr,
}

/// Encrypt `plaintext` under the build's `mask_key` keyed on the
/// `(file, line, column, plaintext)` tuple of `span` (spec §1.5.2),
/// then emit a `{ const __LITMASK_BLOB = ...; decrypt(...) }` block
/// that returns a value of the kind-appropriate type at runtime.
///
/// All six call-site masking macros (`mask!`, `mask_include_str!`,
/// `mask_include_bytes!`, `mask_concat!`, `mask_env!`,
/// `mask_option_env!`, `mask_file!`) share this body once their
/// input has been resolved at proc-macro time. The helper handles
/// key/seed loading, nonce derivation, AEAD encryption, secret
/// zeroization, and the runtime decrypt expression for the
/// requested return type.
///
/// `plaintext` is zeroized on return; callers MUST NOT rely on
/// reading the buffer afterwards.
pub(crate) fn mask_plaintext(
    mut plaintext: Vec<u8>,
    span: proc_macro2::Span,
    kind: MaskKind,
) -> TokenStream {
    let mut mask_key = load_out_dir_artifact::<KEY_LEN>("litmask_key.bin");
    let mut seed = load_out_dir_artifact::<KEY_LEN>("litmask_seed.bin");

    let pm_span = span.unwrap();
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").ok();
    let file = canonicalize_file_path(pm_span.file(), manifest_dir.as_deref());
    let line = u32::try_from(pm_span.line()).unwrap_or(u32::MAX);
    let column = u32::try_from(pm_span.column()).unwrap_or(u32::MAX);
    let nonce = nonce_for_call_site(&seed, &file, line, column, &plaintext);
    seed.zeroize();

    let ciphertext_and_tag =
        aead_encrypt(CipherId::ChaCha20Poly1305, &mask_key, &nonce, &plaintext)
            .expect("AEAD encryption failed during litmask macro expansion");
    // The proc-macro server is a long-lived dylib; build-time key
    // material lingers in process memory if not explicitly cleared.
    // `litmask-build::emit` already zeroizes its copies — mirror
    // that discipline here for every expansion.
    mask_key.zeroize();
    plaintext.zeroize();

    let blob: Vec<u8> = [nonce.as_slice(), &ciphertext_and_tag].concat();
    let blob_lit = byte_array_token(&blob);
    let blob_len = blob.len();
    let blob_ident = syn::Ident::new("__LITMASK_BLOB", proc_macro2::Span::mixed_site());
    let wrapper = quote! { ::litmask::__wrapper_bytes!() };
    let decrypt_expr = match kind {
        MaskKind::Str => quote! {
            ::litmask::__internal::__String::from_utf8(
                ::litmask::__internal::__decrypt(#blob_ident, #wrapper)
            )
            .unwrap()
        },
        MaskKind::Bytes => quote! {
            ::litmask::__internal::__decrypt(#blob_ident, #wrapper)
        },
        MaskKind::CStr => quote! {
            ::litmask::__decrypt_cstring_call!(#blob_ident, #wrapper)
        },
    };

    quote! {
        {
            const #blob_ident: &[u8; #blob_len] = &#blob_lit;
            #decrypt_expr
        }
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

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
