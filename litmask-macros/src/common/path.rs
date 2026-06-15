//! Call-site path resolution: `include_str!`-style relative resolution,
//! `CARGO_MANIFEST_DIR` lookup, and the manifest-prefix canonicalization
//! that keeps per-call-site nonces stable across checkouts.

use std::path::PathBuf;
use std::sync::OnceLock;

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

/// Cached `CARGO_MANIFEST_DIR` value. Read once on first access and
/// reused for every subsequent call in the proc-macro process.
pub(crate) fn manifest_dir() -> Option<&'static str> {
    static CACHE: OnceLock<Option<String>> = OnceLock::new();
    CACHE
        .get_or_init(|| std::env::var("CARGO_MANIFEST_DIR").ok())
        .as_deref()
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
