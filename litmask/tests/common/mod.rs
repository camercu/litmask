//! Shared helpers for integration tests under `litmask/tests/`.
//!
//! Cargo treats `tests/common/mod.rs` specially: it is NOT compiled as
//! its own test binary, only `pub use`-able from sibling tests via
//! `mod common;`. Keep helpers focused on assertions and on
//! invocations that the integration tests share.

#![allow(dead_code)] // Some helpers are used by only a subset of integration tests.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Mutex, Once, OnceLock};

use litmask::{KeyError, KeyProvider, UnlockKey, init_with};

/// Substrings whose presence in any compiled example binary indicates
/// that internal library identifiers or operational tooling vocabulary
/// has leaked into user-facing plaintext. Matched case-insensitively.
///
/// Treat this list as a regression net rather than proof of
/// leak-freedom: the canonical positive signal is the
/// high-entropy-fixture strings check (e.g., the masked Twain
/// substring being absent from `strings` output). Extend the list
/// when new identifiable terms enter the codebase.
pub const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    "litmask",
    "blake3",
    "mask_key",
    "unlock_key",
    "ChaCha20-Poly1305",
    "AEAD encryption",
    "OUT_DIR",
    "locator_b64",
    // Both `weak_mask` and `tamper` would identify a binary as
    // litmask-related if they surfaced through panic-message text
    // or a leaked identifier. The binary's own basename is filtered
    // out before matching (see `filter_binary_basename`) so
    // `weak_mask_demo` does not false-fire on `weak_mask`.
    "weak_mask",
    "tamper",
];

/// Workspace root, derived from `CARGO_MANIFEST_DIR` (set by cargo for
/// every test invocation). The litmask crate lives one level beneath
/// the workspace, so the parent of the manifest dir is the root.
pub fn workspace_root() -> PathBuf {
    PathBuf::from(env_var("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Cargo build profiles available to integration tests.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    Debug,
    /// Stripped-symbols release profile — the recommended deployment
    /// configuration. Used by the dirty-word scrub.
    Release,
}

impl Profile {
    fn dir(self) -> &'static str {
        match self {
            Self::Debug => "debug",
            Self::Release => "release",
        }
    }

    fn cargo_flags(self) -> &'static [&'static str] {
        match self {
            Self::Debug => &[],
            Self::Release => &["--release"],
        }
    }
}

/// Path to an example binary under the given profile.
pub fn example_path(name: &str, profile: Profile) -> PathBuf {
    workspace_root()
        .join("target")
        .join(profile.dir())
        .join("examples")
        .join(name)
}

/// Path to `litmask.config` for the given profile.
pub fn config_path(profile: Profile) -> PathBuf {
    workspace_root()
        .join("target")
        .join(profile.dir())
        .join("litmask.config")
}

/// Build one example by name in the given profile, panicking with a
/// useful message on failure.
///
/// Memoized per `(name, profile, features)` for the lifetime of the
/// test process: subsequent calls with the same key are no-ops.
/// Cargo's own fingerprint cache already skips a recompile for an
/// up-to-date binary, but each `cargo build` invocation still pays
/// ~100–500ms of startup (process spawn + manifest parse +
/// dep-graph walk). The `example_scrub` integration test builds
/// every example at least once across the run; memoizing here
/// shaves a few seconds off the wall time without changing
/// semantics — within one test-binary process, building an example
/// the second time guarantees nothing has changed since the first.
pub fn build_example(name: &str, profile: Profile) {
    build_example_with_features(name, profile, &[]);
}

/// `build_example` with an explicit feature list, passed verbatim
/// to `cargo build --features <...>`. Used by the `hw_id_provider`
/// scrub, which must enable `hw-id` even when the surrounding test
/// runner was launched with default features only (the example's
/// `required-features = ["hw-id"]` would otherwise silently skip
/// the build).
///
/// Concurrency: cargo's own fingerprint cache serializes builds
/// against the workspace's lock files, but two parallel `cargo
/// build --example X` invocations against the same target can race
/// such that the second returns before the first has finished
/// writing the output binary. The integration tests run in parallel
/// (`cargo test`'s default), so two tests both calling
/// `build_example("X", _)` first would otherwise see the second
/// caller's `assert!(path.exists())` fail because cargo hasn't
/// flushed the binary yet. Hold the memoization mutex for the
/// duration of the cargo invocation so the second caller blocks
/// until the first call's cargo write completes. Serial across all
/// example builds is acceptable — there are <10 examples and each
/// cargo build is a cache-hit no-op after the first build per
/// (name, profile, features) triple.
pub fn build_example_with_features(name: &str, profile: Profile, features: &[&str]) {
    /// `(example_name, profile, sorted_feature_list)` identifying a
    /// single example-build invocation. Aliased so the static below
    /// stays under clippy's `type_complexity` threshold.
    type BuildKey = (String, Profile, Vec<String>);
    static BUILT: OnceLock<Mutex<HashSet<BuildKey>>> = OnceLock::new();
    let built = BUILT.get_or_init(|| Mutex::new(HashSet::new()));
    let feature_key: Vec<String> = features.iter().map(|s| (*s).to_string()).collect();
    let mut guard = built
        .lock()
        .expect("build_example memoization mutex poisoned");
    if !guard.insert((name.to_string(), profile, feature_key)) {
        return;
    }

    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let mut cmd = Command::new(&cargo);
    cmd.arg("build");
    cmd.args(profile.cargo_flags());
    if !features.is_empty() {
        cmd.args(["--features", &features.join(",")]);
    }
    cmd.args(["--example", name]);
    cmd.current_dir(workspace_root());
    let status = cmd.status().expect("invoke cargo");
    assert!(
        status.success(),
        "cargo build {flags:?} --features {features:?} --example {name} failed (exit={status:?})",
        flags = profile.cargo_flags(),
    );
    // `guard` drops at end of scope, releasing the mutex AFTER the
    // build artifact exists on disk — that's the load-bearing
    // ordering this function enforces.
    drop(guard);
}

/// Run `strings` on `binary` and return its stdout as UTF-8. Asserts
/// the tool is on PATH and exited cleanly.
pub fn strings_of(binary: &Path) -> String {
    let output = Command::new("strings")
        .arg(binary)
        .output()
        .expect("strings(1) must be available on PATH");
    assert!(
        output.status.success(),
        "strings(1) failed on {} (exit={:?})",
        binary.display(),
        output.status
    );
    String::from_utf8(output.stdout).expect("strings output is UTF-8")
}

/// Assert that none of the [`FORBIDDEN_SUBSTRINGS`] appear in
/// `binary`'s `strings` output, case-insensitively. Delegates to
/// [`assert_no_dirty_words_except`] with an empty allow-list — i.e.
/// every forbidden substring is treated as a leak.
pub fn assert_no_dirty_words(binary: &Path) {
    assert_no_dirty_words_except(binary, &[]);
}

/// [`assert_no_dirty_words`] with a per-binary allow-list. Listed
/// substrings (lowercased before comparison) are stripped from the
/// scrub haystack before the [`FORBIDDEN_SUBSTRINGS`] match, so a
/// transitive-dep crate name that inevitably embeds itself in its
/// own symbol table (e.g. `blake3_*` function names from the
/// `blake3` crate when `hw-id` is enabled) doesn't false-fire on
/// the forbidden list.
///
/// Two classes of substrings are ALSO stripped, unconditionally:
///
/// - Rust source-file locations of the form `<crate>/src/<path>.rs`,
///   emitted by `core::panic::Location::caller()` at every panic
///   site. Unavoidable on stable Rust without the nightly-only
///   `-Z location-detail=none` flag.
/// - The binary's own basename (e.g. `weak_mask_demo`), which the
///   linker embeds in the build-id section. Without this filter,
///   adding `weak_mask` to the forbidden list false-fires on
///   `weak_mask_demo`'s own filename.
///
/// Reports every hit in a single panic message so callers see all
/// leaks at once instead of fixing one and re-running.
pub fn assert_no_dirty_words_except(binary: &Path, allow: &[&str]) {
    let output = strings_of(binary);
    let filtered = filter_source_locations(&output);
    let filtered = filter_binary_basename(&filtered, binary);
    let mut haystack = filtered.to_ascii_lowercase();
    for allowed in allow {
        // Replace rather than remove so byte-offsets-in-context for
        // any subsequent match still point at the original source
        // position — useful when a future allow entry happens to
        // contain a forbidden substring.
        haystack = haystack.replace(&allowed.to_ascii_lowercase(), "");
    }

    let hits: Vec<&str> = FORBIDDEN_SUBSTRINGS
        .iter()
        .copied()
        .filter(|word| haystack.contains(&word.to_ascii_lowercase()))
        .collect();

    assert!(
        hits.is_empty(),
        "{} leaked library plaintext into the binary; found case-insensitive matches for: {:?} (allow-list: {:?})",
        binary.display(),
        hits,
        allow,
    );
}

/// Strip the binary's own filename (without extension) from the
/// haystack. Linkers embed the executable name in the build-id /
/// note section, which would otherwise false-fire any forbidden
/// substring that overlaps with an example name.
fn filter_binary_basename(input: &str, binary: &Path) -> String {
    let Some(name) = binary.file_stem().and_then(|s| s.to_str()) else {
        return input.to_owned();
    };
    input.replace(name, "")
}

/// Strip substrings that look like Rust source-file locations of the
/// form `<crate>/src/<path>.rs`. These are emitted by
/// `core::panic::Location::caller()` at every panic site and cannot
/// be removed on stable Rust 1.88 (the unstable
/// `-Z location-detail=none` flag would do it on nightly).
fn filter_source_locations(input: &str) -> String {
    static PATTERN: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = PATTERN.get_or_init(|| {
        regex::Regex::new(r"[A-Za-z][A-Za-z0-9_-]*(?:/[A-Za-z0-9_./-]+)+\.rs")
            .expect("source-location regex compiles")
    });
    re.replace_all(input, "").into_owned()
}

/// Assert that `needle` does NOT appear in `binary`'s `strings`
/// output. Case-sensitive by design — used for test fixtures that are
/// intentionally chosen to be lexically unusual (e.g., Twain
/// quotations).
pub fn assert_substring_absent(binary: &Path, needle: &str) {
    let output = strings_of(binary);
    assert!(
        !output.contains(needle),
        "fixture substring {needle:?} leaked into {}",
        binary.display(),
    );
}

/// Parse the `unlock_key` field out of `litmask.config` and return its
/// base64url-encoded value (without surrounding quotes).
pub fn read_unlock_key(config_path: &Path) -> String {
    let body = std::fs::read_to_string(config_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", config_path.display()));
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("unlock_key = \"") {
            if let Some(value) = rest.strip_suffix('"') {
                return value.to_string();
            }
        }
    }
    panic!("unlock_key not found in {}", config_path.display());
}

fn env_var(key: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| panic!("{key} not set"))
}

/// Run `f` while suppressing the default panic hook and return the
/// panic payload (downcast to `String` or `&'static str`) if it
/// unwound. Returns `None` when `f` completed normally.
///
/// Both panic kinds reach the same downcast cascade: `panic!("x")`
/// captures as `&'static str`; `panic!("x={}", x)` captures as
/// `String`. Replaces the duplicated take-hook + catch-unwind +
/// downcast block that otherwise needs to live next to every test
/// asserting a specific panic message.
pub fn catch_panic_msg<F>(f: F) -> Option<String>
where
    F: FnOnce() + std::panic::UnwindSafe,
{
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(f);
    std::panic::set_hook(prev_hook);
    let payload = outcome.err()?;
    payload.downcast_ref::<String>().cloned().or_else(|| {
        payload
            .downcast_ref::<&'static str>()
            .map(|s| (*s).to_string())
    })
}

/// Like [`catch_panic_msg`], but panics if `f` returned normally.
/// Use when the test unconditionally expects a panic.
pub fn assert_panic_msg<F>(f: F) -> String
where
    F: FnOnce() + std::panic::UnwindSafe,
{
    catch_panic_msg(f).expect("expected closure to panic, but it returned normally")
}

/// Parse the unlock key from `litmask.config` at the given profile's
/// build directory and return a ready-to-use [`UnlockKey`].
pub fn unlock_key_from_config(profile: Profile) -> UnlockKey {
    let b64 = read_unlock_key(&config_path(profile));
    UnlockKey::from_base64url(&b64).expect("base64url unlock_key in litmask.config")
}

/// Idempotently initialize the runtime against the debug-profile
/// `litmask.config` so integration tests do not depend on
/// `LITMASK_UNLOCK_KEY` being set in the test process's environment.
/// Safe to call from every `#[test]` — only the first call performs
/// initialization.
pub fn init_once() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let key = read_unlock_key(&config_path(Profile::Debug));
        let provider = TestKeyProvider { key_b64: key };
        init_with!(provider).expect("init_with succeeded");
    });
}

/// `KeyProvider` that returns a base64url-encoded unlock key from an
/// in-process `String`. Used by integration tests that want
/// deterministic init against the build's `litmask.config` without
/// depending on `LITMASK_UNLOCK_KEY` in the test environment.
pub struct TestKeyProvider {
    pub key_b64: String,
}

impl KeyProvider for TestKeyProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        UnlockKey::from_base64url(&self.key_b64)
    }
}
