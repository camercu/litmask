//! `litmask keygen` produces a usable `LITMASK_UNLOCK_KEY` (§2.9.2).
//!
//! `keygen` is a pure stdout generator: 32 random bytes, base64url. The
//! external tier derives its `unlock_key` from *arbitrary* material via
//! `KDF("litmask-unlock-v1", material)`, so a keygen value is consumable
//! as-is. This test proves the pipe `litmask keygen | <consumer>` end to
//! end: mint a key, seal the external fixture under it, and confirm the
//! same key opens the binary (and a different key does not).
//!
//! The fixture is the same one `external_tier_e2e` uses; cargo runs test
//! binaries sequentially, so the shared fixture target dir is not raced.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
use common::workspace_root;

/// Canary the external fixture masks — MUST match `CANARY` in
/// `tests/external_tier_e2e.rs` and the fixture's `src/main.rs`.
const CANARY: &str = "external-tier-roundtrip-canary-9f3a2c";

/// Env var the build seal and the runtime `EnvVarProvider::default()`
/// both read.
const MATERIAL_VAR: &str = "LITMASK_UNLOCK_KEY";

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// Mint a key by running the real CLI: `litmask keygen`. Returns the
/// trimmed stdout — exactly what a `litmask keygen | …` pipe delivers.
fn keygen() -> String {
    let out = Command::new(cargo())
        .args(["run", "--quiet", "-p", "litmask-cli", "--", "keygen"])
        .current_dir(workspace_root())
        .output()
        .expect("invoke `cargo run -p litmask-cli -- keygen`");
    assert!(out.status.success(), "keygen exited non-zero");
    assert!(out.stderr.is_empty(), "keygen must write nothing to stderr");
    String::from_utf8(out.stdout)
        .expect("keygen stdout is UTF-8")
        .trim_end()
        .to_owned()
}

fn fixture_manifest() -> PathBuf {
    workspace_root().join("litmask/tests/external_fixture/Cargo.toml")
}

fn build_sealed_fixture(material: &str) -> PathBuf {
    let manifest = fixture_manifest();
    let status = Command::new(cargo())
        .args(["build", "--manifest-path"])
        .arg(&manifest)
        .env(MATERIAL_VAR, material)
        .status()
        .expect("invoke cargo build for the external fixture");
    assert!(status.success(), "external fixture failed to build");
    let bin = manifest
        .parent()
        .expect("fixture manifest has a parent dir")
        .join("target/debug/litmask_external_fixture");
    assert!(bin.exists(), "expected fixture binary at {}", bin.display());
    bin
}

fn run_fixture(bin: &Path, material: &str) -> (bool, String) {
    let out = Command::new(bin)
        .env(MATERIAL_VAR, material)
        .output()
        .expect("run the external fixture binary");
    let stdout = String::from_utf8(out.stdout).expect("fixture stdout is UTF-8");
    (out.status.success(), stdout)
}

#[test]
fn keygen_output_is_a_usable_external_unlock_key() {
    let key = keygen();
    // A keygen value is 32 bytes base64url (43 unpadded chars).
    assert_eq!(key.len(), 43, "keygen output should be 43 base64url chars");
    assert_eq!(
        litmask_internal::base64url::decode(&key)
            .expect("keygen output decodes")
            .len(),
        32,
        "keygen output must decode to 32 bytes",
    );

    let bin = build_sealed_fixture(&key);

    let (ok, stdout) = run_fixture(&bin, &key);
    assert!(ok, "the minted key must open the binary it sealed");
    assert!(
        stdout.contains(CANARY),
        "keygen key must decrypt the canary; stdout was {stdout:?}"
    );

    // A different key re-derives a different unlock_key → AEAD rejects it.
    let other = keygen();
    assert_ne!(key, other, "two keygen calls must differ");
    let (ok, stdout) = run_fixture(&bin, &other);
    assert!(!ok, "a different key must not open the binary");
    assert!(
        !stdout.contains(CANARY),
        "a wrong key must never reveal the canary; stdout was {stdout:?}"
    );
}
