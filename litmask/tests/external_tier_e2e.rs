//! End-to-end exercise of the **External tier**.
//!
//! A standalone fixture crate (`tests/external_fixture/`) runs
//! `litmask_build::emit()` in its own `build.rs` and calls the External
//! `init!(<provider>)` form. Building it with `LITMASK_UNLOCK_KEY` set
//! seals the `external` tier: the build derives `unlock_key =
//! KDF("litmask-unlock-v1", material)` and wraps `mask_key` under it.
//!
//! The fixture lives in its own one-crate workspace (note the empty
//! `[workspace]` table in its manifest) so building it with
//! `LITMASK_UNLOCK_KEY` present does NOT reseal the litmask crate's own
//! embedded build in this workspace's shared target dir.
//!
//! The test builds the fixture ONCE with material `X`, then runs it
//! TWICE — the runtime material only affects the running process, never
//! the sealed binary:
//!
//! - run with `X` → `EnvVarProvider` re-derives the same `unlock_key`,
//!   unwraps `mask_key`, and `mask!` round-trips the canary plaintext.
//! - run with `Y` → a different `unlock_key`, the AEAD tag check on the
//!   wrapper fails, `init!` returns `Err`, and the canary never prints.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
use common::workspace_root;

/// External-factor material the fixture is SEALED with at build time and
/// the material a successful runtime must re-supply. Arbitrary length /
/// bytes — `UnlockKey::derive` normalizes it.
const SEALED_MATERIAL: &str = "operator-supplied external unlock material v1";

/// Material that does NOT match the seal — re-derives a different
/// `unlock_key`, so the wrapper's AEAD tag check must reject it.
const WRONG_MATERIAL: &str = "an entirely different operator secret";

/// Canary plaintext the fixture masks. Lexically unusual so its presence
/// in captured stdout is an unambiguous round-trip signal.
const CANARY: &str = "external-tier-roundtrip-canary-9f3a2c";

/// Environment variable both the build seal and the runtime
/// `EnvVarProvider::default()` read.
const MATERIAL_VAR: &str = "LITMASK_UNLOCK_KEY";

fn fixture_manifest() -> PathBuf {
    workspace_root().join("litmask/tests/external_fixture/Cargo.toml")
}

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// Build the fixture crate sealed under [`SEALED_MATERIAL`] and return
/// the path to the produced binary. The fixture's own workspace puts the
/// binary at a predictable `target/debug/<name>` under the fixture dir,
/// so no `--message-format=json` parse is needed to locate it.
fn build_sealed_fixture() -> PathBuf {
    let manifest = fixture_manifest();
    let status = Command::new(cargo())
        .args(["build", "--manifest-path"])
        .arg(&manifest)
        .env(MATERIAL_VAR, SEALED_MATERIAL)
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

/// Run the sealed fixture binary with `material` supplied via the env
/// channel and return `(success, stdout)`.
fn run_fixture(bin: &Path, material: &str) -> (bool, String) {
    let out = Command::new(bin)
        .env(MATERIAL_VAR, material)
        .output()
        .expect("run the external fixture binary");
    let stdout = String::from_utf8(out.stdout).expect("fixture stdout is UTF-8");
    (out.status.success(), stdout)
}

#[test]
fn external_tier_round_trips_with_matching_material_and_fails_with_wrong_material() {
    let bin = build_sealed_fixture();

    let (ok, stdout) = run_fixture(&bin, SEALED_MATERIAL);
    assert!(
        ok,
        "fixture should exit cleanly when given the sealed material"
    );
    assert!(
        stdout.contains(CANARY),
        "matching material must decrypt the canary; stdout was {stdout:?}"
    );

    let (ok, stdout) = run_fixture(&bin, WRONG_MATERIAL);
    assert!(
        !ok,
        "fixture must fail to initialize under non-matching material"
    );
    assert!(
        !stdout.contains(CANARY),
        "wrong material must never reveal the canary; stdout was {stdout:?}"
    );
}
