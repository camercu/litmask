//! End-to-end exercise of the **`MachineExternal` two-factor tier** (§2.3).
//!
//! A standalone fixture crate (`tests/machine_external_fixture/`) runs
//! `litmask_build::emit()` in its own `build.rs` and calls the two-factor
//! `init!(machine_id + <provider>)` form. Building it with BOTH
//! `LITMASK_MACHINE_ID` and `LITMASK_UNLOCK_KEY` set seals the
//! `machine_external` tier: the build finishes each factor key
//! independently (machine id + nonce; KDF of operator material), composes
//! them machine-first, and wraps `mask_key` under the composition.
//!
//! The fixture lives in its own one-crate workspace (note the empty
//! `[workspace]` table in its manifest) so building it with the factor
//! env vars present does NOT reseal the litmask crate's own embedded
//! build in this workspace's shared target dir.
//!
//! The seal binds two factors, so the test exercises BOTH failure axes —
//! it must open only when *both* match:
//!
//! - seal with (host id, material `X`), run with `X` → both factors
//!   match; the composed `unlock_key` re-derives, `mask_key` unwraps, and
//!   the canary round-trips.
//! - same seal, run with material `Y` → the external factor diverges, the
//!   composition differs, the wrapper's AEAD check fails, and the canary
//!   never prints.
//! - reseal with (wrong id, material `X`), run with `X` → the machine
//!   factor diverges, the composition differs, and the canary never
//!   prints.
//!
//! The host id is sourced through the canonical `litmask show-machine-id`
//! CLI — the same path the build seal reads — so the test never calls
//! `machine_uid::get()` directly. That lookup can fail on container
//! runtimes, OpenBSD, and `/etc/machine-id`-less Linux (§1.6.5); the CLI
//! then exits `UNAVAILABLE` and the test skips cleanly rather than
//! failing.

use std::path::{Path, PathBuf};
use std::process::Command;

mod common;
use common::{machine_id_via_cli, workspace_root};

/// External-factor material the fixture is SEALED with and a successful
/// runtime must re-supply.
const SEALED_MATERIAL: &str = "two-factor operator unlock material v1";

/// External material that does NOT match the seal — re-derives a
/// different external factor key, so the composition (and thus the
/// wrapper's AEAD check) must reject it.
const WRONG_MATERIAL: &str = "an entirely different operator secret";

/// A self-checking token (§4.1.1) for a machine id that is NOT this
/// host's. It is a *well-formed* token — `emit()` decodes it cleanly —
/// but its raw id differs from the host, so the composed `unlock_key`
/// diverges and the runtime must reject it. Built through the token codec
/// because `emit()` now requires the token form on `LITMASK_MACHINE_ID`.
fn wrong_machine_token() -> String {
    litmask_internal::encode_machine_id_token("not-this-hosts-machine-id-0000")
}

/// Canary plaintext the fixture masks. Lexically unusual so its presence
/// in captured stdout is an unambiguous round-trip signal.
const CANARY: &str = "machine-external-tier-roundtrip-canary-3c8f5a";

/// Environment variable the build seal reads to capture the machine id.
const MACHINE_ID_VAR: &str = "LITMASK_MACHINE_ID";

/// Environment variable both the build seal and the runtime
/// `EnvVarProvider::default()` read for the external factor.
const MATERIAL_VAR: &str = "LITMASK_UNLOCK_KEY";

fn fixture_manifest() -> PathBuf {
    workspace_root().join("litmask/tests/machine_external_fixture/Cargo.toml")
}

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// Build the fixture crate sealed under `(machine_id, material)` and
/// return the path to the produced binary. Both vars are part of the
/// build's rerun key, so re-invoking with a different pair reseals the
/// wrapper under the new composition.
fn build_sealed_fixture(machine_id: &str, material: &str) -> PathBuf {
    let manifest = fixture_manifest();
    let status = Command::new(cargo())
        .args(["build", "--manifest-path"])
        .arg(&manifest)
        .env(MACHINE_ID_VAR, machine_id)
        .env(MATERIAL_VAR, material)
        .status()
        .expect("invoke cargo build for the machine_external fixture");
    assert!(status.success(), "machine_external fixture failed to build");

    let bin = manifest
        .parent()
        .expect("fixture manifest has a parent dir")
        .join("target/debug/litmask_machine_external_fixture");
    assert!(bin.exists(), "expected fixture binary at {}", bin.display());
    bin
}

/// Run the sealed fixture binary with `material` supplied as the runtime
/// external factor and return `(success, stdout)`. The machine factor is
/// re-sourced from the host, so only the external var is set here.
fn run_fixture(bin: &Path, material: &str) -> (bool, String) {
    let out = Command::new(bin)
        .env(MATERIAL_VAR, material)
        .output()
        .expect("run the machine_external fixture binary");
    let stdout = String::from_utf8(out.stdout).expect("fixture stdout is UTF-8");
    (out.status.success(), stdout)
}

#[test]
fn two_factor_round_trips_only_when_both_factors_match() {
    // The machine factor is the host's own id, so the seal must be built
    // with that same id, captured through the same CLI a consumer uses.
    // Hosts without a machine id can't exercise this path — skip cleanly.
    let Some(host_id) = machine_id_via_cli() else {
        eprintln!("show-machine-id unavailable on this host; skipping two-factor e2e");
        return;
    };

    // Seal with (host id, SEALED_MATERIAL). Run BEFORE any reseal, which
    // overwrites the shared fixture binary.
    let bin = build_sealed_fixture(&host_id, SEALED_MATERIAL);

    // Both factors match → canary round-trips.
    let (ok, stdout) = run_fixture(&bin, SEALED_MATERIAL);
    assert!(ok, "fixture should exit cleanly when both factors match");
    assert!(
        stdout.contains(CANARY),
        "both factors matching must decrypt the canary; stdout was {stdout:?}"
    );

    // External factor diverges (wrong material, correct host) → reject.
    let (ok, stdout) = run_fixture(&bin, WRONG_MATERIAL);
    assert!(
        !ok,
        "fixture must fail when the external factor does not match the seal"
    );
    assert!(
        !stdout.contains(CANARY),
        "a wrong external factor must never reveal the canary; stdout was {stdout:?}"
    );

    // Machine factor diverges (wrong id at seal, correct material) →
    // reject. Reseal under the wrong id, then run with the correct
    // material so only the machine factor is wrong.
    let bin = build_sealed_fixture(&wrong_machine_token(), SEALED_MATERIAL);
    let (ok, stdout) = run_fixture(&bin, SEALED_MATERIAL);
    assert!(
        !ok,
        "fixture must fail when the machine factor does not match the host"
    );
    assert!(
        !stdout.contains(CANARY),
        "a wrong machine factor must never reveal the canary; stdout was {stdout:?}"
    );
}
