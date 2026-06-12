//! End-to-end exercise of the **Machine tier**.
//!
//! A standalone fixture crate (`tests/machine_fixture/`) runs
//! `litmask_build::emit()` in its own `build.rs` and calls
//! `init!(bind_to_machine)`. Building it with `LITMASK_MACHINE_ID` set seals
//! the `machine` tier: the build derives `unlock_key =
//! derive_machine_id_key(<id>, wrapper_nonce)` and wraps `mask_key` under
//! it. At runtime `init!(bind_to_machine)` recomputes the host id and
//! re-derives the same key — so the binary opens only on a host whose id
//! matches the build's.
//!
//! The fixture lives in its own one-crate workspace (note the empty
//! `[workspace]` table in its manifest) so building it with
//! `LITMASK_MACHINE_ID` present does NOT reseal the litmask crate's own
//! embedded build in this workspace's shared target dir.
//!
//! Unlike the External tier — where the factor varies at *runtime* — the
//! machine factor is fixed at runtime (it is the host's own id), so this
//! test varies the factor at *build* time instead:
//!
//! - seal with the host's real id → `init!(bind_to_machine)` re-derives the
//!   same `unlock_key`, unwraps `mask_key`, and `mask!` round-trips the
//!   canary plaintext.
//! - seal with a *different* id → the host re-derives a different
//!   `unlock_key`, the AEAD tag check on the wrapper fails, `init!`
//!   returns `Err`, and the canary never prints.
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

/// A self-checking token (§4.1.1) for a machine id that is NOT this
/// host's. It is a *well-formed* token — `emit()` decodes it cleanly —
/// but its raw id differs from the host, so the runtime re-derives a
/// different `unlock_key` and the wrapper's AEAD tag check rejects it.
/// Built through the token codec because `emit()` now requires the token
/// form on `LITMASK_MACHINE_ID`.
fn wrong_machine_token() -> String {
    litmask_internal::encode_machine_id_token("not-this-hosts-machine-id-0000")
}

/// Canary plaintext the fixture masks. Lexically unusual so its presence
/// in captured stdout is an unambiguous round-trip signal.
const CANARY: &str = "machine-tier-roundtrip-canary-7b1e4d";

/// Environment variable the build seal reads to capture the machine id.
const MACHINE_ID_VAR: &str = "LITMASK_MACHINE_ID";

fn fixture_manifest() -> PathBuf {
    workspace_root().join("litmask/tests/machine_fixture/Cargo.toml")
}

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// Build the fixture crate sealed under `machine_id` and return the path
/// to the produced binary. The fixture's own workspace puts the binary at
/// a predictable `target/debug/<name>` under the fixture dir.
///
/// `LITMASK_MACHINE_ID` is part of the build's rerun key, so re-invoking
/// with a different id reseals the wrapper under the new id.
fn build_sealed_fixture(machine_id: &str) -> PathBuf {
    let manifest = fixture_manifest();
    let status = Command::new(cargo())
        .args(["build", "--manifest-path"])
        .arg(&manifest)
        .env(MACHINE_ID_VAR, machine_id)
        .status()
        .expect("invoke cargo build for the machine fixture");
    assert!(status.success(), "machine fixture failed to build");

    let bin = manifest
        .parent()
        .expect("fixture manifest has a parent dir")
        .join("target/debug/litmask_machine_fixture");
    assert!(bin.exists(), "expected fixture binary at {}", bin.display());
    bin
}

/// Run the sealed fixture binary and return `(success, stdout)`. The
/// machine factor is re-sourced from the host at runtime, so no env is
/// supplied here.
fn run_fixture(bin: &Path) -> (bool, String) {
    let out = Command::new(bin)
        .output()
        .expect("run the machine fixture binary");
    let stdout = String::from_utf8(out.stdout).expect("fixture stdout is UTF-8");
    (out.status.success(), stdout)
}

#[test]
fn machine_tier_round_trips_when_sealed_with_host_id_and_fails_otherwise() {
    // The runtime factor is the host's own machine id, so the seal must
    // be built with that same id, captured through the same CLI a
    // consumer would use. Hosts without a machine id (containers,
    // OpenBSD, /etc/machine-id-less Linux) can't exercise this path —
    // skip cleanly rather than fail.
    let Some(host_id) = machine_id_via_cli() else {
        eprintln!("show-machine-id unavailable on this host; skipping machine-tier e2e");
        return;
    };

    // Seal with the host's real id, then run on this host: the runtime
    // recomputes the same id and the canary round-trips. Run BEFORE the
    // second build, which overwrites the shared fixture binary.
    let bin = build_sealed_fixture(&host_id);
    let (ok, stdout) = run_fixture(&bin);
    assert!(
        ok,
        "fixture should exit cleanly when sealed with the host id"
    );
    assert!(
        stdout.contains(CANARY),
        "matching machine id must decrypt the canary; stdout was {stdout:?}"
    );

    // Reseal with a different id (rerun-if-env-changed forces a fresh
    // seal), then run on this host: the runtime re-derives a different
    // unlock_key and the wrapper's AEAD check rejects it.
    let bin = build_sealed_fixture(&wrong_machine_token());
    let (ok, stdout) = run_fixture(&bin);
    assert!(
        !ok,
        "fixture must fail to initialize when sealed under a non-host id"
    );
    assert!(
        !stdout.contains(CANARY),
        "wrong machine id must never reveal the canary; stdout was {stdout:?}"
    );
}
