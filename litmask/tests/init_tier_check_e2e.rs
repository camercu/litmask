//! End-to-end coverage for `init!`'s build-authoritative form↔tier
//! cross-check (§2.6.1, §1.9.6).
//!
//! The `init!` proc-macro reads `LITMASK_SEAL_TIER` at expansion time and
//! emits a `compile_error!` when the call form and the sealed tier
//! disagree, or when the tag is absent. Those branches cannot be covered
//! by the in-crate `trybuild` harness (`tests/compile.rs`): litmask's own
//! build script sets `cargo:rustc-env=LITMASK_SEAL_TIER=embedded`, and
//! that value leaks into the trybuild subprocess, so a `compile_fail`
//! fixture can never observe a *mismatched* or *missing* tag. Without
//! this test the `check_tier` `Err` arms are exercised only by pure unit
//! tests, so a reorder that moved the env read before the args-empty
//! check would silently drop their compile-level coverage.
//!
//! Each fixture is its own one-crate workspace (empty `[workspace]`
//! table), so its `build.rs` (or absence of one) controls the sealed tier
//! independently of litmask's own embedded build in the shared target
//! dir. Both builds are EXPECTED TO FAIL — the test asserts the compiler
//! rejected them and named the right §1.9.6 cause.

use std::process::{Command, Output};

mod common;
use common::workspace_root;

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// Build the fixture at `manifest_rel` with the given extra env, return
/// the raw `Output`. No `assert!(success)` — every caller here expects a
/// compile failure and inspects stderr.
///
/// The `LITMASK_*` seal-input vars are scrubbed from the inherited
/// environment first: litmask's own build sets `LITMASK_SEAL_TIER` and it
/// leaks into this test process's environment, so an unscrubbed subprocess
/// would pass that ambient tag down to the fixture's `init!` expansion —
/// masking the very `unset`/mismatch branch under test. Each caller then
/// re-adds exactly the channel it wants the fixture's `emit()` to seal
/// under.
fn build_fixture(manifest_rel: &str, env: &[(&str, &str)]) -> Output {
    let manifest = workspace_root().join(manifest_rel);
    let mut cmd = Command::new(cargo());
    cmd.args(["build", "--manifest-path"]).arg(&manifest);
    for var in [
        "LITMASK_SEAL_TIER",
        "LITMASK_UNLOCK_KEY",
        "LITMASK_MACHINE_ID",
    ] {
        cmd.env_remove(var);
    }
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.output()
        .unwrap_or_else(|e| panic!("invoke cargo build for {}: {e}", manifest.display()))
}

/// A `machine`-tier checksum-bearing token is irrelevant here; the
/// `external` tier only needs *some* unlock material present to seal off
/// the Embedded floor. The value never has to round-trip — the build
/// fails before any binary is produced.
const EXTERNAL_MATERIAL: &str = "init-tier-check external seal material";

#[test]
fn init_machine_form_against_external_seal_fails_to_compile() {
    // Sealing the fixture `external` (via LITMASK_UNLOCK_KEY) while its
    // source calls `init!(bind_to_machine)` (the Machine form) makes the
    // build-sealed tier disagree with the form.
    let out = build_fixture(
        "litmask/tests/init_mismatch_fixture/Cargo.toml",
        &[("LITMASK_UNLOCK_KEY", EXTERNAL_MATERIAL)],
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "init!(bind_to_machine) against an external seal must fail to compile; stderr was {stderr:?}"
    );
    assert!(
        stderr.contains("init! tier-mismatch"),
        "compile error must carry the §1.9.6 tier-mismatch tag; stderr was {stderr:?}"
    );
    assert!(
        stderr.contains("external"),
        "the diagnostic must name the sealed tier; stderr was {stderr:?}"
    );
}

#[test]
fn init_form_without_emit_fails_with_unset_tier() {
    // The unset fixture's build.rs deliberately does not call
    // `litmask_build::emit()`, so `LITMASK_SEAL_TIER` is absent in this
    // isolated consumer crate (litmask's own tag does not cross the crate
    // boundary).
    let out = build_fixture("litmask/tests/init_unset_fixture/Cargo.toml", &[]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success(),
        "init!(bind_to_machine) with no litmask_build::emit() must fail to compile; stderr was {stderr:?}"
    );
    assert!(
        stderr.contains("LITMASK_SEAL_TIER is unset"),
        "compile error must name the unset tag and point at build.rs; stderr was {stderr:?}"
    );
}
