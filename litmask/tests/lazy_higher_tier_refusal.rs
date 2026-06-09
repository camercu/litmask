//! End-to-end guard for the **lazy-init tier gate**.
//!
//! The lazy first-`mask!()` path derives the keyless Embedded
//! `unlock_key` from the wrapper nonce. That is correct only when the
//! build is sealed at the Embedded floor. On a higher-tier build (here
//! `external`), a `mask!()` that races ahead of the required
//! `init!(<provider>)` would otherwise lazy-derive the *wrong* (Embedded)
//! key and fail the wrapper AEAD check — surfacing as a generic
//! decryption error that hides the real cause (a missing/late `init!`).
//!
//! A standalone fixture crate (`tests/lazy_higher_tier_fixture/`) runs
//! `litmask_build::emit()` and calls `mask!()` with NO `init!`. Built
//! with `LITMASK_UNLOCK_KEY` set it seals the `external` tier, so its
//! first `mask!()` hits the lazy path under a non-Embedded seal. The
//! fixture lives in its own one-crate workspace (empty `[workspace]`
//! table) so sealing it does not reseal the litmask crate's own embedded
//! build in the shared target dir.
//!
//! The fixture is built in debug, where the §5.4 diagnostics split emits
//! the actionable message. The test asserts the process aborts and that
//! the panic names the init-ordering cause rather than a bare decryption
//! failure.

use std::path::PathBuf;
use std::process::Command;

mod common;
use common::workspace_root;

/// External-factor material the fixture is SEALED with at build time.
/// Its only job is to push the seal off the Embedded floor and onto the
/// `external` tier; the runtime never supplies it (no `init!` runs).
const SEALED_MATERIAL: &str = "lazy-refusal external seal material v1";

/// Canary the fixture would print if the lazy path wrongly succeeded.
/// Its absence from stdout confirms the gate fired before any plaintext
/// was produced.
const CANARY: &str = "lazy-higher-tier-canary-7d1e4b";

fn fixture_manifest() -> PathBuf {
    workspace_root().join("litmask/tests/lazy_higher_tier_fixture/Cargo.toml")
}

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// Build the fixture sealed at the `external` tier (debug profile) and
/// return the path to the produced binary.
fn build_sealed_fixture() -> PathBuf {
    let manifest = fixture_manifest();
    let status = Command::new(cargo())
        .args(["build", "--manifest-path"])
        .arg(&manifest)
        .env("LITMASK_UNLOCK_KEY", SEALED_MATERIAL)
        .status()
        .expect("invoke cargo build for the lazy-higher-tier fixture");
    assert!(status.success(), "lazy-higher-tier fixture failed to build");

    let bin = manifest
        .parent()
        .expect("fixture manifest has a parent dir")
        .join("target/debug/litmask_lazy_higher_tier_fixture");
    assert!(bin.exists(), "expected fixture binary at {}", bin.display());
    bin
}

#[test]
fn lazy_init_on_higher_tier_aborts_with_init_ordering_diagnostic() {
    let bin = build_sealed_fixture();

    let out = Command::new(&bin)
        .output()
        .expect("run the lazy-higher-tier fixture binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        !out.status.success(),
        "an external-sealed build with no init!() must abort on the first mask!()"
    );
    assert!(
        !stdout.contains(CANARY),
        "the lazy path must refuse before producing plaintext; stdout was {stdout:?}"
    );
    // The actionable debug message must name the init-ordering cause
    // ("before init!") rather than the generic decryption hint, so an
    // operator sees the real fix (call init! first) instead of chasing a
    // phantom key/ciphertext mismatch.
    assert!(
        stderr.contains("before init"),
        "panic must explain the init-ordering cause; stderr was {stderr:?}"
    );
}
