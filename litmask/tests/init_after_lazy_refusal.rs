//! End-to-end guard for the **debug init-after-lazy fail-fast**.
//!
//! On an Embedded-sealed build the lazy first-`mask!()` path derives the
//! same key `init!()` would, so an `init!()` that arrives AFTER a lazy
//! init is functionally invisible — until the consumer reseals at a
//! higher tier, where the same ordering panics at runtime (§2.1.1.12a).
//! Debug builds must surface the latent ordering bug at the late
//! `init!()` itself instead of silently returning `Ok(())`; release
//! builds keep the silent idempotent return (§2.6.1.4).
//!
//! A standalone fixture crate (`tests/init_after_lazy_fixture/`) is
//! built in debug with NO key-channel env vars (Embedded floor). It
//! calls `mask!()` first (lazy init succeeds), then `init!()`. The test
//! asserts the process aborts at the late `init!()` with a message
//! naming the ordering cause, after the lazy `mask!()` already produced
//! its plaintext.

use std::path::PathBuf;
use std::process::Command;

mod common;
use common::workspace_root;

/// Printed by the fixture's lazy `mask!()` BEFORE the late `init!()`.
/// Its presence proves the abort happened at the `init!()` call, not in
/// the (legal) lazy path.
const PRE_CANARY: &str = "init-after-lazy-pre-canary-4c8d1f";

/// Printed only if the late `init!()` wrongly returned `Ok(())`.
const POST_CANARY: &str = "init-after-lazy-post-canary-9b2e7a";

fn fixture_manifest() -> PathBuf {
    workspace_root().join("litmask/tests/init_after_lazy_fixture/Cargo.toml")
}

fn cargo() -> std::ffi::OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

/// Build the fixture at the Embedded floor in the given profile and
/// return the path to the produced binary. Key-channel env vars are
/// scrubbed so a developer's ambient `LITMASK_UNLOCK_KEY` /
/// `LITMASK_MACHINE_ID` cannot push the seal off the Embedded floor and
/// invalidate the test.
fn build_embedded_fixture(profile_flags: &[&str], profile_dir: &str) -> PathBuf {
    let manifest = fixture_manifest();
    let status = Command::new(cargo())
        .arg("build")
        .args(profile_flags)
        .arg("--manifest-path")
        .arg(&manifest)
        .env_remove("LITMASK_UNLOCK_KEY")
        .env_remove("LITMASK_MACHINE_ID")
        .status()
        .expect("invoke cargo build for the init-after-lazy fixture");
    assert!(status.success(), "init-after-lazy fixture failed to build");

    let bin = manifest
        .parent()
        .expect("fixture manifest has a parent dir")
        .join("target")
        .join(profile_dir)
        .join("litmask_init_after_lazy_fixture");
    assert!(bin.exists(), "expected fixture binary at {}", bin.display());
    bin
}

#[test]
fn init_after_lazy_mask_aborts_in_debug_with_ordering_diagnostic() {
    let bin = build_embedded_fixture(&[], "debug");

    let out = Command::new(&bin)
        .output()
        .expect("run the init-after-lazy fixture binary");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(
        stdout.contains(PRE_CANARY),
        "the lazy mask!() must succeed on an Embedded seal before the late init!(); \
         stdout was {stdout:?}"
    );
    assert!(
        !out.status.success(),
        "a debug build must abort at an init!() that arrives after lazy init"
    );
    assert!(
        !stdout.contains(POST_CANARY),
        "the late init!() must not silently return Ok(()); stdout was {stdout:?}"
    );
    // The actionable debug message must name the ordering cause — the
    // init arrived after a mask!() already lazily initialized — so the
    // developer moves init!() ahead of the first mask!() now, before a
    // higher-tier reseal turns the latent bug into a runtime panic.
    assert!(
        stderr.contains("after") && stderr.contains("mask!"),
        "panic must explain the init-after-lazy ordering cause; stderr was {stderr:?}"
    );
}

/// Release keeps the silent idempotent `Ok(())` (§2.6.1.4): the
/// provenance guard compiles to nothing, so the same ordering that
/// aborts a debug build runs to completion — and no diagnostic text
/// reaches the artifact.
#[test]
fn init_after_lazy_mask_is_silent_noop_in_release() {
    let bin = build_embedded_fixture(&["--release"], "release");

    let out = Command::new(&bin)
        .output()
        .expect("run the init-after-lazy fixture binary (release)");
    let stdout = String::from_utf8_lossy(&out.stdout);

    assert!(
        out.status.success(),
        "a release build must keep the idempotent Ok(()) on init-after-lazy; \
         stderr was {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(PRE_CANARY) && stdout.contains(POST_CANARY),
        "release run must complete both prints; stdout was {stdout:?}"
    );
}
