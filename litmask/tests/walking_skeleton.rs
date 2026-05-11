//! Walking-skeleton integration test (Task 5 acceptance).
//!
//! Builds the `hello_world` example, scans its binary with `strings`
//! for absence of the masked Twain fixture, then runs it with
//! `LITMASK_UNLOCK_KEY` sourced from the build's `litmask.config` and
//! asserts the decrypted output matches the fixture.

use std::path::{Path, PathBuf};
use std::process::Command;

const FIXTURE: &str = "The reports of my death have been greatly exaggerated. — Mark Twain";

/// Substring of the fixture that is lexically unusual enough to make
/// false-positive matches against std / dependency text effectively
/// impossible.
const FIXTURE_GREP: &str = "greatly exaggerated";

#[test]
fn end_to_end_round_trip() {
    let manifest_dir = env_path("CARGO_MANIFEST_DIR");
    let workspace_root = manifest_dir.parent().expect("workspace root");

    // 1) Build the example. Cargo places the binary under
    //    target/<profile>/examples/hello_world by default.
    run_cargo(workspace_root, &["build", "--example", "hello_world"]);

    let example_bin = workspace_root
        .join("target")
        .join("debug")
        .join("examples")
        .join("hello_world");
    assert!(
        example_bin.exists(),
        "example binary missing: {example_bin:?}"
    );

    // 2) strings(1) check. The canonical security-property assertion.
    let strings_output = Command::new("strings")
        .arg(&example_bin)
        .output()
        .expect("strings(1) must be available on PATH");
    assert!(strings_output.status.success(), "strings(1) failed");
    let stdout = std::str::from_utf8(&strings_output.stdout).expect("strings output is UTF-8");
    assert!(
        !stdout.contains(FIXTURE_GREP),
        "fixture substring {FIXTURE_GREP:?} leaked into example binary plaintext"
    );

    // 3) Run the example with the build's unlock_key.
    let config = workspace_root
        .join("target")
        .join("debug")
        .join("litmask.config");
    let unlock_key = read_unlock_key(&config);

    let run_output = Command::new(&example_bin)
        .env("LITMASK_UNLOCK_KEY", &unlock_key)
        .output()
        .expect("example invocation failed");
    assert!(
        run_output.status.success(),
        "example exited non-zero: status={:?} stderr={}",
        run_output.status,
        String::from_utf8_lossy(&run_output.stderr)
    );
    let stdout = String::from_utf8(run_output.stdout).expect("example stdout is UTF-8");
    assert_eq!(stdout, format!("{FIXTURE}\n"));
}

#[test]
fn litmask_config_present_with_required_fields() {
    let workspace_root = env_path("CARGO_MANIFEST_DIR")
        .parent()
        .expect("workspace root")
        .to_path_buf();
    let config = workspace_root
        .join("target")
        .join("debug")
        .join("litmask.config");
    assert!(config.exists(), "litmask.config missing at {config:?}");
    let body = std::fs::read_to_string(&config).expect("read litmask.config");
    assert!(body.contains("unlock_key ="), "unlock_key key missing");
    assert!(body.contains("locator ="), "locator key missing");
    assert!(
        body.contains("length = 62"),
        "length field missing or wrong (expected 62)"
    );
}

#[test]
fn key_provider_is_object_safe() {
    use litmask::{EnvVarProvider, KeyProvider};
    let _: Box<dyn KeyProvider> = Box::new(EnvVarProvider::default());
}

fn run_cargo(working_dir: &Path, args: &[&str]) {
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(&cargo)
        .args(args)
        .current_dir(working_dir)
        .status()
        .expect("invoke cargo");
    assert!(status.success(), "cargo {args:?} failed");
}

fn read_unlock_key(config_path: &Path) -> String {
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

fn env_path(var: &str) -> PathBuf {
    std::env::var_os(var)
        .unwrap_or_else(|| panic!("{var} not set"))
        .into()
}
