//! End-to-end integration test for the `hello_world` example.
//!
//! Builds the example, scans its binary with `strings` for absence of
//! the masked Twain fixture, then runs it with `LITMASK_UNLOCK_KEY`
//! sourced from the build's `litmask.config` and asserts the
//! decrypted output matches the fixture.

mod common;

use common::Profile;
use std::process::Command;

const FIXTURE: &str = "The reports of my death have been greatly exaggerated. — Mark Twain";

/// Substring of the fixture that is lexically unusual enough to make
/// false-positive matches against std / dependency text effectively
/// impossible.
const FIXTURE_SUBSTRING: &str = "greatly exaggerated";

#[test]
fn end_to_end_round_trip() {
    common::build_example("hello_world", Profile::Debug);
    let example_bin = common::example_path("hello_world", Profile::Debug);
    assert!(
        example_bin.exists(),
        "example binary missing: {}",
        example_bin.display()
    );

    // Canonical security-property assertion: the high-entropy fixture
    // substring is absent from compiled plaintext.
    common::assert_substring_absent(&example_bin, FIXTURE_SUBSTRING);

    // End-to-end runtime check: the example, given the build's
    // unlock_key, recovers the fixture and prints it to stdout.
    let unlock_key = common::read_unlock_key(&common::config_path(Profile::Debug));
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
    let config = common::config_path(Profile::Debug);
    assert!(
        config.exists(),
        "litmask.config missing at {}",
        config.display()
    );
    let body = std::fs::read_to_string(&config).expect("read litmask.config");
    assert!(body.contains("unlock_key ="), "unlock_key field missing");
}
