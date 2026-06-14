//! End-to-end integration test for the `hello_world` example.
//!
//! Builds the example, scans its binary with `strings` for absence of
//! the masked Franklin fixture, then runs it (the keyless Embedded tier
//! self-initializes, so no key is supplied) and asserts the decrypted
//! output matches the fixture.

mod common;

use common::Profile;
use std::process::Command;

// Must match the string `hello_world` prints — this test builds and
// runs that example and asserts its stdout equals `FIXTURE`.
const FIXTURE: &str = "Three may keep a secret, if two of them are dead. — Benjamin Franklin";

/// Substring of the fixture that is lexically unusual enough to make
/// false-positive matches against std / dependency text effectively
/// impossible.
const FIXTURE_SUBSTRING: &str = "if two of them are dead";

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

    // End-to-end runtime check: the Embedded example self-initializes on
    // its first mask!() and prints the recovered fixture to stdout.
    let run_output = Command::new(&example_bin)
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
