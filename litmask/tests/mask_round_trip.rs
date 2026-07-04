//! End-to-end runtime round-trip for the `hello_world` example: builds
//! it, runs it (the keyless Embedded tier self-initializes, so no key is
//! supplied), and asserts the decrypted stdout matches the fixture.
//!
//! The compile-time security property (the masked fixture being absent
//! from the binary) is owned by `example_scrub.rs` — see
//! `quote_fixtures_absent_from_canonical_examples`, which scrubs the same
//! `hello_world` fixture under the release deployment profile. This test
//! deliberately covers only the one behavior no scrub test does: actually
//! executing the binary and checking its output.

mod common;

use common::Profile;
use std::process::Command;

// Must match the string `hello_world` prints — this test builds and
// runs that example and asserts its stdout equals `FIXTURE`.
const FIXTURE: &str = "Three may keep a secret, if two of them are dead. — Benjamin Franklin";

#[test]
fn end_to_end_round_trip() {
    common::build_example("hello_world", Profile::Debug);
    let example_bin = common::example_path("hello_world", Profile::Debug);
    assert!(
        example_bin.exists(),
        "example binary missing: {}",
        example_bin.display()
    );

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
