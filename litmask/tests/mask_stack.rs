//! End-to-end integration test for `mask_stack!("...")` (the stack-backed
//! `MaskStr` path).
//!
//! Builds the `stack_demo` example with `--features stack`, scans its
//! binary with `strings` for absence of the masked fixture, then runs it
//! (the keyless Embedded tier self-initializes) and asserts the decrypted
//! output matches — proving the stack guard decrypts correctly and leaves
//! no plaintext in the binary.

mod common;

use common::Profile;
use std::process::Command;

// Must match the string `stack_demo` prints.
const FIXTURE: &str = "stack-resident secret: parsnip clavicle 8842";
const BYTES_FIXTURE: &str = "stack-bytes secret: rutabaga 7731";

/// High-entropy substrings that cannot false-positive against std /
/// dependency text.
const FIXTURE_SUBSTRING: &str = "parsnip clavicle 8842";
const BYTES_FIXTURE_SUBSTRING: &str = "rutabaga 7731";

#[test]
fn stack_str_and_bytes_end_to_end_round_trip() {
    common::build_example_with_features("stack_demo", Profile::Debug, &["stack"]);
    let example_bin = common::example_path("stack_demo", Profile::Debug);
    assert!(
        example_bin.exists(),
        "example binary missing: {}",
        example_bin.display()
    );

    // Security property: neither masked fixture is in the binary.
    common::assert_substring_absent(&example_bin, FIXTURE_SUBSTRING);
    common::assert_substring_absent(&example_bin, BYTES_FIXTURE_SUBSTRING);

    // Runtime check: the stack guards decrypt and deref to the fixtures.
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
    assert_eq!(stdout, format!("{FIXTURE}\n{BYTES_FIXTURE}\n"));
}
