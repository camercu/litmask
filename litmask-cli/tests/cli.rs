//! End-to-end tests for the `litmask` binary's observable contract:
//! exit codes and the stdout/stderr split. The pure cores (`encode_key`,
//! `report_machine_id`) are unit-tested in `main.rs`; these exercise the
//! imperative shell (`main`, `dispatch_*`) that unit tests cannot reach —
//! spawning the real binary is the only way to pin the exit code and the
//! stdout-vs-stderr routing that callers pipe against.

use std::process::{Command, Output};

/// Run the built `litmask` binary with `args` and capture its output.
/// `CARGO_BIN_EXE_litmask` is set by cargo for integration tests, so this
/// needs no `assert_cmd` dependency.
fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_litmask"))
        .args(args)
        .output()
        .expect("spawn litmask binary")
}

#[test]
fn keygen_prints_a_key_to_stdout_and_exits_ok() {
    let out = run(&["keygen"]);
    assert_eq!(out.status.code(), Some(0), "keygen must exit 0");

    let stdout = String::from_utf8(out.stdout).expect("keygen stdout is utf8");
    let key = stdout.trim_end();
    // 32 bytes → 43 unpadded base64url chars (mirrors the unit test), on
    // stdout so `litmask keygen | …` captures exactly the key.
    assert_eq!(key.len(), 43, "keygen key is 43 base64url chars: {key:?}");
    assert!(
        !key.contains('='),
        "keygen output must be unpadded: {key:?}"
    );
    assert!(out.stderr.is_empty(), "keygen writes nothing to stderr");
}

#[test]
fn help_flag_exits_success() {
    // `--help` must exit 0, not the `EX_USAGE` (64) that a genuine
    // argument error gets — `main` special-cases clap's DisplayHelp kind.
    let out = run(&["--help"]);
    assert_eq!(out.status.code(), Some(0), "--help must exit 0");
}

#[test]
fn version_flag_exits_success() {
    let out = run(&["--version"]);
    assert_eq!(out.status.code(), Some(0), "--version must exit 0");
}

#[test]
fn unknown_subcommand_exits_usage() {
    // A parse failure is routed through the sysexits `EX_USAGE` (64),
    // not clap's default 2.
    let out = run(&["definitely-not-a-command"]);
    assert_eq!(out.status.code(), Some(64), "bad subcommand exits 64");
}

#[test]
fn show_machine_id_never_exits_silently() {
    // Robust to whether the host exposes a machine id: the contract is a
    // token on stdout (exit 0) *or* an error on stderr (exit 69) — never
    // a silent success. A stubbed `dispatch_show_machine_id` (exit 0 with
    // no output) satisfies neither arm, so this pins the routing without
    // depending on machine-id availability.
    let out = run(&["show-machine-id"]);
    match out.status.code() {
        Some(0) => assert!(
            !out.stdout.is_empty(),
            "a successful show-machine-id emits the token on stdout"
        ),
        Some(69) => {
            assert!(out.stdout.is_empty(), "a failed lookup leaves stdout clean");
            assert!(
                !out.stderr.is_empty(),
                "a failed lookup explains itself on stderr"
            );
        }
        other => panic!("show-machine-id must exit 0 or 69, got {other:?}"),
    }
}
