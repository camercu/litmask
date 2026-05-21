//! Integration tests for `litmask-cli inspect` (§2.9.2.1–§2.9.2.3).
//!
//! Each test constructs a synthetic "binary" (a byte file with
//! known content) and a `litmask.config` pointing at a 12-byte
//! locator. The CLI scans the binary for occurrences and exits per
//! the sysexits.h-aligned table in §2.9.2.3:
//!
//! | Outcome | Exit | Stdout |
//! |---|---|---|
//! | Exactly one match | 0 | `verified` |
//! | Multiple matches | 65 | `ambiguous:<count>` |
//! | No match | 66 | `not_found` |
//! | Arg-parse error | 64 | (usage message to stderr) |

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use litmask_internal::base64url;
use tempfile::TempDir;

/// The 12-byte locator we plant in every fixture. Length matches
/// the wrapper's nonce prefix (§1.7.3); content is arbitrary but
/// distinguishable.
const LOCATOR_BYTES: &[u8; 12] = b"LITMASK-LOCT";

fn cli_binary() -> PathBuf {
    // CARGO_BIN_EXE_litmask-cli is set by cargo for integration
    // tests in the same package as the binary target.
    PathBuf::from(env!("CARGO_BIN_EXE_litmask-cli"))
}

fn write_binary_with_locator_at(path: &Path, occurrences: usize) {
    // Plant the locator `occurrences` times surrounded by enough
    // padding that the byte search has to find them by content, not
    // by file offset. The padding is plain ASCII so the locator
    // bytes are the only place LITMASK appears.
    let mut bytes = Vec::with_capacity(4096);
    bytes.extend(b"ELF-like prefix padding ".repeat(8));
    for _ in 0..occurrences {
        bytes.extend(LOCATOR_BYTES);
        bytes.extend(b" padding between matches ".repeat(4));
    }
    bytes.extend(b" trailing padding ".repeat(8));
    let mut f = fs::File::create(path).expect("create binary fixture");
    f.write_all(&bytes).expect("write fixture");
    f.sync_all().expect("sync");
}

fn write_config(path: &Path, locator_b64: &str) {
    fs::write(
        path,
        format!(
            "# litmask.config — fixture\nunlock_key = \"placeholder\"\nlocator = \"{locator_b64}\"\nlength = 62\n",
        ),
    )
    .expect("write config");
}

struct InspectFixture {
    // Keep the TempDir alive for the lifetime of the fixture so the
    // tempdir is not deleted before the test reads from it. The
    // field is otherwise unused — `held_dir` reads cleanly even
    // when clippy's underscore-prefix lint forbids the more idiomatic
    // `_dir` name.
    held_dir: TempDir,
    binary: PathBuf,
    config: PathBuf,
}

fn fixture(occurrences: usize) -> InspectFixture {
    let dir = TempDir::new().expect("tempdir");
    let binary = dir.path().join("target_binary");
    let config = dir.path().join("litmask.config");
    write_binary_with_locator_at(&binary, occurrences);
    write_config(&config, &base64url::encode(LOCATOR_BYTES));
    InspectFixture {
        held_dir: dir,
        binary,
        config,
    }
}

fn run_inspect(binary: &Path, config: &Path) -> std::process::Output {
    Command::new(cli_binary())
        .args([
            "inspect",
            binary.to_str().expect("utf-8 path"),
            "--config",
            config.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("spawn cli")
}

#[test]
fn single_match_exits_zero_and_prints_verified() {
    let f = fixture(1);
    let out = run_inspect(&f.binary, &f.config);
    assert!(
        out.status.success(),
        "exit code expected 0; got {:?}, stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8(out.stdout).expect("stdout utf-8");
    assert_eq!(stdout.trim(), "verified");
}

#[test]
fn multiple_matches_exits_65_and_prints_ambiguous_count() {
    let f = fixture(3);
    let out = run_inspect(&f.binary, &f.config);
    assert_eq!(out.status.code(), Some(65));
    let stdout = String::from_utf8(out.stdout).expect("stdout utf-8");
    assert_eq!(stdout.trim(), "ambiguous:3");
}

#[test]
fn no_match_exits_66_and_prints_not_found() {
    let f = fixture(0);
    let out = run_inspect(&f.binary, &f.config);
    assert_eq!(out.status.code(), Some(66));
    let stdout = String::from_utf8(out.stdout).expect("stdout utf-8");
    assert_eq!(stdout.trim(), "not_found");
}

#[test]
fn binary_file_unchanged_after_inspect() {
    let f = fixture(1);
    let before = fs::read(&f.binary).expect("read before");
    let _ = run_inspect(&f.binary, &f.config);
    let after = fs::read(&f.binary).expect("read after");
    assert_eq!(before, after, "inspect must not modify the binary");
}

#[test]
fn arg_parse_errors_exit_64() {
    // Missing required arguments.
    let out = Command::new(cli_binary())
        .arg("inspect")
        .output()
        .expect("spawn cli");
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn unknown_subcommand_exits_64() {
    let out = Command::new(cli_binary())
        .arg("does-not-exist-subcommand")
        .output()
        .expect("spawn cli");
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn missing_config_file_exits_64() {
    let f = fixture(1);
    let nonexistent = f.held_dir.path().join("missing.config");
    let out = Command::new(cli_binary())
        .args([
            "inspect",
            f.binary.to_str().unwrap(),
            "--config",
            nonexistent.to_str().unwrap(),
        ])
        .output()
        .expect("spawn cli");
    assert_eq!(out.status.code(), Some(64));
}
