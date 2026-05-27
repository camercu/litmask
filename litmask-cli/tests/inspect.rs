//! Integration smoke test for `litmask-cli inspect`. The branch
//! coverage for every outcome ([`Verified`] / [`NotFound`] /
//! [`Ambiguous`] / [`ConfigMalformed`]) lives in the
//! `inspect::tests` unit tests; this file exists only to confirm
//! the wiring — args parsing, file I/O, stdout, and exit code —
//! survives end-to-end as a real subprocess.
//!
//! [`Verified`]: # "inspect::Outcome::Verified"
//! [`NotFound`]: # "inspect::Outcome::NotFound"
//! [`Ambiguous`]: # "inspect::Outcome::Ambiguous"
//! [`ConfigMalformed`]: # "inspect::Outcome::ConfigMalformed"

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use litmask_internal::{NONCE_LEN, WRAPPER_LEN, base64url};
use tempfile::TempDir;

const LOCATOR: &[u8; NONCE_LEN] = b"LITMASK-LOCT";

fn cli_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_litmask"))
}

#[test]
fn end_to_end_single_match_exits_zero_and_prints_verified() {
    let dir = TempDir::new().expect("tempdir");
    let binary_path = dir.path().join("binary");
    let config_path = dir.path().join("litmask.config");

    // Write a binary that contains the locator exactly once + a
    // config that points at it.
    let mut bytes = b"prefix-padding-".to_vec();
    bytes.extend_from_slice(LOCATOR);
    bytes.extend_from_slice(b" suffix-padding");
    {
        let mut f = fs::File::create(&binary_path).expect("create binary");
        f.write_all(&bytes).expect("write binary");
        f.sync_all().expect("sync");
    }
    fs::write(
        &config_path,
        format!(
            "# fixture\nunlock_key = \"placeholder\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
            base64url::encode(LOCATOR),
        ),
    )
    .expect("write config");

    let out = Command::new(cli_binary())
        .args([
            "inspect",
            binary_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn cli");
    assert!(
        out.status.success(),
        "exit code expected 0; got {:?}, stderr={}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    assert_eq!(stdout.trim(), "verified");
}

#[test]
fn end_to_end_aes_gcm_wrapper_inspects_as_verified() {
    let dir = TempDir::new().expect("tempdir");
    let binary_path = dir.path().join("binary");
    let config_path = dir.path().join("litmask.config");

    let locator: [u8; NONCE_LEN] = *b"AESLOCTR-012";
    let mut bytes = b"prefix-padding-".to_vec();
    bytes.extend_from_slice(&locator);
    bytes.extend_from_slice(b" suffix-padding");
    {
        let mut f = fs::File::create(&binary_path).expect("create binary");
        f.write_all(&bytes).expect("write binary");
        f.sync_all().expect("sync");
    }
    fs::write(
        &config_path,
        format!(
            "# fixture\nunlock_key = \"placeholder\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
            base64url::encode(&locator),
        ),
    )
    .expect("write config");

    let out = Command::new(cli_binary())
        .args([
            "inspect",
            binary_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn cli");
    assert!(
        out.status.success(),
        "inspect of aes-gcm-shaped wrapper must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    assert_eq!(stdout.trim(), "verified");
}

#[test]
fn end_to_end_missing_arguments_exit_64() {
    // Confirms the args-parse → ExitCode wiring in main. Branch
    // coverage for every parse_args path is in main::tests.
    let out = Command::new(cli_binary())
        .arg("inspect")
        .output()
        .expect("spawn cli");
    assert_eq!(out.status.code(), Some(64));
}
