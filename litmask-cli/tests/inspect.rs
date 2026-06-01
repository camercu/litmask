//! Integration smoke test for `litmask inspect`. The branch
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
    // config that points at it. Padded to WRAPPER_LEN so
    // locate_wrapper accepts the match.
    let mut bytes = b"prefix-padding-".to_vec();
    bytes.extend_from_slice(LOCATOR);
    bytes.extend(vec![0u8; WRAPPER_LEN - NONCE_LEN]);
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
    assert!(
        stdout.contains("verified"),
        "stdout should confirm verification, got: {stdout}"
    );
}

#[test]
fn end_to_end_aes_gcm_wrapper_inspects_as_verified() {
    let dir = TempDir::new().expect("tempdir");
    let binary_path = dir.path().join("binary");
    let config_path = dir.path().join("litmask.config");

    let locator: [u8; NONCE_LEN] = *b"AESLOCTR-012";
    let mut bytes = b"prefix-padding-".to_vec();
    bytes.extend_from_slice(&locator);
    bytes.extend(vec![0u8; WRAPPER_LEN - NONCE_LEN]);
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
    assert!(
        stdout.contains("verified"),
        "stdout should confirm verification, got: {stdout}"
    );
}

#[test]
fn end_to_end_not_found_exits_66_and_describes_to_stderr() {
    let dir = TempDir::new().expect("tempdir");
    let binary_path = dir.path().join("binary");
    let config_path = dir.path().join("litmask.config");

    fs::write(&binary_path, vec![0u8; 1024]).expect("write binary");
    fs::write(
        &config_path,
        format!(
            "unlock_key = \"placeholder\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
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
    assert_eq!(out.status.code(), Some(66));
    let stdout = String::from_utf8(out.stdout).expect("utf-8 stdout");
    assert!(
        stdout.trim().is_empty(),
        "diagnostics go to stderr, not stdout"
    );
    let stderr = String::from_utf8(out.stderr).expect("utf-8 stderr");
    assert!(
        stderr.contains("no litmask wrapper") && stderr.contains(binary_path.to_str().unwrap()),
        "stderr should name the missing wrapper and the binary path, got: {stderr}"
    );
}

#[test]
fn end_to_end_missing_arguments_exit_64() {
    let out = Command::new(cli_binary())
        .arg("inspect")
        .output()
        .expect("spawn cli");
    assert_eq!(out.status.code(), Some(64));
}
