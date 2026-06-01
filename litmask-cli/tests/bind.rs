//! Integration smoke test for `litmask bind`. Outcome-
//! classification branches (`NotFound` / `Ambiguous` /
//! `DecryptionFailed` / `SaltInvalid` / `ConfigMalformed` /
//! `UnsupportedFormat` / `UnsupportedCipher` / `Success`) live in
//! the `bind::tests` unit tests; the §1.7.7 step ordering is
//! pinned in `bind::tests::commit_sequence_matches_atomic_rename_protocol`.
//! This file just confirms the wiring — args parsing, file I/O,
//! stdout, atomic-commit execute — survives end-to-end as a real
//! subprocess.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use litmask_internal::{
    CipherId, FormatVersion, HEADER_LEN, KEY_LEN, NONCE_LEN, WRAPPER_BODY_LEN, WRAPPER_LEN,
    base64url,
};
use tempfile::TempDir;

fn cli_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_litmask"))
}

fn build_test_wrapper(
    cipher_id: CipherId,
    unlock_key: &[u8; KEY_LEN],
    mask_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; WRAPPER_LEN] {
    let body =
        litmask_internal::aead_encrypt(cipher_id, unlock_key, nonce, mask_key).expect("encrypt");
    let body: &[u8; WRAPPER_BODY_LEN] = body.as_slice().try_into().expect("WRAPPER_BODY_LEN");
    litmask_internal::assemble_wrapper(FormatVersion::CURRENT, cipher_id, nonce, body)
}

#[test]
fn end_to_end_happy_path_rebinds_wrapper_and_updates_config() {
    let dir = TempDir::new().expect("tempdir");
    let binary_path = dir.path().join("binary");
    let config_path = dir.path().join("litmask.config");
    let unlock = [0xAAu8; KEY_LEN];
    let mask = [0xBBu8; KEY_LEN];
    let nonce = [0xCCu8; NONCE_LEN];
    let wrapper = build_test_wrapper(CipherId::ChaCha20Poly1305, &unlock, &mask, &nonce);
    let locator: [u8; NONCE_LEN] = wrapper[..NONCE_LEN].try_into().unwrap();

    let mut bytes = vec![0u8; 64];
    bytes.extend_from_slice(&wrapper);
    bytes.extend(vec![0u8; 64]);
    fs::write(&binary_path, &bytes).expect("write binary");
    fs::write(
        &config_path,
        format!(
            "# fixture\nunlock_key = \"{}\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
            base64url::encode(&unlock),
            base64url::encode(&locator),
        ),
    )
    .expect("write config");

    let out = Command::new(cli_binary())
        .args([
            "bind",
            binary_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn cli");
    assert_eq!(
        out.status.code(),
        Some(0),
        "exit 0 expected; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    // The atomic-commit step actually wrote new bytes. Decrypt
    // the rebound wrapper under the new unlock_key from the new
    // config — recovers the original mask_key.
    let new_config = fs::read_to_string(&config_path).expect("read rebound config");
    let table: toml::Table = new_config.parse().expect("parse rebound config");
    let new_unlock_b64 = table.get("unlock_key").unwrap().as_str().unwrap();
    let new_unlock_bytes = base64url::decode(new_unlock_b64).expect("decode unlock_key");
    let new_unlock: [u8; KEY_LEN] = new_unlock_bytes.try_into().unwrap();

    let binary_after = fs::read(&binary_path).expect("read rebound binary");
    let locator_matches = binary_after
        .windows(NONCE_LEN)
        .filter(|w| *w == locator)
        .count();
    assert_eq!(locator_matches, 1, "locator must appear exactly once");
    let offset = binary_after
        .windows(NONCE_LEN)
        .position(|w| w == locator)
        .expect("locator preserved across rebind");
    let new_wrapper = &binary_after[offset..offset + WRAPPER_LEN];
    let recovered = litmask_internal::aead_decrypt(
        CipherId::ChaCha20Poly1305,
        &new_unlock,
        &nonce,
        &new_wrapper[HEADER_LEN..],
    )
    .expect("decrypt under rebound unlock_key");
    assert_eq!(recovered, mask.to_vec());
}

#[test]
fn end_to_end_aes_gcm_wrapper_rebinds_successfully() {
    let dir = TempDir::new().expect("tempdir");
    let binary_path = dir.path().join("binary");
    let config_path = dir.path().join("litmask.config");
    let unlock = [0x11u8; KEY_LEN];
    let mask = [0x22u8; KEY_LEN];
    let nonce = [0x33u8; NONCE_LEN];
    let wrapper = build_test_wrapper(CipherId::Aes256Gcm, &unlock, &mask, &nonce);
    let locator: [u8; NONCE_LEN] = wrapper[..NONCE_LEN].try_into().unwrap();

    let mut bytes = vec![0u8; 64];
    bytes.extend_from_slice(&wrapper);
    bytes.extend(vec![0u8; 64]);
    fs::write(&binary_path, &bytes).expect("write binary");
    fs::write(
        &config_path,
        format!(
            "# fixture\nunlock_key = \"{}\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
            base64url::encode(&unlock),
            base64url::encode(&locator),
        ),
    )
    .expect("write config");

    let out = Command::new(cli_binary())
        .args([
            "bind",
            binary_path.to_str().unwrap(),
            "--config",
            config_path.to_str().unwrap(),
        ])
        .output()
        .expect("spawn cli");
    assert_eq!(
        out.status.code(),
        Some(0),
        "aes-gcm bind must exit 0; stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    let new_config = fs::read_to_string(&config_path).expect("read rebound config");
    let table: toml::Table = new_config.parse().expect("parse rebound config");
    let new_unlock_b64 = table.get("unlock_key").unwrap().as_str().unwrap();
    let new_unlock_bytes = base64url::decode(new_unlock_b64).expect("decode unlock_key");
    let new_unlock: [u8; KEY_LEN] = new_unlock_bytes.try_into().unwrap();

    let binary_after = fs::read(&binary_path).expect("read rebound binary");
    let offset = binary_after
        .windows(NONCE_LEN)
        .position(|w| w == locator)
        .expect("locator preserved across rebind");
    let new_wrapper = &binary_after[offset..offset + WRAPPER_LEN];
    let recovered = litmask_internal::aead_decrypt(
        CipherId::Aes256Gcm,
        &new_unlock,
        &nonce,
        &new_wrapper[HEADER_LEN..],
    )
    .expect("decrypt aes-gcm under rebound unlock_key");
    assert_eq!(recovered, mask.to_vec());
}

#[test]
fn end_to_end_not_found_exits_66_and_describes_to_stderr() {
    let dir = TempDir::new().expect("tempdir");
    let binary_path = dir.path().join("binary");
    let config_path = dir.path().join("litmask.config");
    let unlock = [0xAAu8; KEY_LEN];
    let locator = [0xCDu8; NONCE_LEN];

    fs::write(&binary_path, vec![0u8; 1024]).expect("write binary");
    fs::write(
        &config_path,
        format!(
            "unlock_key = \"{}\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
            base64url::encode(&unlock),
            base64url::encode(&locator),
        ),
    )
    .expect("write config");

    let out = Command::new(cli_binary())
        .args([
            "bind",
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
        stderr.contains("litmask wrapper") && stderr.contains(binary_path.to_str().unwrap()),
        "stderr should name the missing wrapper and the binary path, got: {stderr}"
    );
}

#[test]
fn end_to_end_missing_arguments_exit_64() {
    let out = Command::new(cli_binary())
        .arg("bind")
        .output()
        .expect("spawn cli");
    assert_eq!(out.status.code(), Some(64));
}
