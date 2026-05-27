//! Integration smoke test for `litmask-cli bind`. Outcome-
//! classification branches (`NotFound` / `Ambiguous` /
//! `DecryptionFailed` / `SaltInvalid` / `ConfigMalformed` /
//! `UnsupportedFormat` / `UnsupportedCipher` / `Success`) live in
//! the `bind::tests` unit tests; the §1.7.7 step ordering is
//! pinned in `bind::tests::plan_commit_emits_eight_ops_in_spec_order`.
//! This file just confirms the wiring — args parsing, file I/O,
//! stdout, atomic-commit execute — survives end-to-end as a real
//! subprocess.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::aead::{Aead, KeyInit, generic_array::GenericArray};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
// Pull the wire-format constants from `litmask-internal` rather than
// redefining them here: a future header tweak that drifts these
// values would silently break this fixture while the production
// path still matched.
use litmask_internal::{
    CipherId, FormatVersion, HEADER_LEN, KEY_LEN, NONCE_LEN, WRAPPER_LEN, base64url,
};
use tempfile::TempDir;

fn cli_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_litmask"))
}

fn build_wrapper(
    unlock_key: &[u8; KEY_LEN],
    mask_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; WRAPPER_LEN] {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(unlock_key));
    let body = cipher
        .encrypt(Nonce::from_slice(nonce), mask_key.as_slice())
        .expect("encrypt");
    let mut out = [0u8; WRAPPER_LEN];
    out[0] = FormatVersion::CURRENT.to_byte();
    out[1] = CipherId::ChaCha20Poly1305.to_byte();
    out[2..HEADER_LEN].copy_from_slice(nonce);
    out[HEADER_LEN..].copy_from_slice(&body);
    out
}

fn build_aes_gcm_wrapper(
    unlock_key: &[u8; KEY_LEN],
    mask_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; WRAPPER_LEN] {
    let cipher = Aes256Gcm::new(GenericArray::from_slice(unlock_key));
    let body = cipher
        .encrypt(AesNonce::from_slice(nonce), mask_key.as_slice())
        .expect("encrypt");
    let mut out = [0u8; WRAPPER_LEN];
    out[0] = FormatVersion::CURRENT.to_byte();
    out[1] = CipherId::Aes256Gcm.to_byte();
    out[2..HEADER_LEN].copy_from_slice(nonce);
    out[HEADER_LEN..].copy_from_slice(&body);
    out
}

#[test]
fn end_to_end_happy_path_rebinds_wrapper_and_updates_config() {
    let dir = TempDir::new().expect("tempdir");
    let binary_path = dir.path().join("binary");
    let config_path = dir.path().join("litmask.config");
    let unlock = [0xAAu8; KEY_LEN];
    let mask = [0xBBu8; KEY_LEN];
    let nonce = [0xCCu8; NONCE_LEN];
    let wrapper = build_wrapper(&unlock, &mask, &nonce);
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
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&new_unlock));
    let recovered = cipher
        .decrypt(Nonce::from_slice(&nonce), &new_wrapper[HEADER_LEN..])
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
    let wrapper = build_aes_gcm_wrapper(&unlock, &mask, &nonce);
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
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&new_unlock));
    let recovered = cipher
        .decrypt(AesNonce::from_slice(&nonce), &new_wrapper[HEADER_LEN..])
        .expect("decrypt aes-gcm under rebound unlock_key");
    assert_eq!(recovered, mask.to_vec());
}

#[test]
fn end_to_end_missing_arguments_exit_64() {
    let out = Command::new(cli_binary())
        .arg("bind")
        .output()
        .expect("spawn cli");
    assert_eq!(out.status.code(), Some(64));
}
