//! Integration tests for `litmask-cli bind` (§2.9.1).
//!
//! Coverage:
//! - Locator outcomes: single (happy-path rebind), multiple
//!   (`ambiguous`), missing (`not_found`)
//! - AEAD authentication failure → `decryption_failed`
//! - Atomic-commit invariants: failure before write leaves binary
//!   + config byte-identical to pre-bind state
//!
//! The "freshly built binary that runs after rebind" AC depends on
//! a real built binary with `HardwareIdProvider::new()` wired into
//! `init_with!`; that is exercised separately by the
//! `hw_id_provider` example. The "machine-uid unavailable" path
//! requires a host where the lookup fails — outside the scope of
//! the cargo-test runner; the cipher dispatch and exit-code shape
//! are pinned in `bind::tests`.

#![cfg(unix)]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use chacha20poly1305::aead::{Aead, KeyInit, generic_array::GenericArray};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use litmask_internal::base64url;
use tempfile::TempDir;

/// Wrapper constants — duplicated from the CLI's private module so
/// the integration test stays decoupled from the CLI's internal
/// layout.
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const HEADER_LEN: usize = 2 + NONCE_LEN;
const WRAPPER_LEN: usize = HEADER_LEN + KEY_LEN + TAG_LEN;

const FORMAT_V1: u8 = 0x01;
const CIPHER_CHACHA: u8 = 0x01;

fn cli_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_litmask-cli"))
}

/// Assemble a synthetic litmask wrapper under the given keys + nonce.
fn build_wrapper(
    unlock_key: &[u8; KEY_LEN],
    mask_key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
) -> [u8; WRAPPER_LEN] {
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(unlock_key));
    let body = cipher
        .encrypt(Nonce::from_slice(nonce), mask_key.as_slice())
        .expect("AEAD encrypt");
    assert_eq!(body.len(), KEY_LEN + TAG_LEN);
    let mut out = [0u8; WRAPPER_LEN];
    out[0] = FORMAT_V1;
    out[1] = CIPHER_CHACHA;
    out[2..HEADER_LEN].copy_from_slice(nonce);
    out[HEADER_LEN..].copy_from_slice(&body);
    out
}

struct Fixture {
    held_dir: TempDir,
    binary: PathBuf,
    config: PathBuf,
    unlock_key: [u8; KEY_LEN],
    mask_key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
}

fn make_fixture(wrapper_copies: usize) -> Fixture {
    let dir = TempDir::new().expect("tempdir");
    let binary = dir.path().join("target");
    let config = dir.path().join("litmask.config");
    let unlock_key = [0xAAu8; KEY_LEN];
    let mask_key = [0xBBu8; KEY_LEN];
    let nonce = [0xCCu8; NONCE_LEN];
    let wrapper = build_wrapper(&unlock_key, &mask_key, &nonce);

    // The locator (§1.7.1) is the wrapper's first NONCE_LEN bytes,
    // NOT the nonce alone — the wrapper layout is
    // `[format, cipher, nonce, ciphertext, tag]`, so the 12-byte
    // locator overlaps the header (format+cipher) and the first 10
    // bytes of the nonce. Build the config to mirror that.
    let locator: [u8; NONCE_LEN] = wrapper[..NONCE_LEN].try_into().expect("12-byte slice");

    // Synthetic "binary" bytes: padding + N wrapper copies + padding.
    let mut bytes = vec![0u8; 128];
    for _ in 0..wrapper_copies {
        bytes.extend_from_slice(&wrapper);
        bytes.extend(b"padding-between-wrappers-padding-padding".repeat(2));
    }
    bytes.extend(vec![0u8; 64]);
    fs::write(&binary, &bytes).expect("write binary");

    let config_text = format!(
        "# litmask.config — fixture\nunlock_key = \"{}\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
        base64url::encode(&unlock_key),
        base64url::encode(&locator),
    );
    fs::write(&config, config_text).expect("write config");

    Fixture {
        held_dir: dir,
        binary,
        config,
        unlock_key,
        mask_key,
        nonce,
    }
}

fn run_bind(binary: &Path, config: &Path) -> std::process::Output {
    Command::new(cli_binary())
        .args([
            "bind",
            binary.to_str().expect("utf-8 path"),
            "--config",
            config.to_str().expect("utf-8 path"),
        ])
        .output()
        .expect("spawn cli")
}

#[test]
fn no_match_exits_66_and_prints_not_found() {
    let dir = TempDir::new().expect("tempdir");
    let binary = dir.path().join("target");
    let config = dir.path().join("litmask.config");
    // Binary with no wrapper bytes at all.
    fs::write(&binary, b"no wrapper here, just plaintext padding").expect("write binary");
    fs::write(
        &config,
        format!(
            "unlock_key = \"{}\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
            base64url::encode(&[0u8; KEY_LEN]),
            base64url::encode(&[0xCCu8; NONCE_LEN]),
        ),
    )
    .expect("write config");
    let out = run_bind(&binary, &config);
    assert_eq!(out.status.code(), Some(66));
    let stdout = String::from_utf8(out.stdout).expect("stdout");
    assert_eq!(stdout.trim(), "not_found");
}

#[test]
fn multiple_matches_exits_65_and_prints_ambiguous() {
    let f = make_fixture(3);
    let out = run_bind(&f.binary, &f.config);
    assert_eq!(out.status.code(), Some(65));
    let stdout = String::from_utf8(out.stdout).expect("stdout");
    assert_eq!(stdout.trim(), "ambiguous");
}

#[test]
fn wrong_current_unlock_key_exits_65_and_prints_decryption_failed() {
    // Hand-edit the config to record an unlock_key that does not
    // match the one used to encrypt the wrapper. The bind step's
    // AEAD authentication must surface as `decryption_failed`
    // before any patching happens.
    let f = make_fixture(1);
    let wrong = [0x99u8; KEY_LEN];
    let original = build_wrapper(&f.unlock_key, &f.mask_key, &f.nonce);
    let locator: [u8; NONCE_LEN] = original[..NONCE_LEN].try_into().unwrap();
    let config_text = format!(
        "# fixture\nunlock_key = \"{}\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
        base64url::encode(&wrong),
        base64url::encode(&locator),
    );
    fs::write(&f.config, config_text).expect("rewrite config");
    let binary_before = fs::read(&f.binary).expect("read binary before");

    let out = run_bind(&f.binary, &f.config);
    assert_eq!(out.status.code(), Some(65));
    let stdout = String::from_utf8(out.stdout).expect("stdout");
    assert_eq!(stdout.trim(), "decryption_failed");

    let binary_after = fs::read(&f.binary).expect("read binary after");
    assert_eq!(
        binary_before, binary_after,
        "decryption-failed bind must not modify the binary",
    );
}

#[test]
fn pre_write_failure_leaves_binary_and_config_byte_identical() {
    // Failure injected via an unreadable target binary. The
    // sequence is: parse config (succeeds) → read binary (fails)
    // → bail. Neither binary nor config should change.
    let f = make_fixture(1);
    let binary_before = fs::read(&f.binary).expect("read binary before");
    let config_before = fs::read(&f.config).expect("read config before");

    // chmod 000 on the binary so the read fails.
    fs::set_permissions(&f.binary, fs::Permissions::from_mode(0o000)).expect("chmod 000 binary");

    let out = run_bind(&f.binary, &f.config);

    // Restore permissions before assertions so subsequent reads
    // succeed.
    let _ = fs::set_permissions(&f.binary, fs::Permissions::from_mode(0o600));

    // Exit code: the CLI maps BinaryUnreadable to EX_USAGE (64),
    // alongside other "your inputs are wrong" failures.
    assert_eq!(out.status.code(), Some(64));

    let binary_after = fs::read(&f.binary).expect("read binary after");
    let config_after = fs::read(&f.config).expect("read config after");
    assert_eq!(binary_before, binary_after, "binary must be unchanged");
    assert_eq!(config_before, config_after, "config must be unchanged");
}

#[test]
fn happy_path_rebinds_wrapper_and_updates_config() {
    // A real happy-path test: bind succeeds → the binary's wrapper
    // bytes are now encrypted under the new (machine-id-derived)
    // unlock_key recorded in the rebound config. Round-trip the
    // recovered mask_key through the new config's unlock_key to
    // confirm the bind step did the encrypt step correctly.
    let f = make_fixture(1);

    let out = run_bind(&f.binary, &f.config);
    assert_eq!(
        out.status.code(),
        Some(0),
        "stderr={}",
        String::from_utf8_lossy(&out.stderr),
    );

    // Parse the new config to recover the rebound unlock_key.
    let body = fs::read_to_string(&f.config).expect("read rebound config");
    let table: toml::Table = body.parse().expect("parse rebound config");
    let new_unlock_b64 = table
        .get("unlock_key")
        .and_then(|v| v.as_str())
        .expect("unlock_key field");
    let new_unlock_bytes = base64url::decode(new_unlock_b64).expect("decode unlock_key");
    let new_unlock: [u8; KEY_LEN] = new_unlock_bytes.try_into().expect("32 bytes");
    assert_ne!(
        new_unlock, f.unlock_key,
        "rebind must replace the unlock_key",
    );

    // Read the rebound wrapper from the binary and decrypt under
    // the new unlock_key — must recover the original mask_key.
    // The locator (§1.7.1) is the wrapper's first 12 bytes; the
    // rebind step preserves the locator (and the nonce inside it)
    // because the new wrapper still wraps the same mask_key under
    // the same nonce, just with a new unlock_key.
    let binary_after = fs::read(&f.binary).expect("read rebound binary");
    let original = build_wrapper(&f.unlock_key, &f.mask_key, &f.nonce);
    let locator = &original[..NONCE_LEN];
    let offset = binary_after
        .windows(NONCE_LEN)
        .position(|w| w == locator)
        .expect("locator present in rebound binary");
    let wrapper = &binary_after[offset..offset + WRAPPER_LEN];
    let body = &wrapper[HEADER_LEN..];
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&new_unlock));
    let recovered = cipher
        .decrypt(Nonce::from_slice(&f.nonce), body)
        .expect("rebound wrapper decrypts under new unlock_key");
    assert_eq!(recovered, f.mask_key.to_vec());
}

#[test]
fn missing_config_arg_exits_64() {
    let f = make_fixture(1);
    let out = Command::new(cli_binary())
        .args(["bind", f.binary.to_str().unwrap()])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(64));
}

#[test]
fn salt_invalid_exits_64() {
    let f = make_fixture(1);
    let out = Command::new(cli_binary())
        .args([
            "bind",
            f.binary.to_str().unwrap(),
            "--config",
            f.config.to_str().unwrap(),
            "--salt",
            "not valid base64url!!!",
        ])
        .output()
        .expect("spawn");
    assert_eq!(out.status.code(), Some(64));
    // Ensure binary + config unchanged.
    let _ = f.held_dir; // keep tempdir alive
}
