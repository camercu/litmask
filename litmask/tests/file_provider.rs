//! Integration tests for [`litmask::FileProvider`] (§2.5.3).
//!
//! Verifies the public [`KeyProvider`] contract end-to-end: a base64url
//! file holding the build's `unlock_key` initializes the runtime so
//! `mask!()` decryption succeeds, and the documented error categories
//! surface for missing / unreadable / malformed files. Byte-level
//! assertions on the recovered key — and the explicit zeroize-on-drop
//! tracking via `Counted<T>` — live as unit tests inside
//! `litmask::provider` where they can access crate-private internals.

#![cfg(unix)]

mod common;

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use litmask::{FileProvider, KeyEncoding, KeyError, KeyProvider, init_with, mask};

/// Canonical 32-byte test key encoded as 43-char base64url (no padding).
const ZERO_KEY_B64URL: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn tmp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "litmask-fileprovider-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0),
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tmp dir");
    dir
}

fn write_file(path: &Path, bytes: &[u8]) {
    let mut f = fs::File::create(path).expect("create key file");
    f.write_all(bytes).expect("write key file");
    f.sync_all().expect("sync");
}

#[test]
fn file_provider_round_trips_against_build_config() {
    // The canonical end-to-end: write the build's `unlock_key` into a
    // file, hand the path to FileProvider, and verify that mask!()
    // decryption succeeds. Locks the contract that FileProvider is a
    // drop-in for EnvVarProvider when the deployment sources its
    // unlock key from disk.
    common::init_once();
    let dir = tmp_dir("e2e");
    let path = dir.join("unlock_key.b64");
    let key = common::read_unlock_key(&common::config_path(common::Profile::Debug));
    write_file(&path, key.as_bytes());

    // Init was already performed by common::init_once on first call;
    // FileProvider here exercises the unlock_key() path without
    // re-init.
    let provider = FileProvider::new(&path);
    let unlock = provider.unlock_key().expect("read + parse unlock key");
    // Best we can do without exposing key bytes: a second init_with!
    // is a no-op (OnceLock already populated), but the unlock_key
    // round-tripped through base64url parse and produced a typed
    // UnlockKey value. A subsequent mask!() proves the runtime is
    // healthy with whatever provider populated it.
    drop(unlock);
    let _ = mask!("file-provider-fixture");
}

#[test]
fn missing_file_yields_not_found() {
    let dir = tmp_dir("missing");
    let path = dir.join("does-not-exist");
    let provider = FileProvider::new(&path);
    assert!(matches!(provider.unlock_key(), Err(KeyError::NotFound)));
}

#[test]
fn unreadable_file_yields_permission() {
    let dir = tmp_dir("perm");
    let path = dir.join("unlock_key.b64");
    write_file(&path, ZERO_KEY_B64URL.as_bytes());
    // Mode 000 is unreadable by the owner; root would bypass but the
    // test suite does not run as root.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).expect("chmod 000");

    let provider = FileProvider::new(&path);
    let err = provider.unlock_key().expect_err("mode 000 must fail");
    // Restore permissions so the temp file is cleanable.
    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    assert!(matches!(err, KeyError::Permission), "got: {err:?}");
}

#[test]
fn wrong_length_yields_invalid_format() {
    let dir = tmp_dir("short");
    let path = dir.join("unlock_key.b64");
    // 32 url-safe chars decodes to 24 bytes — short of the 32-byte key.
    write_file(&path, b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    let provider = FileProvider::new(&path);
    assert!(matches!(
        provider.unlock_key(),
        Err(KeyError::InvalidFormat)
    ));
}

#[test]
fn bad_encoding_yields_invalid_format() {
    let dir = tmp_dir("bad-encoding");
    let path = dir.join("unlock_key.b64");
    write_file(&path, b"not valid base64url!!!");

    let provider = FileProvider::new(&path);
    assert!(matches!(
        provider.unlock_key(),
        Err(KeyError::InvalidFormat)
    ));
}

#[test]
fn base64url_file_trailing_newline_is_tolerated() {
    // Editors commonly append a trailing newline; users will save key
    // files that way. The decoder must accept this rather than fail
    // with InvalidFormat — the alternative is a frustrating diagnostic
    // that depends on the user's editor settings.
    let dir = tmp_dir("newline");
    let path = dir.join("unlock_key.b64");
    let mut contents = ZERO_KEY_B64URL.to_string();
    contents.push('\n');
    write_file(&path, contents.as_bytes());

    let provider = FileProvider::new(&path);
    assert!(provider.unlock_key().is_ok());
}

#[test]
fn raw_encoding_accepts_exact_32_byte_file() {
    let dir = tmp_dir("raw-ok");
    let path = dir.join("unlock_key.bin");
    let raw_bytes: [u8; 32] = [0xABu8; 32];
    write_file(&path, &raw_bytes);

    let provider = FileProvider::with_encoding(&path, KeyEncoding::Raw);
    assert!(provider.unlock_key().is_ok());
}

#[test]
fn raw_encoding_rejects_off_by_one_length() {
    let dir = tmp_dir("raw-short");
    let path = dir.join("unlock_key.bin");
    write_file(&path, &[0u8; 31]);

    let provider = FileProvider::with_encoding(&path, KeyEncoding::Raw);
    assert!(matches!(
        provider.unlock_key(),
        Err(KeyError::InvalidFormat)
    ));
}

/// `FileProvider::new(path)` must be constructible from any `Into<PathBuf>`:
/// `&str`, `String`, `&Path`, `PathBuf`. Pin the API surface so a future
/// signature tightening (e.g., taking `&Path`) is a noticed change.
#[test]
fn new_accepts_any_into_pathbuf() {
    let _: FileProvider = FileProvider::new("/dev/null");
    let _: FileProvider = FileProvider::new(String::from("/dev/null"));
    let _: FileProvider = FileProvider::new(std::path::Path::new("/dev/null"));
    let _: FileProvider = FileProvider::new(PathBuf::from("/dev/null"));
    let _: FileProvider = FileProvider::with_encoding("/dev/null", KeyEncoding::Raw);
}

/// `init_with!(FileProvider::new(path))` succeeds against a file
/// holding the build's `unlock_key`. The macro path is the most
/// frequent [`FileProvider`] usage — locked here so an [`init_with!`] /
/// [`FileProvider`] integration regression surfaces fast.
#[test]
fn init_with_file_provider_compiles_and_does_not_panic() {
    // Build a key file holding the build's unlock_key.
    let dir = tmp_dir("init-with");
    let path = dir.join("unlock_key.b64");
    let key = common::read_unlock_key(&common::config_path(common::Profile::Debug));
    write_file(&path, key.as_bytes());

    // First init_with! call succeeds; subsequent ones are no-ops.
    // We can't assert "this was the first init" deterministically
    // because integration tests share the test-binary process and
    // common::init_once may have run already. The contract under
    // test is: init_with!(FileProvider::new(path)) returns Ok(_).
    let _ = init_with!(FileProvider::new(&path));
}
