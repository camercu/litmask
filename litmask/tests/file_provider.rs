//! Integration tests for [`litmask::FileProvider`] (§2.5.3).
//!
//! `FileProvider` is an External-tier provider: it reads a file's bytes
//! as raw key material of any length (no encoding, no length check),
//! strips a single trailing newline, and derives the `unlock_key` via
//! the shared KDF — exactly [`UnlockKey::derive`]. These tests pin that
//! derive contract and the documented error categories for missing /
//! unreadable files. The full external-tier round-trip (a build sealed
//! under material `X`, then a `FileProvider`/`EnvVarProvider` re-deriving
//! the same key to decrypt `mask!`) lives in `external_tier_e2e.rs`,
//! which can stand up an externally-sealed build; the litmask crate's
//! own tests run against an embedded-sealed build that no external
//! provider can unlock by construction.

#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use litmask::{FileProvider, KeyError, KeyProvider, UnlockKey};

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
fn derives_canonical_unlock_key_from_file_bytes() {
    // The load-bearing contract: FileProvider delegates to the public
    // KDF over the (newline-trimmed) file bytes, so a deployment that
    // writes material to disk gets byte-identical keying to any other
    // channel feeding the same material to UnlockKey::derive.
    let dir = tmp_dir("canonical");
    let path = dir.join("material.key");
    write_file(&path, b"operator material");

    let from_file = FileProvider::new(&path)
        .unlock_key()
        .expect("derive from file");
    assert_eq!(
        from_file,
        UnlockKey::derive(litmask::UnlockMaterial::new(b"operator material").expect("non-empty"))
    );
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
    let path = dir.join("material.key");
    write_file(&path, b"any material");
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
fn file_trailing_newline_derives_same_key() {
    // A key file saved with an editor-appended trailing newline must
    // derive the same unlock_key as the bare material, so the file and
    // env channels agree on one secret regardless of editor settings.
    let dir = tmp_dir("newline");
    let bare = dir.join("bare.key");
    let newlined = dir.join("newlined.key");
    write_file(&bare, b"operator material");
    write_file(&newlined, b"operator material\n");

    let from_bare = FileProvider::new(&bare)
        .unlock_key()
        .expect("derive from bare material");
    let from_newlined = FileProvider::new(&newlined)
        .unlock_key()
        .expect("derive from newlined material");
    assert!(from_bare == from_newlined);
}

#[test]
fn any_length_material_derives_a_key() {
    // No encoding, no length constraint: file contents are raw material
    // the KDF normalizes. Distinct material derives distinct keys.
    let dir = tmp_dir("any-length");
    let short = dir.join("short.key");
    let long = dir.join("long.key");
    write_file(&short, b"x");
    write_file(&long, &[0x5au8; 4096]);

    let from_short = FileProvider::new(&short)
        .unlock_key()
        .expect("derive short");
    let from_long = FileProvider::new(&long).unlock_key().expect("derive long");
    assert!(from_short != from_long);
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
}
