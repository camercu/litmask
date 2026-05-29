//! `litmask-cli bind` subcommand.
//!
//! `bind` decrypts using the current config's `unlock_key` (from
//! any provider) and re-encrypts under a hardware-derived key. The
//! updated config records this new key, so `EnvVarProvider` callers
//! can relay it through the environment variable without switching
//! to `HardwareIdProvider`.
//!
//! Functional core / imperative shell split:
//!
//! 1. **Plan ([`plan_bind`]):** pure function over (config text,
//!    binary bytes, salt, machine id). Returns a [`BindOutcome`].
//!    The `Success` variant carries the exact new binary bytes +
//!    new config text the commit step will write — atomicity is
//!    structurally enforced because the shell cannot start writing
//!    until the plan succeeds.
//!
//! 2. **Commit ([`commit`]):** writes the plan's payload to disk
//!    via the [`CommitFs`] trait using the POSIX atomic-rename
//!    protocol (write tempfile → fsync → rename). The trait seam
//!    lets tests inject failures and verify ordering without
//!    touching the filesystem.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use litmask_internal::scan::{LocateOutcome, locate_wrapper};
use litmask_internal::{
    CIPHER_AES_256_GCM, CIPHER_CHACHA20_POLY1305, CIPHER_OFFSET, CipherId, FORMAT_V1, HEADER_LEN,
    HW_ID_DERIVATION_CONTEXT, KEY_LEN, NONCE_LEN, NONCE_OFFSET, TAG_LEN, VERSION_OFFSET,
    WRAPPER_LEN, base64url,
};
use zeroize::Zeroizing;

/// Outcome of [`plan_bind`]. The `Success` variant carries the new
/// bytes the shell will write; every other variant is a typed
/// classification of "what went wrong" that the shell renders to
/// stdout + exit code.
#[derive(Debug)]
pub(crate) enum BindOutcome {
    /// Bind plan succeeded. `Commit` carries the payload for
    /// [`commit`].
    Success(Commit),
    /// Locator not present in the binary.
    NotFound,
    /// Locator appears more than once in the binary.
    Ambiguous,
    /// AEAD authentication failed during wrapper decryption.
    DecryptionFailed,
    /// Wrapper carries a cipher byte the dispatcher does not
    /// support.
    UnsupportedCipher,
    /// Wrapper carries an unknown format-version byte.
    UnsupportedFormat,
    /// `--salt <BASE64URL>` argument was not valid base64url.
    SaltInvalid,
    /// `litmask.config` does not parse, or lacks
    /// `unlock_key` / `locator` of the right shape.
    ConfigMalformed,
}

/// Payload of `BindOutcome::Success`: everything the commit step
/// needs to perform the atomic write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Commit {
    pub(crate) new_binary_bytes: Vec<u8>,
    pub(crate) new_config_text: String,
}

impl BindOutcome {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::Success(_) => 0,
            Self::Ambiguous
            | Self::DecryptionFailed
            | Self::UnsupportedCipher
            | Self::UnsupportedFormat => 65,
            Self::NotFound => 66,
            Self::SaltInvalid | Self::ConfigMalformed => 64,
        }
    }

    /// Stdout tag. `None` means "the shell prints a
    /// stderr message instead" (Salt/Config errors are operator-
    /// input problems that warrant a usage message, not a
    /// machine-parseable stdout tag).
    // `match_same_arms` would collapse `Success` and the
    // SaltInvalid/ConfigMalformed pair because both return None.
    // Keep them as separate arms — the variants are conceptually
    // distinct (Success carries the commit payload; the others
    // are operator-input errors handled at the shell layer with
    // stderr messages) and a future change to either branch
    // should not have to disentangle the other.
    #[allow(clippy::match_same_arms)]
    pub(crate) fn stdout_tag(&self) -> Option<&'static str> {
        match self {
            Self::Success(_) => None,
            Self::NotFound => Some("not_found"),
            Self::Ambiguous => Some("ambiguous"),
            Self::DecryptionFailed => Some("decryption_failed"),
            Self::UnsupportedCipher => Some("unsupported_cipher"),
            Self::UnsupportedFormat => Some("unsupported_format"),
            Self::SaltInvalid | Self::ConfigMalformed => None,
        }
    }
}

/// Pure functional core for `bind`. Takes all I/O results as
/// inputs (config text, binary bytes, salt arg, machine id) and
/// returns the typed outcome. No I/O, no globals, deterministic.
pub(crate) fn plan_bind(
    config_text: &str,
    binary_bytes: &[u8],
    salt_b64: Option<&str>,
    machine_id: &str,
) -> BindOutcome {
    let Ok(salt) = decode_salt(salt_b64) else {
        return BindOutcome::SaltInvalid;
    };
    let Ok(parsed_config) = crate::config::parse(config_text) else {
        return BindOutcome::ConfigMalformed;
    };

    let offsets = match locate_wrapper(binary_bytes, &parsed_config.locator) {
        LocateOutcome::Found(o) => o,
        LocateOutcome::None => return BindOutcome::NotFound,
        LocateOutcome::Ambiguous => return BindOutcome::Ambiguous,
    };
    let offset = offsets[0];
    let Ok(wrapper): Result<[u8; WRAPPER_LEN], _> =
        binary_bytes[offset..offset + WRAPPER_LEN].try_into()
    else {
        unreachable!(
            "locate_wrapper returned offset {offset} but slice into binary_bytes[..{}] is not WRAPPER_LEN bytes — programmer bug in litmask-cli's bind locator",
            offset + WRAPPER_LEN,
        );
    };

    if wrapper[VERSION_OFFSET] != FORMAT_V1 {
        return BindOutcome::UnsupportedFormat;
    }
    let cipher_byte = wrapper[CIPHER_OFFSET];
    if cipher_byte != CIPHER_CHACHA20_POLY1305 && cipher_byte != CIPHER_AES_256_GCM {
        return BindOutcome::UnsupportedCipher;
    }
    let nonce: [u8; NONCE_LEN] = wrapper[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN]
        .try_into()
        .expect("12-byte slice");
    let body = &wrapper[HEADER_LEN..];

    let Some(mask_key) =
        aead_decrypt_dispatch(cipher_byte, &parsed_config.unlock_key, &nonce, body)
            .filter(|p| p.len() == KEY_LEN)
    else {
        return BindOutcome::DecryptionFailed;
    };
    let mask_key: [u8; KEY_LEN] = mask_key.as_slice().try_into().expect("KEY_LEN bytes");
    let mask_key = Zeroizing::new(mask_key);

    let new_unlock_key = Zeroizing::new(litmask_internal::derive_hw_key(
        HW_ID_DERIVATION_CONTEXT,
        machine_id.as_bytes(),
        &salt,
    ));

    // Re-encrypt mask_key under the new unlock_key, reusing the
    // existing nonce. Reuse is safe: the (key, nonce) pair never
    // repeats because the key changed. `aead_encrypt_dispatch`
    // returning `None` here would be a programmer bug: we've
    // already validated `cipher_byte` against the two known
    // constants (UnsupportedCipher branch above) and the AEAD
    // implementations cannot fail for a 32-byte plaintext under
    // a valid 32-byte key + 12-byte nonce. Panic on that
    // contract violation rather than misclassify it as a
    // user-input error (`ConfigMalformed`) — operators reading
    // the diagnostic should see "this is a bug, file an issue",
    // not "fix your config".
    let new_body = aead_encrypt_dispatch(cipher_byte, &new_unlock_key, &nonce, mask_key.as_slice())
        .unwrap_or_else(|| {
            unreachable!(
                "AEAD encrypt refused a 32-byte mask_key under a validated cipher/key/nonce — programmer bug in litmask-cli's bind dispatch",
            )
        });
    assert!(
        new_body.len() == KEY_LEN + TAG_LEN,
        "AEAD encrypt returned wrong-length body: expected {} bytes, got {}",
        KEY_LEN + TAG_LEN,
        new_body.len(),
    );

    let mut new_wrapper = [0u8; WRAPPER_LEN];
    new_wrapper[VERSION_OFFSET] = FORMAT_V1;
    new_wrapper[CIPHER_OFFSET] = cipher_byte;
    new_wrapper[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN].copy_from_slice(&nonce);
    new_wrapper[HEADER_LEN..].copy_from_slice(&new_body);
    let mut new_binary_bytes = binary_bytes.to_vec();
    for &off in &offsets {
        new_binary_bytes[off..off + WRAPPER_LEN].copy_from_slice(&new_wrapper);
    }

    // Locator stays put because the nonce did — only `unlock_key`
    // rotates, so the rendered config differs from the input only
    // in its `unlock_key` field.
    let new_config_text = render_config(&new_unlock_key, &parsed_config.locator);

    BindOutcome::Success(Commit {
        new_binary_bytes,
        new_config_text,
    })
}

fn decode_salt(salt_b64: Option<&str>) -> Result<Vec<u8>, ()> {
    match salt_b64 {
        None => Ok(Vec::new()),
        Some(s) => base64url::decode(s).map_err(|_| ()),
    }
}

fn aead_decrypt_dispatch(
    cipher_byte: u8,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    body: &[u8],
) -> Option<Vec<u8>> {
    let cipher_id = CipherId::try_from(cipher_byte).ok()?;
    litmask_internal::aead_decrypt(cipher_id, key, nonce, body).ok()
}

fn aead_encrypt_dispatch(
    cipher_byte: u8,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    let cipher_id = CipherId::try_from(cipher_byte).ok()?;
    litmask_internal::aead_encrypt(cipher_id, key, nonce, plaintext).ok()
}

fn render_config(unlock_key: &[u8; KEY_LEN], locator: &[u8; NONCE_LEN]) -> String {
    format!(
        "# litmask.config — bound by litmask-cli.\n\
         # SECRET: contains the runtime `unlock_key` for this build. Do not commit.\n\
         # This file is written by litmask-cli's bind step; the binary's embedded wrapper has\n\
         # been re-encrypted under the new unlock_key recorded below.\n\n{}",
        litmask_internal::render_config_fields(unlock_key, locator),
    )
}

/// Filesystem operations required by the atomic commit protocol.
///
/// Default methods cover the platform-agnostic operations
/// (`write_file`, `sync_file`, `copy_permissions`, `remove_file`).
/// Platform-specific impls override only `rename` and
/// `sync_dir_best_effort` — e.g. [`WindowsCommitFs`] uses
/// `MoveFileExW(MOVEFILE_WRITE_THROUGH)` for the rename step.
///
/// Tests inject a recording double (`RecordingCommitFs`) that
/// overrides every method for failure-injection and sequence
/// verification without touching the filesystem.
pub(crate) trait CommitFs {
    fn write_file(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;
        f.write_all(bytes)
    }

    // Windows `FlushFileBuffers` requires a write-capable handle;
    // `File::open` (read-only) returns `ACCESS_DENIED`. Opening
    // with `.write(true)` without `.truncate(true)` is safe.
    fn sync_file(&self, path: &Path) -> io::Result<()> {
        let f = fs::OpenOptions::new().write(true).open(path)?;
        f.sync_all()
    }

    fn copy_permissions(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::set_permissions(to, fs::metadata(from)?.permissions())
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()>;
    fn sync_dir_best_effort(&self, path: &Path);

    fn remove_file(&self, path: &Path) {
        let _ = fs::remove_file(path);
    }
}

/// POSIX [`CommitFs`]: `std::fs::rename` provides atomic
/// same-filesystem replacement; directory fsync ensures durability.
#[cfg_attr(windows, allow(dead_code))]
pub(crate) struct StdCommitFs;

impl CommitFs for StdCommitFs {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        fs::rename(from, to)
    }

    fn sync_dir_best_effort(&self, path: &Path) {
        if let Ok(dir) = fs::File::open(path) {
            let _ = dir.sync_all();
        }
    }
}

/// Windows [`CommitFs`] using `MoveFileExW` with
/// `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` for the rename
/// step. `WRITE_THROUGH` flushes the directory entry
/// to disk before returning, which subsumes the POSIX directory-fsync
/// step — `sync_dir_best_effort` is a no-op.
#[cfg(windows)]
pub(crate) struct WindowsCommitFs;

#[cfg(windows)]
impl CommitFs for WindowsCommitFs {
    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        win_rename_write_through(from, to)
    }

    fn sync_dir_best_effort(&self, _path: &Path) {}
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn win_rename_write_through(from: &Path, to: &Path) -> io::Result<()> {
    use std::os::windows::ffi::OsStrExt;

    const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

    unsafe extern "system" {
        fn MoveFileExW(
            lpExistingFileName: *const u16,
            lpNewFileName: *const u16,
            dwFlags: u32,
        ) -> i32;
    }

    fn to_wide(path: &Path) -> Vec<u16> {
        path.as_os_str()
            .encode_wide()
            .chain(core::iter::once(0))
            .collect()
    }

    let from_wide = to_wide(from);
    let to_wide = to_wide(to);
    let flags = MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH;
    // SAFETY: `MoveFileExW` is a stable Windows API. Both wide-string
    // pointers are null-terminated, heap-allocated, and live for the
    // duration of the call.
    let ret = unsafe { MoveFileExW(from_wide.as_ptr(), to_wide.as_ptr(), flags) };
    if ret == 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Atomically commit the bind payload to disk. Follows the
/// write-tempfile → fsync → rename protocol; same-dir tempfiles
/// ensure `rename(2)` stays atomic on POSIX.
///
/// On rename failure the orphaned tempfile is best-effort cleaned
/// up before returning the error.
pub(crate) fn commit(
    binary_path: &Path,
    config_path: &Path,
    payload: &Commit,
    commit_fs: &dyn CommitFs,
) -> io::Result<()> {
    let temp_config = tempfile_alongside(config_path);
    let temp_binary = tempfile_alongside(binary_path);

    commit_fs.write_file(&temp_config, payload.new_config_text.as_bytes())?;
    commit_fs.sync_file(&temp_config)?;

    commit_fs.write_file(&temp_binary, &payload.new_binary_bytes)?;
    commit_fs.copy_permissions(binary_path, &temp_binary)?;
    commit_fs.sync_file(&temp_binary)?;

    // Crash before this rename leaves both originals intact (retryable).
    if let Err(e) = commit_fs.rename(&temp_binary, binary_path) {
        commit_fs.remove_file(&temp_binary);
        commit_fs.remove_file(&temp_config);
        return Err(e);
    }

    // Crash between the two renames leaves new binary + old config
    // (inconsistent but documented; recovery = rebind).
    if let Err(e) = commit_fs.rename(&temp_config, config_path) {
        commit_fs.remove_file(&temp_config);
        return Err(e);
    }

    // Fsync parent directories so renames survive crash.
    if let Some(bin_parent) = binary_path.parent() {
        commit_fs.sync_dir_best_effort(bin_parent);
        match config_path.parent() {
            Some(cfg_parent) if cfg_parent != bin_parent => {
                commit_fs.sync_dir_best_effort(cfg_parent);
            }
            _ => {}
        }
    } else if let Some(cfg_parent) = config_path.parent() {
        commit_fs.sync_dir_best_effort(cfg_parent);
    }

    Ok(())
}

/// Build a tempfile path alongside `target` so `rename(2)` stays
/// atomic. Encoding the PID into the name avoids collision between
/// concurrent `bind` invocations targeting the same config.
fn tempfile_alongside(target: &Path) -> PathBuf {
    let parent = target.parent().unwrap_or_else(|| Path::new("."));
    let name = match target.file_name() {
        Some(n) => n.to_string_lossy().into_owned(),
        None => "litmask.config".to_string(),
    };
    parent.join(format!(".{}.bind-{}.tmp", name, std::process::id()))
}

/// Re-sign the binary with an ad-hoc signature on macOS.
///
/// `bind` patches the binary in-place, which invalidates any existing
/// code signature. On ARM64 macOS the kernel kills unsigned binaries
/// (SIGKILL). Warns to stderr on failure but does not abort — the
/// bind itself succeeded and the user may re-sign manually.
#[cfg(target_os = "macos")]
fn resign_macos(binary_path: &Path) {
    let result = std::process::Command::new("codesign")
        .args(["-s", "-", "-f"])
        .arg(binary_path)
        .stdout(std::process::Stdio::null())
        .output();
    match result {
        Ok(output) if output.status.success() => {}
        Ok(output) => {
            let code = output
                .status
                .code()
                .map_or("(signal)".to_string(), |c| c.to_string());
            eprintln!(
                "warning: codesign exited {code} — the bound binary may not run on ARM64 macOS"
            );
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.is_empty() {
                eprint!("{stderr}");
            }
        }
        Err(e) => {
            eprintln!(
                "warning: codesign not found ({e}) — the bound binary may not run on ARM64 macOS"
            );
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn resign_macos(_binary_path: &Path) {}

/// Shell-layer failure shapes. These cover the I/O that happens
/// outside the pure planner (file reads, machine-uid lookup, the
/// atomic commit). Each maps to a specific exit code at the CLI
/// top level.
#[derive(Debug)]
pub(crate) enum ShellError {
    ConfigUnreadable,
    BinaryUnreadable,
    HardwareIdUnavailable,
    CommitFailed(io::Error),
}

impl ShellError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::ConfigUnreadable => "config file is missing or unreadable".to_string(),
            Self::BinaryUnreadable => "target binary is missing or unreadable".to_string(),
            Self::HardwareIdUnavailable => "hardware_id_unavailable".to_string(),
            Self::CommitFailed(e) => format!("commit failed: {e}"),
        }
    }
}

/// Imperative shell entry point. Reads files + machine-uid, calls
/// [`plan_bind`], and on success commits the payload atomically.
pub(crate) fn run(
    binary_path: &Path,
    config_path: &Path,
    salt_b64: Option<&str>,
) -> Result<BindOutcome, ShellError> {
    let config_text = fs::read_to_string(config_path).map_err(|_| ShellError::ConfigUnreadable)?;
    let binary_bytes = fs::read(binary_path).map_err(|_| ShellError::BinaryUnreadable)?;
    let machine_id = machine_uid::get().map_err(|_| ShellError::HardwareIdUnavailable)?;

    let outcome = plan_bind(&config_text, &binary_bytes, salt_b64, &machine_id);

    if let BindOutcome::Success(payload) = &outcome {
        #[cfg(windows)]
        let commit_fs: &dyn CommitFs = &WindowsCommitFs;
        #[cfg(not(windows))]
        let commit_fs: &dyn CommitFs = &StdCommitFs;
        commit(binary_path, config_path, payload, commit_fs).map_err(ShellError::CommitFailed)?;
        resign_macos(binary_path);
    } else if let Some(tag) = outcome.stdout_tag() {
        println!("{tag}");
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    const MACHINE_ID_FIXTURE: &str = "fixed-test-machine-id";

    fn build_wrapper(
        unlock_key: &[u8; KEY_LEN],
        mask_key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        cipher_byte: u8,
    ) -> [u8; WRAPPER_LEN] {
        let body =
            aead_encrypt_dispatch(cipher_byte, unlock_key, nonce, mask_key).expect("encrypt");
        assert_eq!(body.len(), KEY_LEN + TAG_LEN);
        let mut out = [0u8; WRAPPER_LEN];
        out[VERSION_OFFSET] = FORMAT_V1;
        out[CIPHER_OFFSET] = cipher_byte;
        out[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN].copy_from_slice(nonce);
        out[HEADER_LEN..].copy_from_slice(&body);
        out
    }

    fn config_text(unlock_key: &[u8; KEY_LEN], locator: &[u8; NONCE_LEN]) -> String {
        format!(
            "# fixture\nunlock_key = \"{}\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
            base64url::encode(unlock_key),
            base64url::encode(locator),
        )
    }

    fn binary_with(wrapper: &[u8; WRAPPER_LEN], copies: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; 64];
        for _ in 0..copies {
            bytes.extend_from_slice(wrapper);
            bytes.extend(b"padding-between-wrappers-padding".repeat(2));
        }
        bytes.extend(vec![0u8; 64]);
        bytes
    }

    fn locator_of(wrapper: &[u8; WRAPPER_LEN]) -> [u8; NONCE_LEN] {
        wrapper[..NONCE_LEN].try_into().unwrap()
    }

    // ── plan_bind: outcome classification ────────────────────

    #[test]
    fn plan_bind_success_returns_commit_with_new_binary_and_config() {
        let unlock = [0xAAu8; KEY_LEN];
        let mask = [0xBBu8; KEY_LEN];
        let nonce = [0xCCu8; NONCE_LEN];
        let wrapper = build_wrapper(&unlock, &mask, &nonce, CIPHER_CHACHA20_POLY1305);
        let locator = locator_of(&wrapper);
        let cfg = config_text(&unlock, &locator);
        let binary = binary_with(&wrapper, 1);

        let outcome = plan_bind(&cfg, &binary, None, MACHINE_ID_FIXTURE);
        let BindOutcome::Success(commit) = outcome else {
            panic!("expected Success, got {outcome:?}");
        };
        // Same length: in-place patch preserves binary size.
        assert_eq!(commit.new_binary_bytes.len(), binary.len());
        // The new config contains a different unlock_key.
        assert!(commit.new_config_text.contains("unlock_key = "));
        let new_table: toml::Table = commit.new_config_text.parse().unwrap();
        let new_unlock_b64 = new_table.get("unlock_key").unwrap().as_str().unwrap();
        let new_unlock_bytes = base64url::decode(new_unlock_b64).unwrap();
        let new_unlock: [u8; KEY_LEN] = new_unlock_bytes.try_into().unwrap();
        assert_ne!(new_unlock, unlock, "bind must rotate the unlock_key");

        // Round-trip: the new wrapper in new_binary_bytes decrypts
        // under the new unlock_key to recover the original mask_key.
        let offset = commit
            .new_binary_bytes
            .windows(NONCE_LEN)
            .position(|w| w == locator)
            .expect("locator preserved");
        let new_wrapper = &commit.new_binary_bytes[offset..offset + WRAPPER_LEN];
        let recovered = aead_decrypt_dispatch(
            CIPHER_CHACHA20_POLY1305,
            &new_unlock,
            &nonce,
            &new_wrapper[HEADER_LEN..],
        )
        .expect("decrypt under new unlock_key");
        assert_eq!(recovered, mask.to_vec());
    }

    #[test]
    fn plan_bind_not_found_when_locator_absent() {
        let cfg = config_text(&[0u8; KEY_LEN], &[0xCDu8; NONCE_LEN]);
        let binary = vec![0u8; 1024];
        assert!(matches!(
            plan_bind(&cfg, &binary, None, MACHINE_ID_FIXTURE),
            BindOutcome::NotFound,
        ));
    }

    #[test]
    fn plan_bind_succeeds_with_identical_duplicate_wrappers() {
        let unlock = [0xAAu8; KEY_LEN];
        let mask = [0xBBu8; KEY_LEN];
        let nonce = [0xCCu8; NONCE_LEN];
        let wrapper = build_wrapper(&unlock, &mask, &nonce, CIPHER_CHACHA20_POLY1305);
        let cfg = config_text(&unlock, &locator_of(&wrapper));
        let binary = binary_with(&wrapper, 2);

        let outcome = plan_bind(&cfg, &binary, None, MACHINE_ID_FIXTURE);
        let BindOutcome::Success(commit) = outcome else {
            panic!("expected Success for identical duplicates, got {outcome:?}");
        };
        assert_eq!(commit.new_binary_bytes.len(), binary.len());
    }

    #[test]
    fn plan_bind_ambiguous_when_wrappers_differ() {
        let unlock = [0xAAu8; KEY_LEN];
        let nonce = [0xCCu8; NONCE_LEN];
        let wrapper_a = build_wrapper(
            &unlock,
            &[0xBBu8; KEY_LEN],
            &nonce,
            CIPHER_CHACHA20_POLY1305,
        );
        let wrapper_b = build_wrapper(
            &unlock,
            &[0xDDu8; KEY_LEN],
            &nonce,
            CIPHER_CHACHA20_POLY1305,
        );
        let locator = locator_of(&wrapper_a);
        assert_eq!(locator, locator_of(&wrapper_b));
        let cfg = config_text(&unlock, &locator);
        let mut binary = vec![0u8; 64];
        binary.extend_from_slice(&wrapper_a);
        binary.extend(vec![0u8; 64]);
        binary.extend_from_slice(&wrapper_b);
        binary.extend(vec![0u8; 64]);
        assert!(matches!(
            plan_bind(&cfg, &binary, None, MACHINE_ID_FIXTURE),
            BindOutcome::Ambiguous,
        ));
    }

    #[test]
    fn plan_bind_decryption_failed_under_wrong_unlock_key() {
        let unlock = [0xAAu8; KEY_LEN];
        let wrong = [0x99u8; KEY_LEN];
        let mask = [0xBBu8; KEY_LEN];
        let nonce = [0xCCu8; NONCE_LEN];
        let wrapper = build_wrapper(&unlock, &mask, &nonce, CIPHER_CHACHA20_POLY1305);
        let cfg = config_text(&wrong, &locator_of(&wrapper));
        let binary = binary_with(&wrapper, 1);
        assert!(matches!(
            plan_bind(&cfg, &binary, None, MACHINE_ID_FIXTURE),
            BindOutcome::DecryptionFailed,
        ));
    }

    #[test]
    fn plan_bind_unsupported_format_when_header_byte_is_unknown() {
        let unlock = [0xAAu8; KEY_LEN];
        let mask = [0xBBu8; KEY_LEN];
        let nonce = [0xCCu8; NONCE_LEN];
        let mut wrapper = build_wrapper(&unlock, &mask, &nonce, CIPHER_CHACHA20_POLY1305);
        wrapper[VERSION_OFFSET] = 0x99;
        let cfg = config_text(&unlock, &locator_of(&wrapper));
        let binary = binary_with(&wrapper, 1);
        assert!(matches!(
            plan_bind(&cfg, &binary, None, MACHINE_ID_FIXTURE),
            BindOutcome::UnsupportedFormat,
        ));
    }

    #[test]
    fn plan_bind_unsupported_cipher_when_cipher_byte_is_unknown() {
        let unlock = [0xAAu8; KEY_LEN];
        let mask = [0xBBu8; KEY_LEN];
        let nonce = [0xCCu8; NONCE_LEN];
        let mut wrapper = build_wrapper(&unlock, &mask, &nonce, CIPHER_CHACHA20_POLY1305);
        wrapper[CIPHER_OFFSET] = 0x77; // neither 0x01 nor 0x02
        let cfg = config_text(&unlock, &locator_of(&wrapper));
        let binary = binary_with(&wrapper, 1);
        assert!(matches!(
            plan_bind(&cfg, &binary, None, MACHINE_ID_FIXTURE),
            BindOutcome::UnsupportedCipher,
        ));
    }

    #[test]
    fn plan_bind_succeeds_under_aes_gcm_wrapper() {
        // §2.9.1.6: the dispatcher must accept either cipher byte
        // and round-trip the wrapper under that cipher.
        let unlock = [0x11u8; KEY_LEN];
        let mask = [0x22u8; KEY_LEN];
        let nonce = [0x33u8; NONCE_LEN];
        let wrapper = build_wrapper(&unlock, &mask, &nonce, CIPHER_AES_256_GCM);
        let cfg = config_text(&unlock, &locator_of(&wrapper));
        let binary = binary_with(&wrapper, 1);
        let outcome = plan_bind(&cfg, &binary, None, MACHINE_ID_FIXTURE);
        assert!(
            matches!(outcome, BindOutcome::Success(_)),
            "aes-gcm wrapper must round-trip, got {outcome:?}",
        );
    }

    #[test]
    fn plan_bind_salt_invalid_when_arg_not_base64url() {
        let cfg = config_text(&[0u8; KEY_LEN], &[0u8; NONCE_LEN]);
        let outcome = plan_bind(&cfg, &[], Some("not valid base64!!"), MACHINE_ID_FIXTURE);
        assert!(matches!(outcome, BindOutcome::SaltInvalid));
    }

    #[test]
    fn plan_bind_config_malformed_when_unlock_key_missing() {
        let cfg = "locator = \"AAAAAAAAAAAAAAAA\"\nlength = 62\n";
        let outcome = plan_bind(cfg, &[0u8; 1024], None, MACHINE_ID_FIXTURE);
        assert!(matches!(outcome, BindOutcome::ConfigMalformed));
    }

    #[test]
    fn plan_bind_config_malformed_when_locator_wrong_length() {
        let too_long = [0xCDu8; 16];
        let cfg = format!(
            "unlock_key = \"{}\"\nlocator = \"{}\"\n",
            base64url::encode(&[0u8; KEY_LEN]),
            base64url::encode(&too_long),
        );
        let outcome = plan_bind(&cfg, &[0u8; 1024], None, MACHINE_ID_FIXTURE);
        assert!(matches!(outcome, BindOutcome::ConfigMalformed));
    }

    #[test]
    fn plan_bind_different_salts_produce_different_unlock_keys() {
        let unlock = [0xAAu8; KEY_LEN];
        let mask = [0xBBu8; KEY_LEN];
        let nonce = [0xCCu8; NONCE_LEN];
        let wrapper = build_wrapper(&unlock, &mask, &nonce, CIPHER_CHACHA20_POLY1305);
        let cfg = config_text(&unlock, &locator_of(&wrapper));
        let binary = binary_with(&wrapper, 1);

        let salt_a = base64url::encode(b"salt-A");
        let salt_b = base64url::encode(b"salt-B");
        let BindOutcome::Success(a) = plan_bind(&cfg, &binary, Some(&salt_a), MACHINE_ID_FIXTURE)
        else {
            panic!()
        };
        let BindOutcome::Success(b) = plan_bind(&cfg, &binary, Some(&salt_b), MACHINE_ID_FIXTURE)
        else {
            panic!()
        };
        assert_ne!(
            a.new_config_text, b.new_config_text,
            "different salts must yield different unlock_keys",
        );
    }

    // ── BindOutcome.exit_code / stdout_tag pairings ────────────

    #[test]
    fn outcome_exit_codes_match_spec_2_9_1_3() {
        let dummy_commit = Commit {
            new_binary_bytes: vec![],
            new_config_text: String::new(),
        };
        assert_eq!(BindOutcome::Success(dummy_commit).exit_code(), 0);
        assert_eq!(BindOutcome::NotFound.exit_code(), 66);
        assert_eq!(BindOutcome::Ambiguous.exit_code(), 65);
        assert_eq!(BindOutcome::DecryptionFailed.exit_code(), 65);
        assert_eq!(BindOutcome::UnsupportedCipher.exit_code(), 65);
        assert_eq!(BindOutcome::UnsupportedFormat.exit_code(), 65);
        assert_eq!(BindOutcome::SaltInvalid.exit_code(), 64);
        assert_eq!(BindOutcome::ConfigMalformed.exit_code(), 64);
    }

    #[test]
    fn outcome_stdout_tags_match_spec_2_9_1_3() {
        assert_eq!(BindOutcome::NotFound.stdout_tag(), Some("not_found"));
        assert_eq!(BindOutcome::Ambiguous.stdout_tag(), Some("ambiguous"));
        assert_eq!(
            BindOutcome::DecryptionFailed.stdout_tag(),
            Some("decryption_failed"),
        );
        assert_eq!(
            BindOutcome::UnsupportedCipher.stdout_tag(),
            Some("unsupported_cipher"),
        );
        assert_eq!(
            BindOutcome::UnsupportedFormat.stdout_tag(),
            Some("unsupported_format"),
        );
        assert_eq!(BindOutcome::SaltInvalid.stdout_tag(), None);
        assert_eq!(BindOutcome::ConfigMalformed.stdout_tag(), None);
    }

    // ── commit: end-to-end on real filesystem (StdCommitFs) ────

    #[test]
    fn commit_writes_binary_and_config_atomically() {
        let dir = tempfile::TempDir::new().unwrap();
        let binary = dir.path().join("binary");
        let config = dir.path().join("litmask.config");
        fs::write(&binary, b"old binary contents").unwrap();
        fs::write(&config, b"old config contents").unwrap();

        let payload = Commit {
            new_binary_bytes: b"new binary contents".to_vec(),
            new_config_text: "new config contents".to_string(),
        };
        commit(&binary, &config, &payload, &StdCommitFs).expect("commit should succeed");

        assert_eq!(fs::read(&binary).unwrap(), b"new binary contents");
        assert_eq!(fs::read(&config).unwrap(), b"new config contents");
        let remaining: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(remaining.len(), 2);
    }

    // ── commit: RecordingCommitFs (ordering + failure injection) ──

    use std::cell::RefCell;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FsCall {
        WriteFile(PathBuf),
        SyncFile(PathBuf),
        CopyPermissions { from: PathBuf, to: PathBuf },
        Rename { from: PathBuf, to: PathBuf },
        SyncDirBestEffort(PathBuf),
        RemoveFile(PathBuf),
    }

    struct RecordingCommitFs {
        calls: RefCell<Vec<FsCall>>,
        fail_at_call: Option<usize>,
    }

    impl RecordingCommitFs {
        fn new() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_at_call: None,
            }
        }

        fn failing_at(call_index: usize) -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                fail_at_call: Some(call_index),
            }
        }

        fn calls(&self) -> Vec<FsCall> {
            self.calls.borrow().clone()
        }

        fn maybe_fail(&self) -> io::Result<()> {
            let idx = self.calls.borrow().len() - 1;
            if self.fail_at_call == Some(idx) {
                Err(io::Error::other("injected failure"))
            } else {
                Ok(())
            }
        }
    }

    impl CommitFs for RecordingCommitFs {
        fn write_file(&self, path: &Path, _bytes: &[u8]) -> io::Result<()> {
            self.calls
                .borrow_mut()
                .push(FsCall::WriteFile(path.to_path_buf()));
            self.maybe_fail()
        }

        fn sync_file(&self, path: &Path) -> io::Result<()> {
            self.calls
                .borrow_mut()
                .push(FsCall::SyncFile(path.to_path_buf()));
            self.maybe_fail()
        }

        fn copy_permissions(&self, from: &Path, to: &Path) -> io::Result<()> {
            self.calls.borrow_mut().push(FsCall::CopyPermissions {
                from: from.to_path_buf(),
                to: to.to_path_buf(),
            });
            self.maybe_fail()
        }

        fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
            self.calls.borrow_mut().push(FsCall::Rename {
                from: from.to_path_buf(),
                to: to.to_path_buf(),
            });
            self.maybe_fail()
        }

        fn sync_dir_best_effort(&self, path: &Path) {
            self.calls
                .borrow_mut()
                .push(FsCall::SyncDirBestEffort(path.to_path_buf()));
        }

        fn remove_file(&self, path: &Path) {
            self.calls
                .borrow_mut()
                .push(FsCall::RemoveFile(path.to_path_buf()));
        }
    }

    fn test_payload() -> Commit {
        Commit {
            new_binary_bytes: b"binary".to_vec(),
            new_config_text: "config".to_string(),
        }
    }

    #[test]
    fn commit_sequence_matches_atomic_rename_protocol() {
        let fs = RecordingCommitFs::new();
        commit(Path::new("/bin"), Path::new("/cfg"), &test_payload(), &fs)
            .expect("no failures injected");
        let calls = fs.calls();
        assert_eq!(calls.len(), 8);
        assert!(matches!(&calls[0], FsCall::WriteFile(p) if p != Path::new("/cfg")));
        assert!(matches!(&calls[1], FsCall::SyncFile(_)));
        assert!(matches!(&calls[2], FsCall::WriteFile(p) if p != Path::new("/bin")));
        assert!(matches!(&calls[3], FsCall::CopyPermissions { .. }));
        assert!(matches!(&calls[4], FsCall::SyncFile(_)));
        assert!(matches!(&calls[5], FsCall::Rename { to, .. } if to == Path::new("/bin")));
        assert!(matches!(&calls[6], FsCall::Rename { to, .. } if to == Path::new("/cfg")));
        assert!(matches!(&calls[7], FsCall::SyncDirBestEffort(_)));
    }

    #[test]
    fn commit_tempfiles_share_parent_with_targets() {
        let fs = RecordingCommitFs::new();
        commit(
            Path::new("/x/binary"),
            Path::new("/x/litmask.config"),
            &test_payload(),
            &fs,
        )
        .expect("no failures injected");
        let calls = fs.calls();
        let write_parents: Vec<_> = calls
            .iter()
            .filter_map(|c| match c {
                FsCall::WriteFile(p) => p.parent().map(Path::to_path_buf),
                _ => None,
            })
            .collect();
        let rename_parents: Vec<_> = calls
            .iter()
            .filter_map(|c| match c {
                FsCall::Rename { to, .. } => to.parent().map(Path::to_path_buf),
                _ => None,
            })
            .collect();
        for (w, r) in write_parents.iter().zip(&rename_parents) {
            assert_eq!(
                w, r,
                "tempfile and target must share parent for atomic rename"
            );
        }
    }

    #[test]
    fn commit_deduplicates_parent_fsync_when_same_dir() {
        let fs = RecordingCommitFs::new();
        commit(
            Path::new("/x/bin"),
            Path::new("/x/cfg"),
            &test_payload(),
            &fs,
        )
        .expect("no failures injected");
        let fsync_count = fs
            .calls()
            .iter()
            .filter(|c| matches!(c, FsCall::SyncDirBestEffort(_)))
            .count();
        assert_eq!(fsync_count, 1);
    }

    #[test]
    fn commit_fsyncs_both_parents_when_different_dirs() {
        let fs = RecordingCommitFs::new();
        commit(
            Path::new("/a/bin"),
            Path::new("/b/cfg"),
            &test_payload(),
            &fs,
        )
        .expect("no failures injected");
        let fsync_dirs: Vec<_> = fs
            .calls()
            .iter()
            .filter(|c| matches!(c, FsCall::SyncDirBestEffort(_)))
            .cloned()
            .collect();
        assert_eq!(fsync_dirs.len(), 2);
        assert!(matches!(&fsync_dirs[0], FsCall::SyncDirBestEffort(p) if p == Path::new("/a")));
        assert!(matches!(&fsync_dirs[1], FsCall::SyncDirBestEffort(p) if p == Path::new("/b")));
    }

    #[test]
    fn commit_fsyncs_only_config_parent_when_binary_has_no_parent() {
        let fs = RecordingCommitFs::new();
        commit(Path::new(""), Path::new("/x/cfg"), &test_payload(), &fs)
            .expect("no failures injected");
        let fsync_dirs: Vec<_> = fs
            .calls()
            .iter()
            .filter_map(|c| match c {
                FsCall::SyncDirBestEffort(p) => Some(p.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(fsync_dirs, vec![PathBuf::from("/x")]);
    }

    #[rstest]
    #[case::config_write(0, 1)]
    #[case::binary_write(2, 3)]
    #[case::binary_fsync(4, 5)]
    fn commit_failure_before_rename_stops_early(
        #[case] fail_at: usize,
        #[case] expected_calls: usize,
    ) {
        let fs = RecordingCommitFs::failing_at(fail_at);
        commit(Path::new("/bin"), Path::new("/cfg"), &test_payload(), &fs).unwrap_err();
        let calls = fs.calls();
        assert_eq!(calls.len(), expected_calls);
        assert!(!calls.iter().any(|c| matches!(c, FsCall::Rename { .. })));
    }

    #[rstest]
    #[case::binary_rename(5, 2)]
    #[case::config_rename(6, 1)]
    fn commit_rename_failure_cleans_up_tempfiles(
        #[case] fail_at: usize,
        #[case] expected_removals: usize,
    ) {
        let fs = RecordingCommitFs::failing_at(fail_at);
        commit(Path::new("/bin"), Path::new("/cfg"), &test_payload(), &fs).unwrap_err();
        let removals = fs
            .calls()
            .iter()
            .filter(|c| matches!(c, FsCall::RemoveFile(_)))
            .count();
        assert_eq!(
            removals, expected_removals,
            "must clean up all orphaned tempfiles after rename failure",
        );
    }
}
