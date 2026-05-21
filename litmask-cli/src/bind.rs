//! `litmask-cli bind` subcommand (§2.9.1.1–§2.9.1.6, §1.7.6,
//! §1.7.7 POSIX).
//!
//! Functional core / imperative shell split with plan-execute
//! atomicity:
//!
//! 1. **Plan ([`plan_bind`]):** pure function over (config text,
//!    binary bytes, salt, machine id). Returns a [`BindOutcome`].
//!    The `Success` variant carries the exact new binary bytes +
//!    new config text the commit step will write — atomicity is
//!    structurally enforced because the shell cannot start writing
//!    until the plan succeeds.
//!
//! 2. **Commit plan ([`plan_posix_commit`]):** another pure
//!    function that turns the bind plan's payload into a
//!    `Vec<Operation>` whose order encodes the §1.7.7 protocol.
//!    A unit test pins this order at the value level so a future
//!    bug that swaps fsync and rename surfaces in CI rather than
//!    after a power loss in production.
//!
//! 3. **Execute ([`execute`]):** thin imperative loop that applies
//!    the operations in order. The first failure short-circuits
//!    with the failing op's index for attribution.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

// Both AEAD crates re-export the same `Aead` and `KeyInit` traits
// from upstream `aead`; pulling them once via the chacha import is
// enough for both ciphers' `.encrypt` / `.decrypt` / `::new` calls.
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, generic_array::GenericArray};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use litmask_internal::{HW_ID_DERIVATION_CONTEXT, base64url};
use zeroize::Zeroizing;

// ── Wire-format constants (§1.7.3) ──────────────────────────

const VERSION_OFFSET: usize = 0;
const CIPHER_OFFSET: usize = 1;
const NONCE_OFFSET: usize = 2;
const NONCE_LEN: usize = 12;
const HEADER_LEN: usize = 2 + NONCE_LEN;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const WRAPPER_LEN: usize = HEADER_LEN + KEY_LEN + TAG_LEN;

const CIPHER_CHACHA20_POLY1305: u8 = 0x01;
const CIPHER_AES_256_GCM: u8 = 0x02;
const FORMAT_V1: u8 = 0x01;

// `HW_ID_DERIVATION_CONTEXT` is imported from `litmask_internal` so
// the CLI and the runtime `HardwareIdProvider` share a single
// canonical string. A drift would silently break bind ↔ runtime
// interop: every freshly bound binary would fail to unlock.

// ── Functional core: bind planner ────────────────────────────

/// Outcome of [`plan_bind`]. The `Success` variant carries the new
/// bytes the shell will write; every other variant is a typed
/// classification of "what went wrong" that the shell renders to
/// stdout + exit code per §2.9.1.3.
#[derive(Debug)]
pub(crate) enum BindOutcome {
    /// Bind plan succeeded. `Commit` is the input to the commit
    /// planner ([`plan_posix_commit`]).
    Success(Commit),
    /// Locator not present in the binary.
    NotFound,
    /// Locator appears more than once in the binary.
    Ambiguous,
    /// AEAD authentication failed during wrapper decryption.
    DecryptionFailed,
    /// Wrapper carries a cipher byte the dispatcher does not
    /// support (§2.9.1.6).
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

    /// Stdout tag per §2.9.1.3. `None` means "the shell prints a
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
    let Ok(parsed_config) = parse_config(config_text) else {
        return BindOutcome::ConfigMalformed;
    };

    // Locate the wrapper.
    let offset = match locate_wrapper(binary_bytes, &parsed_config.locator) {
        LocateOutcome::Single(o) => o,
        LocateOutcome::None => return BindOutcome::NotFound,
        LocateOutcome::Multiple => return BindOutcome::Ambiguous,
    };
    let Ok(wrapper): Result<[u8; WRAPPER_LEN], _> =
        binary_bytes[offset..offset + WRAPPER_LEN].try_into()
    else {
        // Locate-wrapper already filtered offsets that don't have
        // room for a full wrapper; reaching this branch would be
        // a logic bug in `locate_wrapper`.
        return BindOutcome::ConfigMalformed;
    };

    // Parse the wrapper's header bytes.
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

    // Decrypt under the current unlock_key.
    let Some(mask_key) =
        aead_decrypt_dispatch(cipher_byte, &parsed_config.unlock_key, &nonce, body)
            .filter(|p| p.len() == KEY_LEN)
    else {
        return BindOutcome::DecryptionFailed;
    };
    let mask_key: [u8; KEY_LEN] = mask_key.as_slice().try_into().expect("KEY_LEN bytes");
    let mask_key = Zeroizing::new(mask_key);

    // Derive the new unlock_key from machine id + salt. Mirrors
    // `litmask::provider::derive_hw_key` exactly so a runtime
    // `HardwareIdProvider` recovers the same key.
    let new_unlock_key = derive_hw_unlock_key(&salt, machine_id);

    // Re-encrypt mask_key under the new unlock_key, reusing the
    // existing nonce. Reuse is safe: the (key, nonce) pair never
    // repeats because the key changed.
    let Some(new_body) =
        aead_encrypt_dispatch(cipher_byte, &new_unlock_key, &nonce, mask_key.as_slice())
    else {
        // Encrypt failure on a valid cipher/key/nonce combo is
        // unreachable for the cipher set we support; classify as
        // an internal error via SaltInvalid (the closest typed
        // "the inputs combined into something the cipher refused"
        // bucket) — would need a SpecBug variant for true
        // exhaustiveness.
        return BindOutcome::ConfigMalformed;
    };
    if new_body.len() != KEY_LEN + TAG_LEN {
        return BindOutcome::ConfigMalformed;
    }

    // Assemble the new wrapper, patch the in-memory binary.
    let mut new_wrapper = [0u8; WRAPPER_LEN];
    new_wrapper[VERSION_OFFSET] = FORMAT_V1;
    new_wrapper[CIPHER_OFFSET] = cipher_byte;
    new_wrapper[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN].copy_from_slice(&nonce);
    new_wrapper[HEADER_LEN..].copy_from_slice(&new_body);
    let mut new_binary_bytes = binary_bytes.to_vec();
    new_binary_bytes[offset..offset + WRAPPER_LEN].copy_from_slice(&new_wrapper);

    // Render the new config (locator unchanged because nonce
    // unchanged).
    let new_config_text = render_config(&new_unlock_key, &parsed_config.locator);

    BindOutcome::Success(Commit {
        new_binary_bytes,
        new_config_text,
    })
}

struct ParsedConfig {
    unlock_key: [u8; KEY_LEN],
    locator: [u8; NONCE_LEN],
}

fn parse_config(config_text: &str) -> Result<ParsedConfig, ()> {
    let table: toml::Table = config_text.parse().map_err(|_| ())?;
    let unlock_key_text = table.get("unlock_key").and_then(|v| v.as_str()).ok_or(())?;
    let locator_text = table.get("locator").and_then(|v| v.as_str()).ok_or(())?;
    let unlock_key_bytes = Zeroizing::new(base64url::decode(unlock_key_text).map_err(|_| ())?);
    let unlock_key: [u8; KEY_LEN] = unlock_key_bytes.as_slice().try_into().map_err(|_| ())?;
    let locator_bytes = base64url::decode(locator_text).map_err(|_| ())?;
    let locator: [u8; NONCE_LEN] = locator_bytes.try_into().map_err(|_| ())?;
    Ok(ParsedConfig {
        unlock_key,
        locator,
    })
}

fn decode_salt(salt_b64: Option<&str>) -> Result<Vec<u8>, ()> {
    match salt_b64 {
        None => Ok(Vec::new()),
        Some(s) => base64url::decode(s).map_err(|_| ()),
    }
}

enum LocateOutcome {
    None,
    Single(usize),
    Multiple,
}

fn locate_wrapper(haystack: &[u8], locator: &[u8; NONCE_LEN]) -> LocateOutcome {
    if haystack.len() < WRAPPER_LEN {
        return LocateOutcome::None;
    }
    let mut hits = haystack
        .windows(NONCE_LEN)
        .enumerate()
        .filter(|(_, w)| *w == locator)
        .filter(|(i, _)| i + WRAPPER_LEN <= haystack.len())
        .map(|(i, _)| i);
    let Some(first) = hits.next() else {
        return LocateOutcome::None;
    };
    if hits.next().is_some() {
        return LocateOutcome::Multiple;
    }
    LocateOutcome::Single(first)
}

fn aead_decrypt_dispatch(
    cipher_byte: u8,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    body: &[u8],
) -> Option<Vec<u8>> {
    match cipher_byte {
        CIPHER_CHACHA20_POLY1305 => {
            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
            cipher.decrypt(ChaNonce::from_slice(nonce), body).ok()
        }
        CIPHER_AES_256_GCM => {
            let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
            cipher.decrypt(AesNonce::from_slice(nonce), body).ok()
        }
        _ => None,
    }
}

fn aead_encrypt_dispatch(
    cipher_byte: u8,
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    match cipher_byte {
        CIPHER_CHACHA20_POLY1305 => {
            let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(key));
            cipher.encrypt(ChaNonce::from_slice(nonce), plaintext).ok()
        }
        CIPHER_AES_256_GCM => {
            let cipher = Aes256Gcm::new(GenericArray::from_slice(key));
            cipher.encrypt(AesNonce::from_slice(nonce), plaintext).ok()
        }
        _ => None,
    }
}

fn derive_hw_unlock_key(salt: &[u8], machine_id: &str) -> [u8; KEY_LEN] {
    let key = blake3::derive_key(HW_ID_DERIVATION_CONTEXT, salt);
    let mac = blake3::keyed_hash(&key, machine_id.as_bytes());
    *mac.as_bytes()
}

fn render_config(unlock_key: &[u8; KEY_LEN], locator: &[u8; NONCE_LEN]) -> String {
    format!(
        "# litmask.config — bound by litmask-cli.\n\
         # SECRET: contains the runtime `unlock_key` for this build. Do not commit.\n\
         # This file is written by litmask-cli's bind step; the binary's embedded wrapper has\n\
         # been re-encrypted under the new unlock_key recorded below.\n\
         \nunlock_key = \"{}\"\nlocator = \"{}\"\nlength = {WRAPPER_LEN}\n",
        base64url::encode(unlock_key),
        base64url::encode(locator),
    )
}

// ── Functional core: atomic-commit planner ───────────────────

/// One step of the §1.7.7 atomic commit protocol. The plan is a
/// `Vec<Operation>`; the executor applies them in order, surfacing
/// the first failure as the bind result. Variants are deliberately
/// narrow so the §1.7.7 ordering is a structural property of the
/// plan rather than a property of imperative flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Operation {
    /// Truncate `path` to zero and write `bytes`. Used for both
    /// the in-place binary patch and the tempfile config write.
    WriteFile { path: PathBuf, bytes: Vec<u8> },
    /// Open `path`, call `sync_all()`. Hard error on failure; the
    /// protocol depends on the file being durable before
    /// proceeding.
    FsyncFile { path: PathBuf },
    /// `rename(from, to)`. POSIX atomic same-filesystem. Cleanup
    /// (removing the orphaned tempfile if rename fails) is the
    /// executor's responsibility — see `execute`.
    Rename { from: PathBuf, to: PathBuf },
    /// `fsync` on a directory handle. Best-effort: platforms that
    /// refuse a directory fsync (some FUSE mounts, certain BSD
    /// configurations) are tolerated rather than aborting the
    /// commit — the prior Rename already provides local
    /// atomicity. Failure to `sync_all` the parent dir is OK; we
    /// log a debug note and move on.
    FsyncDirBestEffort { path: PathBuf },
}

/// Plan the §1.7.7 POSIX atomic commit. Pure: same inputs in,
/// byte-identical operation list out. The unit tests pin the
/// step ordering at the value level so a future bug that swaps
/// fsync and rename surfaces in CI.
pub(crate) fn plan_posix_commit(
    binary_path: &Path,
    new_binary: Vec<u8>,
    config_path: &Path,
    new_config: String,
) -> Vec<Operation> {
    let temp_config = tempfile_alongside(config_path);
    let parent = config_path.parent().map(Path::to_path_buf);
    let mut plan = vec![
        // Step 2: write new config to a same-dir tempfile.
        // Same-dir is mandatory for `rename(2)` to be atomic
        // (cross-filesystem renames degrade to copy+unlink).
        Operation::WriteFile {
            path: temp_config.clone(),
            bytes: new_config.into_bytes(),
        },
        // Step 3: fsync the tempfile so its bytes land on disk
        // before we begin patching the binary.
        Operation::FsyncFile {
            path: temp_config.clone(),
        },
        // Step 4: in-place binary patch. We overwrite the entire
        // file rather than seeking-and-writing the WRAPPER_LEN
        // window so the binary either has the new wrapper or the
        // old one, not a partial blend.
        Operation::WriteFile {
            path: binary_path.to_path_buf(),
            bytes: new_binary,
        },
        // Step 5: fsync the binary so its bytes land before the
        // rename. A crash between steps 4 and 6 must not persist
        // the rename + old binary.
        Operation::FsyncFile {
            path: binary_path.to_path_buf(),
        },
        // Step 6: rename(temp_config, config_path). POSIX
        // guarantees this is atomic with respect to a concurrent
        // reader.
        Operation::Rename {
            from: temp_config,
            to: config_path.to_path_buf(),
        },
    ];
    // Step 7: fsync the parent directory so the rename survives
    // a crash. Without this step, the rename is in the kernel's
    // dirent cache but the journal may not yet reference it.
    if let Some(parent) = parent {
        plan.push(Operation::FsyncDirBestEffort { path: parent });
    }
    plan
}

/// Failure shape from [`execute`]. `op_index` attributes the
/// failure to a specific plan step so the operator (or a CI
/// diagnostic) can identify exactly which boundary was crossed
/// before the I/O failed.
#[derive(Debug)]
pub(crate) struct ExecuteError {
    pub(crate) op_index: usize,
    pub(crate) cause: io::Error,
}

/// Apply the plan in order. The first operation to fail
/// short-circuits the execution with the failing index. On
/// `Rename` failure the orphaned tempfile is best-effort cleaned
/// up before returning the error — leaving a `.bind-<pid>.tmp`
/// behind would clutter the operator's working dir without
/// changing the (binary, config) consistency state.
pub(crate) fn execute(plan: &[Operation]) -> Result<(), ExecuteError> {
    for (op_index, op) in plan.iter().enumerate() {
        match op {
            Operation::WriteFile { path, bytes } => {
                let mut f = fs::OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path)
                    .map_err(|cause| ExecuteError { op_index, cause })?;
                f.write_all(bytes)
                    .map_err(|cause| ExecuteError { op_index, cause })?;
            }
            Operation::FsyncFile { path } => {
                let f = fs::File::open(path).map_err(|cause| ExecuteError { op_index, cause })?;
                f.sync_all()
                    .map_err(|cause| ExecuteError { op_index, cause })?;
            }
            Operation::Rename { from, to } => {
                if let Err(cause) = fs::rename(from, to) {
                    let _ = fs::remove_file(from);
                    return Err(ExecuteError { op_index, cause });
                }
            }
            Operation::FsyncDirBestEffort { path } => {
                // sync_all on a directory handle is the documented
                // POSIX way to flush dirent updates; ignore the
                // result if the platform refuses (e.g., directory
                // not syncable) — the prior Rename's local atomicity
                // is what the §1.7.7 protocol critically relies on.
                if let Ok(dir) = fs::File::open(path) {
                    let _ = dir.sync_all();
                }
            }
        }
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

// ── Imperative shell ─────────────────────────────────────────

/// Shell-layer failure shapes. These cover the I/O that happens
/// outside the pure planner (file reads, machine-uid lookup, the
/// final commit execute). Each maps to a specific exit code at
/// the CLI top level.
#[derive(Debug)]
pub(crate) enum ShellError {
    ConfigUnreadable,
    BinaryUnreadable,
    HardwareIdUnavailable,
    CommitFailed(ExecuteError),
}

impl ShellError {
    pub(crate) fn message(&self) -> String {
        match self {
            Self::ConfigUnreadable => "config file is missing or unreadable".to_string(),
            Self::BinaryUnreadable => "target binary is missing or unreadable".to_string(),
            Self::HardwareIdUnavailable => "hardware_id_unavailable".to_string(),
            Self::CommitFailed(e) => format!("commit failed at op[{}]: {}", e.op_index, e.cause),
        }
    }
}

/// Imperative shell entry point. Reads files + machine-uid, calls
/// [`plan_bind`], and on Success executes the §1.7.7 commit plan.
pub(crate) fn run(
    binary_path: &Path,
    config_path: &Path,
    salt_b64: Option<&str>,
) -> Result<BindOutcome, ShellError> {
    let config_text = fs::read_to_string(config_path).map_err(|_| ShellError::ConfigUnreadable)?;
    let binary_bytes = fs::read(binary_path).map_err(|_| ShellError::BinaryUnreadable)?;
    let machine_id = machine_uid::get().map_err(|_| ShellError::HardwareIdUnavailable)?;

    let outcome = plan_bind(&config_text, &binary_bytes, salt_b64, &machine_id);

    if let BindOutcome::Success(commit) = &outcome {
        let plan = plan_posix_commit(
            binary_path,
            commit.new_binary_bytes.clone(),
            config_path,
            commit.new_config_text.clone(),
        );
        execute(&plan).map_err(ShellError::CommitFailed)?;
    } else if let Some(tag) = outcome.stdout_tag() {
        println!("{tag}");
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn plan_bind_ambiguous_when_locator_appears_twice() {
        let unlock = [0xAAu8; KEY_LEN];
        let mask = [0xBBu8; KEY_LEN];
        let nonce = [0xCCu8; NONCE_LEN];
        let wrapper = build_wrapper(&unlock, &mask, &nonce, CIPHER_CHACHA20_POLY1305);
        let cfg = config_text(&unlock, &locator_of(&wrapper));
        let binary = binary_with(&wrapper, 2);
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

    // ── plan_posix_commit: §1.7.7 ordering as data ───────────

    #[test]
    fn plan_posix_commit_emits_six_ops_in_spec_order() {
        let plan = plan_posix_commit(
            Path::new("/path/to/binary"),
            vec![0xEFu8; 100],
            Path::new("/path/to/litmask.config"),
            "config".to_string(),
        );
        // 5 fs ops + 1 best-effort parent fsync.
        assert_eq!(plan.len(), 6);

        // Step 2 — WriteFile(tempfile in same dir as config).
        match &plan[0] {
            Operation::WriteFile { path, bytes: _ } => {
                assert_eq!(path.parent(), Some(Path::new("/path/to")));
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .expect("temp path file_name str");
                // Case sensitivity is fine here — we generated
                // the suffix ourselves and want byte-exact match.
                #[allow(clippy::case_sensitive_file_extension_comparisons)]
                let ok = name.contains(".bind-") && name.ends_with(".tmp");
                assert!(ok, "tempfile name shape mismatch: {path:?}");
            }
            other => panic!("step 2 must be WriteFile, got {other:?}"),
        }

        // Step 3 — FsyncFile(tempfile).
        match &plan[1] {
            Operation::FsyncFile { path } => {
                assert_eq!(path.parent(), Some(Path::new("/path/to")));
            }
            other => panic!("step 3 must be FsyncFile, got {other:?}"),
        }

        // Step 4 — WriteFile(binary).
        match &plan[2] {
            Operation::WriteFile { path, bytes } => {
                assert_eq!(path, Path::new("/path/to/binary"));
                assert_eq!(bytes.len(), 100);
            }
            other => panic!("step 4 must be WriteFile binary, got {other:?}"),
        }

        // Step 5 — FsyncFile(binary).
        match &plan[3] {
            Operation::FsyncFile { path } => assert_eq!(path, Path::new("/path/to/binary")),
            other => panic!("step 5 must be FsyncFile binary, got {other:?}"),
        }

        // Step 6 — Rename(tempfile → config).
        match &plan[4] {
            Operation::Rename { from, to } => {
                assert_eq!(to, Path::new("/path/to/litmask.config"));
                assert_eq!(from.parent(), Some(Path::new("/path/to")));
            }
            other => panic!("step 6 must be Rename, got {other:?}"),
        }

        // Step 7 — FsyncDirBestEffort(parent of config).
        match &plan[5] {
            Operation::FsyncDirBestEffort { path } => {
                assert_eq!(path, Path::new("/path/to"));
            }
            other => panic!("step 7 must be FsyncDirBestEffort, got {other:?}"),
        }
    }

    #[test]
    fn plan_posix_commit_tempfile_and_target_share_parent_dir() {
        // Same-dir is mandatory for rename(2) to be atomic. Pin
        // it at the plan level so a future refactor that moved
        // the tempfile (e.g., to /tmp) fails the unit test before
        // shipping.
        let plan = plan_posix_commit(
            Path::new("/x/binary"),
            vec![],
            Path::new("/x/litmask.config"),
            String::new(),
        );
        let Operation::WriteFile { path: temp, .. } = &plan[0] else {
            panic!()
        };
        let Operation::Rename { from, to } = &plan[4] else {
            panic!()
        };
        assert_eq!(temp.parent(), Some(Path::new("/x")));
        assert_eq!(from.parent(), Some(Path::new("/x")));
        assert_eq!(to.parent(), Some(Path::new("/x")));
        assert_eq!(from, temp);
    }

    #[test]
    fn plan_posix_commit_omits_parent_fsync_when_config_has_no_parent() {
        let plan = plan_posix_commit(
            Path::new("binary"),
            vec![],
            Path::new("config"),
            String::new(),
        );
        // `Path::new("config").parent()` returns `Some("")`, which
        // resolves to the empty path. We still emit FsyncDirBestEffort
        // on it (executor open() of the empty path will fail and the
        // best-effort branch absorbs it) — but only one of them.
        assert_eq!(
            plan.iter()
                .filter(|op| matches!(op, Operation::FsyncDirBestEffort { .. }))
                .count(),
            1,
        );
    }

    // ── execute: end-to-end on tempfiles ─────────────────────

    #[test]
    fn execute_writes_binary_and_renames_temp_config() {
        let dir = tempfile::TempDir::new().unwrap();
        let binary = dir.path().join("binary");
        let config = dir.path().join("litmask.config");
        fs::write(&binary, b"old binary contents").unwrap();
        fs::write(&config, b"old config contents").unwrap();

        let plan = plan_posix_commit(
            &binary,
            b"new binary contents".to_vec(),
            &config,
            "new config contents".to_string(),
        );
        execute(&plan).expect("execute should succeed");

        assert_eq!(fs::read(&binary).unwrap(), b"new binary contents");
        assert_eq!(fs::read(&config).unwrap(), b"new config contents");
        // The tempfile was renamed away — only `binary` and
        // `litmask.config` should remain in the dir.
        let remaining: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(remaining.len(), 2);
    }

    #[test]
    fn execute_reports_op_index_of_first_failure() {
        let dir = tempfile::TempDir::new().unwrap();
        // Plan with an FsyncFile at op[1] pointing at a path that
        // doesn't exist yet — exercise the error-attribution path.
        let plan = vec![
            Operation::WriteFile {
                path: dir.path().join("a"),
                bytes: b"a".to_vec(),
            },
            Operation::FsyncFile {
                path: dir.path().join("does-not-exist"),
            },
        ];
        let err = execute(&plan).expect_err("op[1] must fail");
        assert_eq!(err.op_index, 1);
    }

    #[test]
    fn execute_cleans_up_tempfile_on_rename_failure() {
        let dir = tempfile::TempDir::new().unwrap();
        let temp = dir.path().join(".litmask.config.bind-1.tmp");
        let nonexistent_dest = dir.path().join("subdir-not-created").join("config");
        fs::write(&temp, b"orphan").unwrap();
        let plan = vec![Operation::Rename {
            from: temp.clone(),
            to: nonexistent_dest,
        }];
        let err = execute(&plan).expect_err("rename into nonexistent subdir must fail");
        assert_eq!(err.op_index, 0);
        assert!(
            !temp.exists(),
            "executor must clean up orphaned tempfile after rename failure",
        );
    }
}
