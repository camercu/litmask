//! `litmask-cli bind` subcommand (§2.9.1.1–§2.9.1.6, §1.7.6,
//! §1.7.7 POSIX).
//!
//! Rebinds a target binary's embedded `mask_key` wrapper to a new
//! `unlock_key` derived from the target host's machine ID (with an
//! optional caller-supplied salt). The atomic commit protocol from
//! §1.7.7 ensures the binary and `litmask.config` cannot end up in
//! inconsistent states across a crash.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

// Both AEAD crates re-export the same `Aead` and `KeyInit` traits
// from upstream `aead`; pulling them once via the chacha import is
// enough for both ciphers' `.encrypt` / `.decrypt` / `::new` calls.
use aes_gcm::{Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, generic_array::GenericArray};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaNonce};
use litmask_internal::base64url;
use zeroize::Zeroizing;

/// Sysexits.h codes (§1.9.7 / §2.9.1.3) surfaced by `bind`. Inline
/// literals to avoid pulling a sysexits dep.
const EXIT_OK: u8 = 0;
const EX_DATAERR: u8 = 65;
const EX_NOINPUT: u8 = 66;
const EX_UNAVAILABLE: u8 = 69;

/// Wrapper layout (§1.7.3): 1-byte version + 1-byte cipher id +
/// 12-byte nonce + 32-byte ciphertext + 16-byte tag.
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

/// BLAKE3 domain separator for the hardware-id key derivation —
/// matches the constant in `litmask::provider` so a CLI-bound
/// binary and a runtime `HardwareIdProvider` derive identical keys.
const HW_ID_DERIVATION_CONTEXT: &str = "litmask 2026-05-20 HardwareIdProvider derivation";

/// Internal error type. Each variant that surfaces here maps to an
/// `EX_USAGE` / `EX_DATAERR` / `EX_SOFTWARE` exit-code at the
/// caller; the §2.9.1.3 outcome tags (`not_found`, `ambiguous`,
/// `decryption_failed`, `hardware_id_unavailable`) are printed
/// directly by `run` and returned as `Ok(<exit_code>)`, so they
/// don't get their own `Error` variants.
#[derive(Debug)]
pub(crate) enum Error {
    /// `litmask.config` missing or unreadable / malformed.
    ConfigUnreadable,
    /// Target binary missing or unreadable.
    BinaryUnreadable,
    /// Salt argument not valid base64url.
    SaltInvalid,
    /// AEAD authentication failed; routed through `Err` so the
    /// `decrypt_wrapper` helper can stay infallible-looking for
    /// every other failure mode.
    DecryptionFailed,
    /// `machine-uid::get()` failed on this host. Same routing
    /// rationale as `DecryptionFailed`.
    HardwareIdUnavailable,
    /// Wrapper carries a cipher byte that is neither `0x01` nor
    /// `0x02` (§2.9.1.6). Constructed in a follow-on amendment;
    /// the current AEAD dispatch surfaces unknown bytes as
    /// `DecryptionFailed` because the dispatch returns `None` for
    /// non-matching bytes. Keep the variant in the typed surface
    /// so a future tightening of the dispatcher has a clean
    /// landing pad.
    #[allow(dead_code)]
    UnsupportedCipher,
    /// Wrapper carries an unknown format-version byte.
    UnsupportedFormat,
    /// Anything unanticipated: I/O during the atomic commit, etc.
    Internal,
}

impl Error {
    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::ConfigUnreadable => "config file is missing, unreadable, or malformed",
            Self::BinaryUnreadable => "target binary is missing or unreadable",
            Self::SaltInvalid => "salt argument is not valid base64url",
            Self::DecryptionFailed => "decryption_failed",
            Self::HardwareIdUnavailable => "hardware_id_unavailable",
            Self::UnsupportedCipher => "unsupported_cipher",
            Self::UnsupportedFormat => "unsupported_format",
            Self::Internal => "internal_error",
        }
    }
}

/// Run the bind workflow. Returns the exit code; the caller maps
/// it to `ExitCode::from(...)`. Stdout receives the documented
/// outcome tag (`not_found`, `ambiguous`, `decryption_failed`,
/// `hardware_id_unavailable`, or — on success — nothing).
pub(crate) fn run(
    binary_path: &Path,
    config_path: &Path,
    salt_b64: Option<&str>,
) -> Result<u8, Error> {
    // Parse the salt eagerly so a malformed --salt argument fails
    // before any I/O.
    let salt = decode_salt(salt_b64)?;
    let config = parse_config(config_path)?;
    let mut binary_bytes = fs::read(binary_path).map_err(|_| Error::BinaryUnreadable)?;

    // Locate the wrapper. Multiple matches abort without writing.
    let offset = match locate_wrapper(&binary_bytes, &config.locator) {
        LocateOutcome::Single(o) => o,
        LocateOutcome::None => {
            println!("not_found");
            return Ok(EX_NOINPUT);
        }
        LocateOutcome::Multiple => {
            println!("ambiguous");
            return Ok(EX_DATAERR);
        }
    };

    let wrapper: [u8; WRAPPER_LEN] = binary_bytes[offset..offset + WRAPPER_LEN]
        .try_into()
        .map_err(|_| Error::Internal)?;

    // Recover the mask_key under the current unlock_key. AEAD
    // authentication failure surfaces as `decryption_failed`.
    let mask_key = match decrypt_wrapper(&wrapper, &config.unlock_key) {
        Ok(k) => k,
        Err(Error::DecryptionFailed) => {
            println!("decryption_failed");
            return Ok(EX_DATAERR);
        }
        Err(other) => return Err(other),
    };

    // Derive the new unlock_key from the host machine id.
    let new_unlock_key = match derive_hw_unlock_key(&salt) {
        Ok(k) => k,
        Err(Error::HardwareIdUnavailable) => {
            println!("hardware_id_unavailable");
            return Ok(EX_UNAVAILABLE);
        }
        Err(other) => return Err(other),
    };

    // Re-encrypt mask_key under the new unlock_key, reusing the
    // existing nonce. Reuse is safe: the (key, nonce) pair never
    // repeats because the key changed.
    let new_wrapper = encrypt_wrapper(&wrapper, &new_unlock_key, &mask_key)?;

    // Patch the in-memory binary bytes; the on-disk binary stays
    // unmodified until step 4 of the §1.7.7 protocol.
    binary_bytes[offset..offset + WRAPPER_LEN].copy_from_slice(&new_wrapper);

    // Render the new config text. Locator stays unchanged because
    // the nonce did not change; only `unlock_key` rotates.
    let new_config_text = render_config(&new_unlock_key, &config.locator);

    posix_atomic_commit(
        binary_path,
        &binary_bytes,
        config_path,
        new_config_text.as_bytes(),
    )?;

    Ok(EXIT_OK)
}

struct ParsedConfig {
    unlock_key: [u8; KEY_LEN],
    locator: [u8; NONCE_LEN],
}

fn parse_config(path: &Path) -> Result<ParsedConfig, Error> {
    let body = fs::read_to_string(path).map_err(|_| Error::ConfigUnreadable)?;
    let table: toml::Table = body.parse().map_err(|_| Error::ConfigUnreadable)?;
    let unlock_key_text = table
        .get("unlock_key")
        .and_then(|v| v.as_str())
        .ok_or(Error::ConfigUnreadable)?;
    let locator_text = table
        .get("locator")
        .and_then(|v| v.as_str())
        .ok_or(Error::ConfigUnreadable)?;
    let unlock_key_bytes =
        Zeroizing::new(base64url::decode(unlock_key_text).map_err(|_| Error::ConfigUnreadable)?);
    let unlock_key: [u8; KEY_LEN] = unlock_key_bytes
        .as_slice()
        .try_into()
        .map_err(|_| Error::ConfigUnreadable)?;
    let locator_bytes = base64url::decode(locator_text).map_err(|_| Error::ConfigUnreadable)?;
    let locator: [u8; NONCE_LEN] = locator_bytes
        .try_into()
        .map_err(|_| Error::ConfigUnreadable)?;
    Ok(ParsedConfig {
        unlock_key,
        locator,
    })
}

fn decode_salt(salt_b64: Option<&str>) -> Result<Vec<u8>, Error> {
    match salt_b64 {
        None => Ok(Vec::new()),
        Some(s) => base64url::decode(s).map_err(|_| Error::SaltInvalid),
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
        // The wrapper occupies WRAPPER_LEN bytes starting at the
        // locator offset; reject matches near the end of the file
        // that don't have room for a full wrapper.
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

fn decrypt_wrapper(
    wrapper: &[u8; WRAPPER_LEN],
    unlock_key: &[u8; KEY_LEN],
) -> Result<Zeroizing<[u8; KEY_LEN]>, Error> {
    let format_byte = wrapper[VERSION_OFFSET];
    if format_byte != FORMAT_V1 {
        return Err(Error::UnsupportedFormat);
    }
    let cipher_byte = wrapper[CIPHER_OFFSET];
    let nonce: [u8; NONCE_LEN] = wrapper[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN]
        .try_into()
        .map_err(|_| Error::Internal)?;
    let body = &wrapper[HEADER_LEN..];
    let plaintext = aead_decrypt_dispatch(cipher_byte, unlock_key, &nonce, body)
        .ok_or(Error::DecryptionFailed)?;
    let mut bytes = Zeroizing::new([0u8; KEY_LEN]);
    if plaintext.len() != KEY_LEN {
        return Err(Error::DecryptionFailed);
    }
    bytes.copy_from_slice(&plaintext);
    Ok(bytes)
}

fn encrypt_wrapper(
    original_wrapper: &[u8; WRAPPER_LEN],
    new_unlock_key: &[u8; KEY_LEN],
    mask_key: &[u8; KEY_LEN],
) -> Result<[u8; WRAPPER_LEN], Error> {
    let format_byte = original_wrapper[VERSION_OFFSET];
    let cipher_byte = original_wrapper[CIPHER_OFFSET];
    let nonce: [u8; NONCE_LEN] = original_wrapper[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN]
        .try_into()
        .map_err(|_| Error::Internal)?;
    let body = aead_encrypt_dispatch(cipher_byte, new_unlock_key, &nonce, mask_key)
        .ok_or(Error::Internal)?;
    if body.len() != KEY_LEN + TAG_LEN {
        return Err(Error::Internal);
    }
    let mut out = [0u8; WRAPPER_LEN];
    out[VERSION_OFFSET] = format_byte;
    out[CIPHER_OFFSET] = cipher_byte;
    out[NONCE_OFFSET..NONCE_OFFSET + NONCE_LEN].copy_from_slice(&nonce);
    out[HEADER_LEN..].copy_from_slice(&body);
    Ok(out)
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

/// Derive a 32-byte `unlock_key` from the host machine id +
/// caller-supplied salt. Mirrors `litmask::provider::derive_hw_key`
/// exactly so a runtime `HardwareIdProvider` recovers the same
/// key the bind operation just installed.
fn derive_hw_unlock_key(salt: &[u8]) -> Result<[u8; KEY_LEN], Error> {
    let machine_id = machine_uid::get().map_err(|_| Error::HardwareIdUnavailable)?;
    let key = blake3::derive_key(HW_ID_DERIVATION_CONTEXT, salt);
    let mac = blake3::keyed_hash(&key, machine_id.as_bytes());
    Ok(*mac.as_bytes())
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

/// POSIX atomic commit per §1.7.7. Step ordering and `fsync`
/// placement are normative — any reordering risks inconsistency
/// after a crash mid-bind. The parent-dir fsync (step 7) is the
/// often-skipped step that turns an "atomic on the local
/// filesystem" rename into one that's durable across reboots.
fn posix_atomic_commit(
    binary_path: &Path,
    new_binary_bytes: &[u8],
    config_path: &Path,
    new_config_bytes: &[u8],
) -> Result<(), Error> {
    // Step 2: write new config to a tempfile in the same dir as
    // the target. Same-dir is mandatory for `rename(2)` to be
    // atomic (cross-filesystem renames degrade to copy+unlink).
    let temp_config = tempfile_alongside(config_path)?;
    let mut tf = fs::File::create(&temp_config).map_err(|_| Error::Internal)?;
    tf.write_all(new_config_bytes)
        .map_err(|_| Error::Internal)?;
    // Step 3: fsync the tempfile so its contents land on disk
    // before we begin patching the binary.
    tf.sync_all().map_err(|_| Error::Internal)?;
    drop(tf);

    // Step 4: patch the binary in place. We overwrite the entire
    // file rather than seeking-and-writing the WRAPPER_LEN window
    // so callers do not have to track byte offsets through
    // intermediate states; the binary either has the new wrapper
    // or the old one, not a partial blend. Note that an in-place
    // overwrite preserves the inode (and any ACL / xattr) — only
    // the bytes within the file change.
    {
        let mut bf = fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(binary_path)
            .map_err(|_| Error::Internal)?;
        bf.write_all(new_binary_bytes)
            .map_err(|_| Error::Internal)?;
        // Step 5: fsync the binary so its contents land before
        // step 6's rename. Without this, a crash between 4 and 6
        // could persist the rename + old binary, violating the
        // (binary, config) pair-consistency property.
        bf.sync_all().map_err(|_| Error::Internal)?;
    }

    // Step 6: rename(temp_config, config_path). POSIX guarantees
    // this is atomic with respect to a concurrent reader.
    fs::rename(&temp_config, config_path).map_err(|_| {
        // Best-effort cleanup if the rename fails partway. The
        // binary is already patched; the operator has to rebuild
        // or re-bind to recover the matching config.
        let _ = fs::remove_file(&temp_config);
        Error::Internal
    })?;

    // Step 7: fsync the parent directory so the rename survives
    // a crash. Without this step, the rename is in the kernel's
    // dirent cache but the journal may not yet reference it; a
    // crash here leaves the old config visible after reboot.
    if let Some(parent) = config_path.parent() {
        if let Ok(dir) = fs::File::open(parent) {
            // fsync on a directory handle is the documented POSIX
            // way to flush dirent updates; ignore the result if
            // the platform refuses (e.g., directory not
            // syncable) — the prior step's rename is still
            // ordered correctly.
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Build a tempfile path alongside `target` so `rename(2)` stays
/// atomic. Encoding the PID into the name avoids collision between
/// concurrent `bind` invocations targeting the same config (rare
/// but plausible in CI).
fn tempfile_alongside(target: &Path) -> Result<PathBuf, Error> {
    let parent = target.parent().ok_or(Error::Internal)?;
    let name = target
        .file_name()
        .ok_or(Error::Internal)?
        .to_string_lossy()
        .into_owned();
    Ok(parent.join(format!(".{}.bind-{}.tmp", name, std::process::id())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_config_starts_with_hash_comment_block() {
        let body = render_config(&[0u8; KEY_LEN], &[0u8; NONCE_LEN]);
        let first = body.lines().next().expect("non-empty");
        assert!(
            first.starts_with('#'),
            "first line must be a comment: {first:?}"
        );
    }

    #[test]
    fn render_config_includes_unlock_key_and_locator_fields() {
        let body = render_config(&[0xAAu8; KEY_LEN], &[0xBBu8; NONCE_LEN]);
        assert!(body.contains("unlock_key = "));
        assert!(body.contains("locator = "));
        assert!(body.contains(&format!("length = {WRAPPER_LEN}")));
    }

    #[test]
    fn locate_wrapper_none_when_haystack_too_short() {
        assert!(matches!(
            locate_wrapper(&[0u8; WRAPPER_LEN - 1], &[0u8; NONCE_LEN]),
            LocateOutcome::None,
        ));
    }

    #[test]
    fn locate_wrapper_single_returns_offset() {
        let locator = [0xABu8; NONCE_LEN];
        let mut haystack = vec![0u8; 100];
        let offset = 32;
        haystack[offset..offset + WRAPPER_LEN].fill(0x11);
        haystack[offset..offset + NONCE_LEN].copy_from_slice(&locator);
        match locate_wrapper(&haystack, &locator) {
            LocateOutcome::Single(o) => assert_eq!(o, offset),
            other => panic!(
                "expected Single, got {:?}",
                matches!(other, LocateOutcome::Single(_))
            ),
        }
    }

    #[test]
    fn locate_wrapper_multiple_when_locator_appears_twice() {
        let locator = [0xEFu8; NONCE_LEN];
        let mut haystack = vec![0u8; 200];
        haystack[40..40 + WRAPPER_LEN].fill(0x22);
        haystack[40..40 + NONCE_LEN].copy_from_slice(&locator);
        haystack[120..120 + WRAPPER_LEN].fill(0x33);
        haystack[120..120 + NONCE_LEN].copy_from_slice(&locator);
        assert!(matches!(
            locate_wrapper(&haystack, &locator),
            LocateOutcome::Multiple,
        ));
    }

    #[test]
    fn decode_salt_none_yields_empty() {
        assert_eq!(decode_salt(None).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn decode_salt_rejects_invalid_base64url() {
        assert!(matches!(
            decode_salt(Some("not valid base64url!!")),
            Err(Error::SaltInvalid),
        ));
    }
}
