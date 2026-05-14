//! Build-script helper for `litmask`.
//!
//! Intended use is a single-line `build.rs` in any crate that masks
//! string literals:
//!
//! ```ignore
//! fn main() {
//!     litmask_build::emit();
//! }
//! ```
//!
//! `emit()` generates the per-build random seed, derives the
//! `mask_key` / `unlock_key` pair, encrypts the `mask_key` into the
//! wrapper, and writes:
//!
//! - `$OUT_DIR/litmask_seed.bin` — 32-byte seed (consumed by the
//!   proc-macro for per-call-site nonce derivation).
//! - `$OUT_DIR/litmask_key.bin` — 32-byte plaintext `mask_key`
//!   (consumed by the proc-macro to encrypt per-string blobs at
//!   expansion time).
//! - `$OUT_DIR/litmask_wrapper.bin` — encrypted-`mask_key` wrapper
//!   (consumed by the runtime via `include_bytes!` inside the
//!   `init!` / `init_with!` / `mask!` macro expansions).
//! - `target/<profile>/litmask.config` — TOML containing `unlock_key`,
//!   `locator`, and `length`.

use std::fs;
use std::path::{Path, PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use zeroize::Zeroize;

use litmask_internal::{
    CipherId, FormatVersion, KEY_LEN, NONCE_LEN, WRAPPER_BODY_LEN, WRAPPER_LEN, aead_encrypt,
    assemble_wrapper, nonce_for_wrapper,
};

const CONFIG_HEADER: &str = "\
# litmask.config — build artifact.
# SECRET: contains the runtime `unlock_key` for this build. Do not commit.
# This file is written by litmask-build::emit() at compile time and consumed by
# the litmask runtime (env var) and by `litmask-cli` (bind / inspect).
";

/// Run the build-time mask-key + unlock-key generation pipeline.
///
/// # Panics
///
/// Panics on any I/O failure or unsupported environment. Build scripts
/// run in tightly controlled contexts (cargo sets `OUT_DIR`,
/// `CARGO_MANIFEST_DIR`, `PROFILE`); a failure of any of these is a
/// build-system bug, not a user error.
pub fn emit() {
    // Re-run when the user changes the seed env var or edits their
    // build script.
    println!("cargo:rerun-if-env-changed=LITMASK_RNG_SEED");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir: PathBuf = std::env::var_os("OUT_DIR")
        .expect("cargo did not set OUT_DIR")
        .into();
    let profile_dir = profile_dir_of(&out_dir);

    let mut seed = source_seed(&profile_dir);
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut mask_key = [0u8; KEY_LEN];
    let mut unlock_key = [0u8; KEY_LEN];
    rng.fill_bytes(&mut mask_key);
    rng.fill_bytes(&mut unlock_key);

    let cipher = CipherId::ChaCha20Poly1305;
    let wrapper_nonce = nonce_for_wrapper(&seed);

    let mut ciphertext_with_tag =
        aead_encrypt(cipher, &unlock_key, &wrapper_nonce, mask_key.as_slice())
            .expect("wrapper encryption failed");
    let body: &[u8; WRAPPER_BODY_LEN] = ciphertext_with_tag
        .as_slice()
        .try_into()
        .expect("AEAD output of 32-byte plaintext is WRAPPER_BODY_LEN bytes");
    let wrapper = assemble_wrapper(FormatVersion::CURRENT, cipher, &wrapper_nonce, body);
    ciphertext_with_tag.zeroize();

    // OUT_DIR receives the binary artifacts the proc-macro and runtime
    // `include_bytes!` at macro-expansion time. profile_dir receives
    // `litmask.config`, the TOML the runtime reads via env var.
    write_secret(&out_dir.join("litmask_seed.bin"), &seed);
    write_secret(&out_dir.join("litmask_key.bin"), &mask_key);
    write_secret(&out_dir.join("litmask_wrapper.bin"), &wrapper);
    write_config(&profile_dir.join("litmask.config"), &unlock_key, &wrapper);

    seed.zeroize();
    mask_key.zeroize();
    unlock_key.zeroize();
}

/// Load the per-build seed from the profile-dir persist file, or
/// generate + persist a fresh one if the file is missing or corrupt.
///
/// Persistence is profile-scoped (not OUT_DIR-scoped) so two cargo
/// invocations with different feature flags (e.g., `cargo build` and
/// `cargo build --no-default-features --features alloc`) share the
/// same key material and produce a single coherent `litmask.config`.
fn source_seed(profile_dir: &Path) -> [u8; KEY_LEN] {
    let path = profile_dir.join("litmask_seed.bin");
    if let Ok(bytes) = fs::read(&path) {
        if let Ok(seed) = <[u8; KEY_LEN]>::try_from(bytes.as_slice()) {
            return seed;
        }
    }
    let mut seed = [0u8; KEY_LEN];
    getrandom::getrandom(&mut seed).expect("OS RNG failure during litmask seed generation");
    write_secret(&path, &seed);
    seed
}

fn write_secret(path: &Path, contents: &[u8]) {
    fs::write(path, contents).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn profile_dir_of(out_dir: &Path) -> PathBuf {
    // OUT_DIR looks like target/<profile>/build/<pkg>-<hash>/out.
    // Three ancestors up is target/<profile>/, where litmask.config
    // and the persisted seed live.
    out_dir
        .ancestors()
        .nth(3)
        .expect("OUT_DIR has expected target/<profile>/build/<pkg>-<hash>/out shape")
        .to_path_buf()
}

fn write_config(path: &Path, unlock_key: &[u8; KEY_LEN], wrapper: &[u8; WRAPPER_LEN]) {
    let unlock_key_text = Base64UrlUnpadded::encode_string(unlock_key);
    let locator_text = Base64UrlUnpadded::encode_string(&wrapper[..NONCE_LEN]);

    let body = format!(
        "{CONFIG_HEADER}\nunlock_key = \"{unlock_key_text}\"\nlocator = \"{locator_text}\"\nlength = {WRAPPER_LEN}\n"
    );

    fs::write(path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn persist_path(dir: &TempDir) -> PathBuf {
        dir.path().join("litmask_seed.bin")
    }

    #[test]
    fn source_seed_generates_and_persists_when_file_is_missing() {
        let dir = TempDir::new().expect("tempdir");
        let seed = source_seed(dir.path());
        let persisted = fs::read(persist_path(&dir)).expect("file persisted");
        assert_eq!(persisted.len(), KEY_LEN);
        assert_eq!(persisted.as_slice(), &seed);
    }

    #[test]
    fn source_seed_reads_back_valid_persisted_file() {
        let dir = TempDir::new().expect("tempdir");
        let canned = [0x42u8; KEY_LEN];
        fs::write(persist_path(&dir), canned).expect("seed file");
        assert_eq!(source_seed(dir.path()), canned);
    }

    /// Prove-it: a wrong-length persist file is overwritten with a
    /// fresh KEY_LEN-byte seed. The pre-fix code generated a fresh
    /// seed but did not persist it, so the corrupt file stayed in
    /// place and every subsequent build produced a different seed —
    /// the `assert_eq!(after.len(), KEY_LEN)` line below failed
    /// against that path.
    #[test]
    fn source_seed_overwrites_corrupt_short_file() {
        let dir = TempDir::new().expect("tempdir");
        let canned_short = vec![0xAAu8; KEY_LEN - 1];
        fs::write(persist_path(&dir), &canned_short).expect("short seed file");

        let seed = source_seed(dir.path());

        let after = fs::read(persist_path(&dir)).expect("file still present");
        assert_eq!(
            after.len(),
            KEY_LEN,
            "corrupt persist file must be overwritten with KEY_LEN bytes",
        );
        assert_eq!(
            after.as_slice(),
            &seed,
            "persisted bytes must match returned seed",
        );
        assert_ne!(
            after.as_slice(),
            canned_short.as_slice(),
            "corrupt bytes must not survive the call",
        );
    }

    #[test]
    fn source_seed_overwrites_corrupt_long_file() {
        let dir = TempDir::new().expect("tempdir");
        let canned_long = vec![0xBBu8; KEY_LEN + 1];
        fs::write(persist_path(&dir), &canned_long).expect("long seed file");

        let seed = source_seed(dir.path());

        let after = fs::read(persist_path(&dir)).expect("file still present");
        assert_eq!(after.len(), KEY_LEN);
        assert_eq!(after.as_slice(), &seed);
    }

    #[test]
    fn source_seed_is_idempotent_when_file_is_valid() {
        let dir = TempDir::new().expect("tempdir");
        let first = source_seed(dir.path());
        let second = source_seed(dir.path());
        assert_eq!(first, second);
    }
}
