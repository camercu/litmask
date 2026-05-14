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
use std::io::Write;
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

    // Source the per-build seed. Persistence is profile-scoped (not
    // OUT_DIR-scoped) so two cargo invocations with different feature
    // flags (e.g., `cargo build` and `cargo build --no-default-features
    // --features alloc`) share the same key material and produce a
    // single coherent litmask.config.
    let seed_persist_path = profile_dir.join("litmask-seed.bin");
    let mut seed = [0u8; KEY_LEN];
    if let Ok(bytes) = fs::read(&seed_persist_path) {
        if bytes.len() == KEY_LEN {
            seed.copy_from_slice(&bytes);
        } else {
            getrandom::getrandom(&mut seed).expect("OS RNG failure during litmask seed generation");
        }
    } else {
        getrandom::getrandom(&mut seed).expect("OS RNG failure during litmask seed generation");
        write_secret(&seed_persist_path, &seed);
    }

    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut mask_key = [0u8; KEY_LEN];
    let mut unlock_key = [0u8; KEY_LEN];
    rng.fill_bytes(&mut mask_key);
    rng.fill_bytes(&mut unlock_key);

    let wrapper_nonce = nonce_for_wrapper(&seed);

    let mut ciphertext_with_tag = aead_encrypt(
        CipherId::ChaCha20Poly1305,
        &unlock_key,
        &wrapper_nonce,
        mask_key.as_slice(),
    )
    .expect("wrapper encryption failed");
    let body: &[u8; WRAPPER_BODY_LEN] = ciphertext_with_tag
        .as_slice()
        .try_into()
        .expect("AEAD output of 32-byte plaintext is WRAPPER_BODY_LEN bytes");

    let wrapper = assemble_wrapper(
        FormatVersion::CURRENT,
        CipherId::ChaCha20Poly1305,
        &wrapper_nonce,
        body,
    );
    ciphertext_with_tag.zeroize();

    // OUT_DIR is the path the proc-macro and the runtime `include_bytes!`
    // at macro-expansion time; profile_dir (below) holds the human-
    // readable `litmask.config` consumed via env-var at runtime.
    write_secret(&out_dir.join("litmask_seed.bin"), &seed);
    write_secret(&out_dir.join("litmask_key.bin"), &mask_key);
    write_secret(&out_dir.join("litmask_wrapper.bin"), &wrapper);

    write_config(&profile_dir.join("litmask.config"), &unlock_key, &wrapper);

    seed.zeroize();
    mask_key.zeroize();
    unlock_key.zeroize();
}

fn write_secret(path: &Path, contents: &[u8]) {
    let mut f = fs::File::create(path).unwrap_or_else(|e| panic!("create {}: {e}", path.display()));
    f.write_all(contents)
        .unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn profile_dir_of(out_dir: &Path) -> PathBuf {
    // OUT_DIR looks like target/<profile>/build/<pkg>-<hash>/out. Three
    // parents up is target/<profile>/, where litmask.config and the
    // persisted seed live.
    out_dir
        .parent()
        .and_then(Path::parent)
        .and_then(Path::parent)
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
