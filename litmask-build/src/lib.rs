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
//! 62-byte wrapper described in §1.7.3, and writes:
//!
//! - `$OUT_DIR/litmask_seed.bin`      — 32-byte seed (consumed by the
//!   proc-macro for per-call-site nonce derivation).
//! - `$OUT_DIR/litmask_key.bin`       — 32-byte plaintext `mask_key`
//!   (consumed by the proc-macro to encrypt per-string blobs at
//!   expansion time).
//! - `$OUT_DIR/litmask_wrapper.bin`   — 62-byte encrypted-`mask_key`
//!   wrapper (consumed by the runtime via `include_bytes!` inside the
//!   `init!` / `init_with!` / `mask!` macro expansions).
//! - `target/<profile>/litmask.config` — TOML with `unlock_key`,
//!   `locator`, and `length` per §1.7.4.
//!
//! Reproducible seed sourcing (`LITMASK_RNG_SEED`, `target/litmask-seed`,
//! `cargo:warning=` for release builds) is deferred to Task 19. This
//! initial implementation generates a fresh seed via `getrandom` on
//! every build.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};
use chacha20poly1305::{
    ChaCha20Poly1305, KeyInit, Nonce,
    aead::{Aead, generic_array::GenericArray},
};
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const WRAPPER_LEN: usize = 1 + 1 + NONCE_LEN + KEY_LEN + TAG_LEN; // 62

const WRAPPER_VERSION: u8 = 0x01;
const WRAPPER_CIPHER_CHACHA20: u8 = 0x01;
const WRAPPER_TAG: &[u8] = b"litmask-mask-key-nonce";

const CONFIG_HEADER: &str = "\
# litmask.config — build artifact.
# SECRET: contains the runtime `unlock_key` for this build. Do not commit.
# This file is written by litmask-build::emit() at compile time and consumed by
# the litmask runtime (env var) and by `litmask-cli` (bind / inspect).
";

/// Run the build-time key generation pipeline.
///
/// # Panics
///
/// Panics on any I/O failure or unsupported environment. Build scripts
/// run in tightly controlled contexts (cargo sets `OUT_DIR`,
/// `CARGO_MANIFEST_DIR`, `PROFILE`); a failure of any of these is a
/// build-system bug, not a user error.
pub fn emit() {
    // Re-run if the user changes the seed env var or edits their build
    // script. Full LITMASK_RNG_SEED honoring lands in Task 19.
    println!("cargo:rerun-if-env-changed=LITMASK_RNG_SEED");
    println!("cargo:rerun-if-changed=build.rs");

    let out_dir: PathBuf = std::env::var_os("OUT_DIR")
        .expect("cargo did not set OUT_DIR")
        .into();
    let profile_dir = profile_dir_of(&out_dir);

    // Source the per-build seed. Persistence is profile-scoped (not
    // OUT_DIR-scoped) so that two cargo invocations with different
    // feature flags (e.g., `cargo build` and `cargo build
    // --no-default-features --features alloc`) share the same key
    // material and produce a single coherent litmask.config. Spec
    // §2.4.1.3 specifies this path explicitly ("target/litmask-seed");
    // we use `target/<profile>/litmask-seed.bin` because cargo writes
    // litmask.config alongside it. Task 19 layers `LITMASK_RNG_SEED`
    // env var + release/debug split on top.
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

    // Derive both keys deterministically from the seed.
    let mut rng = ChaCha20Rng::from_seed(seed);
    let mut mask_key = [0u8; KEY_LEN];
    let mut unlock_key = [0u8; KEY_LEN];
    rng.fill_bytes(&mut mask_key);
    rng.fill_bytes(&mut unlock_key);

    // Derive the wrapper nonce per §1.7.3.
    let wrapper_nonce = wrapper_nonce(&seed);

    // Encrypt mask_key under unlock_key with ChaCha20-Poly1305.
    let cipher = ChaCha20Poly1305::new(GenericArray::from_slice(&unlock_key));
    let mut ciphertext_with_tag = cipher
        .encrypt(Nonce::from_slice(&wrapper_nonce), mask_key.as_slice())
        .expect("ChaCha20-Poly1305 wrapper encryption failed");
    assert_eq!(
        ciphertext_with_tag.len(),
        KEY_LEN + TAG_LEN,
        "encrypted mask_key length must be {} bytes",
        KEY_LEN + TAG_LEN
    );

    // Assemble the 62-byte wrapper.
    let mut wrapper = [0u8; WRAPPER_LEN];
    wrapper[0] = WRAPPER_VERSION;
    wrapper[1] = WRAPPER_CIPHER_CHACHA20;
    wrapper[2..2 + NONCE_LEN].copy_from_slice(&wrapper_nonce);
    wrapper[2 + NONCE_LEN..].copy_from_slice(&ciphertext_with_tag);
    // Best-effort zeroize of the local copy.
    ciphertext_with_tag.fill(0);

    // Write OUT_DIR artifacts. These are the per-build-unit copies the
    // proc-macro reads at expansion time via include_bytes!.
    write_secret(&out_dir.join("litmask_seed.bin"), &seed);
    write_secret(&out_dir.join("litmask_key.bin"), &mask_key);
    write_secret(&out_dir.join("litmask_wrapper.bin"), &wrapper);

    // Write the deployer-facing config at the profile root.
    write_config(&profile_dir.join("litmask.config"), &unlock_key, &wrapper);

    // Best-effort zeroize of the in-memory keys.
    drop_zeroed(seed);
    drop_zeroed(mask_key);
    drop_zeroed(unlock_key);
}

fn wrapper_nonce(seed: &[u8; KEY_LEN]) -> [u8; NONCE_LEN] {
    let mut hasher = blake3::Hasher::new_keyed(seed);
    hasher.update(WRAPPER_TAG);
    let digest = hasher.finalize();
    let bytes = digest.as_bytes();
    bytes[..NONCE_LEN]
        .try_into()
        .expect("blake3 output ≥12 bytes")
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
    let unlock_key_b64 = Base64UrlUnpadded::encode_string(unlock_key);
    let locator_b64 = Base64UrlUnpadded::encode_string(&wrapper[..NONCE_LEN]);

    let body = format!(
        "{CONFIG_HEADER}\nunlock_key = \"{unlock_key_b64}\"\nlocator = \"{locator_b64}\"\nlength = {WRAPPER_LEN}\n"
    );

    fs::write(path, body).unwrap_or_else(|e| panic!("write {}: {e}", path.display()));
}

fn drop_zeroed(mut buf: [u8; KEY_LEN]) {
    buf.fill(0);
}
