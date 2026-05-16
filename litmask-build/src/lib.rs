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

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use base64ct::{Base64UrlUnpadded, Encoding};
use rand_chacha::ChaCha20Rng;
// `Rng` is the rand_core 0.10 renaming of the former `RngCore`; it
// provides `fill_bytes` for any seedable RNG. `getrandom::fill` is the
// 0.4+ replacement for the standalone `getrandom::getrandom` function.
use rand_core::{Rng, SeedableRng};
use zeroize::{Zeroize, Zeroizing};

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
    let profile = Profile::from_env();

    let (mut seed, seed_source) = source_seed(&profile_dir);

    // §2.4.1.5: a release build whose seed was freshly generated
    // (no `LITMASK_RNG_SEED` supplied) has no persistence path, so
    // the only way to reproduce the build later is to capture the
    // generated seed. Print it via `cargo:warning=` so it lands in
    // the developer's terminal output even when stderr is captured.
    if profile == Profile::Release && seed_source == SeedSource::Fresh {
        let encoded = Base64UrlUnpadded::encode_string(&seed);
        println!(
            "cargo:warning=litmask: release build generated a fresh RNG seed. Capture this value for reproducible rebuilds: LITMASK_RNG_SEED={encoded}",
        );
    }

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

/// Indicates which of the three sources in §1.3.2 the seed came from.
/// `emit()` consults this to decide whether a release-profile
/// `cargo:warning=` should be emitted (only when freshly generated,
/// per §2.4.1.5).
#[derive(Debug, PartialEq, Eq)]
enum SeedSource {
    /// Supplied via `LITMASK_RNG_SEED` — highest priority.
    Env,
    /// Recovered from the per-profile persist file (debug only).
    Persist,
    /// Fresh-generated via OS RNG.
    Fresh,
}

/// Cargo build profile, derived from the `PROFILE` env var. Drives
/// the persist-on-miss / persist-fresh behavior split per §1.3.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Profile {
    Debug,
    Release,
}

impl Profile {
    /// `PROFILE` is set by cargo to "debug" or "release" for every
    /// build-script invocation. Unset (or any other value) defaults
    /// to Debug — the more conservative behavior (persist enabled).
    fn from_env() -> Self {
        match std::env::var("PROFILE").as_deref() {
            Ok("release") => Profile::Release,
            _ => Profile::Debug,
        }
    }
}

/// Load the per-build seed per §1.3.2 priority order:
/// 1. `LITMASK_RNG_SEED` env var (base64url, 32 bytes), regardless of profile.
/// 2. Profile-dir persist file (debug profile only).
/// 3. Fresh OS-RNG generation (with persist write on debug; no persist on release).
fn source_seed(profile_dir: &Path) -> ([u8; KEY_LEN], SeedSource) {
    source_seed_with_env_and_profile(
        profile_dir,
        std::env::var_os("LITMASK_RNG_SEED"),
        Profile::from_env(),
    )
}

/// `source_seed`'s pure core: takes the env value and profile
/// explicitly so unit tests can pin both without mutating the test
/// process environment.
fn source_seed_with_env_and_profile(
    profile_dir: &Path,
    env_value: Option<OsString>,
    profile: Profile,
) -> ([u8; KEY_LEN], SeedSource) {
    if let Some(raw) = env_value {
        let seed = decode_env_seed(&raw);
        return (seed, SeedSource::Env);
    }
    let persist_path = profile_dir.join("litmask_seed.bin");
    if profile == Profile::Debug {
        if let Ok(bytes) = fs::read(&persist_path) {
            let bytes = Zeroizing::new(bytes);
            if let Ok(seed) = <[u8; KEY_LEN]>::try_from(bytes.as_slice()) {
                return (seed, SeedSource::Persist);
            }
        }
    }
    let mut seed = [0u8; KEY_LEN];
    getrandom::fill(&mut seed).expect("OS RNG failure during litmask seed generation");
    if profile == Profile::Debug {
        write_secret(&persist_path, &seed);
    }
    (seed, SeedSource::Fresh)
}

/// Decode a base64url-encoded 32-byte seed from `LITMASK_RNG_SEED`.
/// Panics with an actionable message on malformed input — this is
/// build-time input from the developer, not runtime data subject to
/// §1.9.5 panic hygiene.
fn decode_env_seed(raw: &OsString) -> [u8; KEY_LEN] {
    let text = raw.to_str().expect("LITMASK_RNG_SEED must be valid UTF-8");
    let mut decoded = Zeroizing::new(
        Base64UrlUnpadded::decode_vec(text).expect("LITMASK_RNG_SEED must be base64url-encoded"),
    );
    let seed = <[u8; KEY_LEN]>::try_from(decoded.as_slice())
        .expect("LITMASK_RNG_SEED must decode to exactly 32 bytes");
    decoded.zeroize();
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

    /// Helper: invoke `source_seed_with_env_and_profile` with no env
    /// override and the debug profile (matches the pre-§2.4.1.3
    /// default), returning just the seed bytes to keep the existing
    /// assertions tight.
    fn debug_seed(profile_dir: &Path) -> [u8; KEY_LEN] {
        let (seed, _) = source_seed_with_env_and_profile(profile_dir, None, Profile::Debug);
        seed
    }

    #[test]
    fn source_seed_generates_and_persists_when_file_is_missing() {
        let dir = TempDir::new().expect("tempdir");
        let seed = debug_seed(dir.path());
        let persisted = fs::read(persist_path(&dir)).expect("file persisted");
        assert_eq!(persisted.len(), KEY_LEN);
        assert_eq!(persisted.as_slice(), &seed);
    }

    #[test]
    fn source_seed_reads_back_valid_persisted_file() {
        let dir = TempDir::new().expect("tempdir");
        let canned = [0x42u8; KEY_LEN];
        fs::write(persist_path(&dir), canned).expect("seed file");
        assert_eq!(debug_seed(dir.path()), canned);
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

        let seed = debug_seed(dir.path());

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

        let seed = debug_seed(dir.path());

        let after = fs::read(persist_path(&dir)).expect("file still present");
        assert_eq!(after.len(), KEY_LEN);
        assert_eq!(after.as_slice(), &seed);
    }

    #[test]
    fn source_seed_is_idempotent_when_file_is_valid() {
        let dir = TempDir::new().expect("tempdir");
        let first = debug_seed(dir.path());
        let second = debug_seed(dir.path());
        assert_eq!(first, second);
    }

    /// Prove-it for §2.4.1.3: when `LITMASK_RNG_SEED` is set, the
    /// returned seed comes from the env var (decoded base64url),
    /// regardless of profile or whether a persist file exists. The
    /// pre-fix code only read the persist file and ignored the env,
    /// so this assertion failed (returned bytes were the cached
    /// canned-persist value instead of the env-decoded value).
    #[test]
    fn source_seed_honors_litmask_rng_seed_env_var() {
        let dir = TempDir::new().expect("tempdir");
        // A canned persist file would be returned by the buggy
        // pre-fix path; the env var must win over it.
        let canned_persist = [0x42u8; KEY_LEN];
        fs::write(persist_path(&dir), canned_persist).expect("seed file");

        let canned_env = [0xCDu8; KEY_LEN];
        let encoded: OsString = Base64UrlUnpadded::encode_string(&canned_env).into();

        let (seed, source) =
            source_seed_with_env_and_profile(dir.path(), Some(encoded), Profile::Debug);
        assert_eq!(seed, canned_env, "env var must override persist file");
        assert_eq!(source, SeedSource::Env);
    }

    /// End-to-end prove-it for the §2.4.1.3 wire-up: when `source_seed`
    /// (not the explicit-env helper) is invoked with `LITMASK_RNG_SEED`
    /// present in the **process** environment, the returned seed is
    /// env-decoded.
    ///
    /// The test uses a self-exec subprocess pattern so the env var is
    /// set by `Command::env` in the child only — no in-process
    /// `std::env::set_var` call, which would require `unsafe` and is
    /// forbidden workspace-wide.
    ///
    /// RED state (pre-fix) observed: with `source_seed`'s old body
    /// (read persist or fresh, ignoring env), the child returned a
    /// fresh-generated seed not matching the env-supplied bytes; the
    /// `assert_eq!(source, SeedSource::Env)` line failed.
    #[test]
    fn source_seed_wires_up_litmask_rng_seed_from_process_env() {
        const MARKER: &str = "__LITMASK_SEED_TEST_CHILD";
        const DIR_VAR: &str = "__LITMASK_SEED_TEST_DIR";

        if std::env::var_os(MARKER).is_some() {
            // CHILD: runs inside the subprocess with LITMASK_RNG_SEED
            // pre-populated by the parent. Asserts the outer wrapper
            // honored it.
            let dir = std::env::var(DIR_VAR).expect("DIR_VAR set by parent");
            let (seed, source) = source_seed(Path::new(&dir));
            assert_eq!(source, SeedSource::Env, "outer wrapper must read env");
            assert_eq!(seed, [0xCDu8; KEY_LEN], "env-decoded seed mismatch");
            return;
        }

        // PARENT: spawn self with the env set + marker.
        let dir = TempDir::new().expect("tempdir");
        let canned = [0xCDu8; KEY_LEN];
        let encoded = Base64UrlUnpadded::encode_string(&canned);

        let exe = std::env::current_exe().expect("current_exe");
        let output = std::process::Command::new(&exe)
            .env("LITMASK_RNG_SEED", &encoded)
            .env(MARKER, "1")
            .env(DIR_VAR, dir.path())
            .args([
                "--exact",
                "tests::source_seed_wires_up_litmask_rng_seed_from_process_env",
            ])
            .output()
            .expect("spawn test child");

        assert!(
            output.status.success(),
            "child failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }

    #[test]
    fn source_seed_release_profile_skips_persist_read_and_write() {
        let dir = TempDir::new().expect("tempdir");
        // A canned persist file MUST be ignored under the release
        // profile (§1.3.2: release seed priority is env → fresh,
        // with no persistence).
        let canned_persist = [0x42u8; KEY_LEN];
        fs::write(persist_path(&dir), canned_persist).expect("seed file");

        let (seed, source) = source_seed_with_env_and_profile(dir.path(), None, Profile::Release);
        assert_ne!(seed, canned_persist, "release must not read persist file");
        assert_eq!(source, SeedSource::Fresh);

        // And the persist file must not have been overwritten.
        let after = fs::read(persist_path(&dir)).expect("file still present");
        assert_eq!(
            after.as_slice(),
            &canned_persist,
            "release must not write persist file",
        );
    }
}
