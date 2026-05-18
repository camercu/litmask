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

    // A release build whose seed was freshly generated (no
    // `LITMASK_RNG_SEED` supplied) has no persistence path, so the
    // only way to reproduce the build later is to capture the
    // generated seed. Print it via `cargo:warning=` so it lands in
    // the developer's terminal output even when stderr is captured.
    if profile == Profile::Release && seed_source == SeedSource::Fresh {
        let encoded = Base64UrlUnpadded::encode_string(&seed);
        println!(
            "cargo:warning=litmask: release build generated a fresh RNG seed. Capture this value for reproducible rebuilds: LITMASK_RNG_SEED={encoded}",
        );
    }

    let artifacts = BuildArtifacts::derive(&seed);
    seed.zeroize();
    artifacts.write_to(&out_dir, &profile_dir);
    // artifacts' Drop zeroizes mask_key, unlock_key, and the in-memory
    // copy of the seed.
}

/// The five byte arrays produced from a single build seed: the seed
/// itself, the derived `mask_key` and `unlock_key`, and the assembled
/// `wrapper` that encrypts the mask key under the unlock key.
///
/// Constructed via [`BuildArtifacts::derive`] and persisted to disk via
/// [`BuildArtifacts::write_to`]. `derive` is pure — no I/O, no globals
/// — so given the same seed it returns byte-identical fields every
/// call. The split lets tests cover key derivation and wrapper assembly
/// without going through the filesystem.
///
/// Drop zeroizes the secret fields (`seed`, `mask_key`, `unlock_key`).
/// The `wrapper` field is not secret (it's the public ciphertext
/// embedded into user binaries) and is not zeroized.
struct BuildArtifacts {
    /// 32-byte build seed — root of the derivation tree. Persisted to
    /// `OUT_DIR/litmask_seed.bin` for the proc-macro's per-call-site
    /// nonce derivation.
    seed: [u8; KEY_LEN],
    /// 32-byte ChaCha20-Poly1305 key that encrypts every per-call-site
    /// blob. Persisted to `OUT_DIR/litmask_key.bin` for the proc-macro
    /// to read at expansion time.
    mask_key: [u8; KEY_LEN],
    /// 32-byte ChaCha20-Poly1305 key that encrypts the wrapper.
    /// Written into `litmask.config` (deployer-facing TOML); the
    /// runtime reads it back via env var.
    unlock_key: [u8; KEY_LEN],
    /// Assembled wrapper bytes — header + AEAD-encrypted `mask_key`
    /// under `unlock_key`. Persisted to `OUT_DIR/litmask_wrapper.bin`
    /// and embedded into user binaries via `include_bytes!`.
    wrapper: [u8; WRAPPER_LEN],
}

impl BuildArtifacts {
    /// Derive the full artifact set from a build seed. Pure: same seed
    /// in, byte-identical fields out.
    fn derive(seed: &[u8; KEY_LEN]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let mut mask_key = [0u8; KEY_LEN];
        let mut unlock_key = [0u8; KEY_LEN];
        rng.fill_bytes(&mut mask_key);
        rng.fill_bytes(&mut unlock_key);

        let cipher = CipherId::ChaCha20Poly1305;
        let wrapper_nonce = nonce_for_wrapper(seed);
        let mut ciphertext_with_tag =
            aead_encrypt(cipher, &unlock_key, &wrapper_nonce, mask_key.as_slice())
                .expect("wrapper encryption failed");
        let body: &[u8; WRAPPER_BODY_LEN] = ciphertext_with_tag
            .as_slice()
            .try_into()
            .expect("AEAD output of 32-byte plaintext is WRAPPER_BODY_LEN bytes");
        let wrapper = assemble_wrapper(FormatVersion::CURRENT, cipher, &wrapper_nonce, body);
        ciphertext_with_tag.zeroize();

        Self {
            seed: *seed,
            mask_key,
            unlock_key,
            wrapper,
        }
    }

    /// Persist artifacts to disk. `out_dir` receives the three binary
    /// blobs the proc-macro and runtime `include_bytes!` at expansion
    /// time; `profile_dir` receives `litmask.config`, the deployer-facing
    /// TOML the runtime reads via env var.
    fn write_to(&self, out_dir: &Path, profile_dir: &Path) {
        write_secret(&out_dir.join("litmask_seed.bin"), &self.seed);
        write_secret(&out_dir.join("litmask_key.bin"), &self.mask_key);
        write_secret(&out_dir.join("litmask_wrapper.bin"), &self.wrapper);
        write_config(
            &profile_dir.join("litmask.config"),
            &self.unlock_key,
            &self.wrapper,
        );
    }
}

impl Drop for BuildArtifacts {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.mask_key.zeroize();
        self.unlock_key.zeroize();
    }
}

/// Indicates which of the three sources the seed came from. `emit()`
/// consults this to decide whether a release-profile `cargo:warning=`
/// should be emitted (only when freshly generated).
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
/// the persist-on-miss / persist-fresh behavior split between debug
/// and release builds.
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

/// Load the per-build seed in priority order:
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
/// build-time input from the developer, not runtime data subject
/// to the panic-message-hygiene rule that applies in user binaries.
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
    /// override and the debug profile, returning just the seed bytes
    /// to keep the existing assertions tight.
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

    /// When `LITMASK_RNG_SEED` is set, the returned seed comes from
    /// the env var (decoded base64url), regardless of profile or
    /// whether a persist file exists.
    #[test]
    fn source_seed_honors_litmask_rng_seed_env_var() {
        let dir = TempDir::new().expect("tempdir");
        // Persist file must be ignored when an env-var seed is
        // provided — env priority over persist is the invariant
        // this test asserts.
        let canned_persist = [0x42u8; KEY_LEN];
        fs::write(persist_path(&dir), canned_persist).expect("seed file");

        let canned_env = [0xCDu8; KEY_LEN];
        let encoded: OsString = Base64UrlUnpadded::encode_string(&canned_env).into();

        let (seed, source) =
            source_seed_with_env_and_profile(dir.path(), Some(encoded), Profile::Debug);
        assert_eq!(seed, canned_env, "env var must override persist file");
        assert_eq!(source, SeedSource::Env);
    }

    /// End-to-end wire-up: when `source_seed` (not the explicit-env
    /// helper) is invoked with `LITMASK_RNG_SEED` present in the
    /// **process** environment, the returned seed is env-decoded.
    ///
    /// The test uses a self-exec subprocess pattern so the env var is
    /// set by `Command::env` in the child only — no in-process
    /// `std::env::set_var` call, which would require `unsafe` and is
    /// forbidden workspace-wide.
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
        // profile (release seed priority is env → fresh, with no
        // persistence).
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

    /// `derive` is the pure core of `emit()`. Same seed in must yield
    /// byte-identical artifacts out — the spec calls this out as the
    /// reproducible-builds property.
    #[test]
    fn build_artifacts_derive_is_deterministic() {
        let seed = [0x55u8; KEY_LEN];
        let first = BuildArtifacts::derive(&seed);
        let second = BuildArtifacts::derive(&seed);
        assert_eq!(first.mask_key, second.mask_key);
        assert_eq!(first.unlock_key, second.unlock_key);
        assert_eq!(first.wrapper, second.wrapper);
    }

    /// Distinct seeds must yield distinct keys + wrappers. Guards
    /// against any future refactor that accidentally shares state
    /// across `derive` calls.
    #[test]
    fn build_artifacts_derive_is_seed_sensitive() {
        let a = BuildArtifacts::derive(&[0xAAu8; KEY_LEN]);
        let b = BuildArtifacts::derive(&[0xBBu8; KEY_LEN]);
        assert_ne!(a.mask_key, b.mask_key);
        assert_ne!(a.unlock_key, b.unlock_key);
        assert_ne!(a.wrapper, b.wrapper);
    }

    /// The wrapper produced by `derive` must round-trip through the
    /// runtime's decrypt path under the matching `unlock_key`. Without
    /// this, a successful `emit()` could ship a wrapper the runtime
    /// rejects — a silent breakage detectable only at user-program
    /// startup.
    #[test]
    fn build_artifacts_wrapper_round_trips_under_unlock_key() {
        use litmask_internal::cipher::decrypt_wrapper;
        let seed = [0x33u8; KEY_LEN];
        let artifacts = BuildArtifacts::derive(&seed);
        let recovered =
            decrypt_wrapper(&artifacts.unlock_key, &artifacts.wrapper).expect("round-trip");
        assert_eq!(recovered, artifacts.mask_key);
    }
}
