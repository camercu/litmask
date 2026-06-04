//! Build-script helper for `litmask`.
//!
//! Intended use is a single-line `build.rs` in any crate that masks
//! string literals:
//!
//! ```no_run
//! litmask_build::emit();
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
//! - `target/<profile>/litmask.config` — TOML containing `unlock_key`.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};

use rand_chacha::ChaCha20Rng;
// `Rng` is the rand_core 0.10 renaming of the former `RngCore`; it
// provides `fill_bytes` for any seedable RNG. `getrandom::fill` is the
// 0.4+ replacement for the standalone `getrandom::getrandom` function.
use rand_core::{Rng, SeedableRng};
use zeroize::{Zeroize, Zeroizing};

use litmask_internal::{
    CURRENT_CIPHER, FormatVersion, KEY_LEN, WRAPPER_BODY_LEN, WRAPPER_LEN, WRAPPER_PLAINTEXT_LEN,
    aead_encrypt, assemble_wrapper, base64url, derive_embedded_unlock_key, nonce_for_wrapper,
};

/// Build-authoritative seal-tier tag (§2.4). Fixed at `embedded` — the
/// keyless nonce-derived floor whose key travels inside the artifact —
/// until the external / machine tiers make tag selection presence-driven
/// on `LITMASK_UNLOCK_KEY` and `LITMASK_MACHINE_ID`.
const SEAL_TIER_TAG: &str = "embedded";

const CONFIG_HEADER: &str = "\
# litmask.config — build artifact.
# SECRET: contains the runtime `unlock_key` for this build. Do not commit.
# This file is written by litmask-build::emit() at compile time and consumed by
# the litmask runtime (env var).
";

/// Run the build-time mask-key + unlock-key generation pipeline.
///
/// # Panics
///
/// Panics on any I/O failure or unsupported environment. Build scripts
/// run in tightly controlled contexts (cargo sets `OUT_DIR` and
/// `PROFILE`); a failure of either is a build-system bug, not a user
/// error.
pub fn emit() {
    // Re-run when the user changes the seed env var or edits their
    // build script.
    println!("cargo:rerun-if-env-changed=LITMASK_RNG_SEED");
    println!("cargo:rerun-if-changed=build.rs");

    // Publish the build-authoritative seal-tier tag and re-run when
    // either factor channel changes (§2.4).
    for directive in seal_tier_directives() {
        println!("{directive}");
    }

    let out_dir: PathBuf = std::env::var_os("OUT_DIR")
        .expect("cargo did not set OUT_DIR")
        .into();
    let profile_dir = profile_dir_of(&out_dir);
    let profile = Profile::from_env();

    let (mut seed, _seed_source) = source_seed(&profile_dir, profile);

    let artifacts = BuildArtifacts::derive(&seed);
    seed.zeroize();
    artifacts.write_to(&out_dir, &profile_dir);
    // artifacts' Drop zeroizes mask_key, unlock_key, and the in-memory
    // copy of the seed.
}

/// The four byte arrays produced from a single build seed: the seed
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
    /// Assembled wrapper bytes — cleartext nonce followed by the AEAD
    /// sealing of `version_byte || mask_key` under `unlock_key`.
    /// Persisted to `OUT_DIR/litmask_wrapper.bin` and embedded into
    /// user binaries via `include_bytes!`.
    wrapper: [u8; WRAPPER_LEN],
}

impl BuildArtifacts {
    /// Derive the full artifact set from a build seed. Pure: same seed
    /// in, byte-identical fields out.
    fn derive(seed: &[u8; KEY_LEN]) -> Self {
        let mut rng = ChaCha20Rng::from_seed(*seed);
        let mut mask_key = [0u8; KEY_LEN];
        rng.fill_bytes(&mut mask_key);

        // Single-cipher property: the runtime crate selects exactly
        // one cipher at compile time (§1.5.1); `litmask-build`
        // inherits that selection via `CURRENT_CIPHER`. A future
        // dual-cipher CLI build of the build-script would not be
        // valid (the build script writes a wrapper that the runtime
        // crate consumes, and the runtime crate is always single-
        // cipher), so `CURRENT_CIPHER` being undefined in dual mode
        // is the correct compile error to surface.
        let cipher = CURRENT_CIPHER;
        let wrapper_nonce = nonce_for_wrapper(seed);

        // Embedded-tier keying: the unlock_key is derived from the
        // public wrapper nonce, not from the seed's key stream, so the
        // runtime recomputes the identical key from the embedded nonce
        // with no stored material (§1). The seed now feeds only mask_key
        // + the nonce.
        let unlock_key = derive_embedded_unlock_key(&wrapper_nonce);

        // AEAD plaintext is `version_byte || mask_key` — the format
        // version is authenticated inside the wrapper rather than
        // carried in cleartext, so no fixed-value structural byte
        // appears at a known offset in the binary.
        let mut plaintext = Zeroizing::new([0u8; WRAPPER_PLAINTEXT_LEN]);
        plaintext[0] = FormatVersion::CURRENT.to_byte();
        plaintext[1..].copy_from_slice(&mask_key);

        let mut ciphertext_with_tag =
            aead_encrypt(cipher, &unlock_key, &wrapper_nonce, plaintext.as_slice())
                .expect("wrapper encryption failed");
        let body: &[u8; WRAPPER_BODY_LEN] = ciphertext_with_tag.as_slice().try_into().expect(
            "AEAD output of WRAPPER_PLAINTEXT_LEN-byte plaintext is WRAPPER_BODY_LEN bytes",
        );
        let wrapper = assemble_wrapper(&wrapper_nonce, body);
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
        write_config(&profile_dir.join("litmask.config"), &self.unlock_key);
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
fn source_seed(profile_dir: &Path, profile: Profile) -> ([u8; KEY_LEN], SeedSource) {
    source_seed_with_env_and_profile(profile_dir, std::env::var_os("LITMASK_RNG_SEED"), profile)
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
        base64url::decode(text).expect("LITMASK_RNG_SEED must be base64url-encoded"),
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

/// Cargo directives that publish the seal-tier tag and re-run the build
/// when either factor channel changes (§2.4).
///
/// The tag rides `cargo:rustc-env` so it joins the consumer crate's
/// compile fingerprint: flipping a factor recompiles the consumer and
/// re-runs the `init!` form↔tag cross-check. `LITMASK_SEAL_TIER` is the
/// ONLY `LITMASK_*` value litmask sends over rustc-env — it is
/// non-secret; secrets never use this channel (they would log under
/// `cargo --verbose` and inject into downstream rustc).
fn seal_tier_directives() -> [String; 3] {
    [
        format!("cargo:rustc-env=LITMASK_SEAL_TIER={SEAL_TIER_TAG}"),
        "cargo:rerun-if-env-changed=LITMASK_MACHINE_ID".to_string(),
        "cargo:rerun-if-env-changed=LITMASK_UNLOCK_KEY".to_string(),
    ]
}

fn write_config(path: &Path, unlock_key: &[u8; KEY_LEN]) {
    let body = format!(
        "{CONFIG_HEADER}\nunlock_key = \"{}\"\n",
        base64url::encode(unlock_key),
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

    /// A wrong-length persist file MUST be overwritten with a
    /// fresh KEY_LEN-byte seed, not left in place. If the corrupt
    /// file survives, every subsequent build regenerates a fresh
    /// seed (because the read still fails), silently defeating
    /// debug-profile reproducibility — the persisted bytes drift
    /// each build.
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
        let encoded: OsString = base64url::encode(&canned_env).into();

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
            let (seed, source) = source_seed(Path::new(&dir), Profile::Debug);
            assert_eq!(source, SeedSource::Env, "outer wrapper must read env");
            assert_eq!(seed, [0xCDu8; KEY_LEN], "env-decoded seed mismatch");
            return;
        }

        // PARENT: spawn self with the env set + marker.
        let dir = TempDir::new().expect("tempdir");
        let canned = [0xCDu8; KEY_LEN];
        let encoded = base64url::encode(&canned);

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
    /// byte-identical artifacts out — this is the reproducible-builds
    /// property.
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
        use litmask_internal::decrypt_wrapper;
        let seed = [0x33u8; KEY_LEN];
        let artifacts = BuildArtifacts::derive(&seed);
        let recovered =
            decrypt_wrapper(&artifacts.unlock_key, &artifacts.wrapper).expect("round-trip");
        assert_eq!(recovered, artifacts.mask_key);
    }

    /// AC4 (narrowed for §2.4): the build script may publish exactly
    /// one `LITMASK_*` value over the cargo rustc-env channel — the
    /// non-secret `LITMASK_SEAL_TIER` tier tag. Every *other* `LITMASK_*`
    /// rustc-env directive is forbidden: that channel logs at cargo's
    /// `--verbose` setting and injects into downstream rustc, so a
    /// secret (seed, `unlock_key`, machine-id) must never travel it.
    ///
    /// The rule is intent ("no *secret* via rustc-env"), not a blanket
    /// `LITMASK_*` ban — do not evade it by renaming the tag. Reassemble
    /// the prefix from fragments so this test's own source does not trip
    /// the scan.
    #[test]
    fn only_seal_tier_tag_travels_litmask_rustc_env() {
        let src = include_str!("lib.rs");
        let prefix = ["cargo:rustc", "env=LITMASK"].join("-");
        for (idx, _) in src.match_indices(&prefix) {
            let rest = &src[idx + prefix.len()..];
            assert!(
                rest.starts_with("_SEAL_TIER="),
                "only LITMASK_SEAL_TIER may travel the rustc-env channel; \
                 found a different LITMASK_* rustc-env directive — secrets \
                 must never use this channel",
            );
        }
    }

    /// AC: `emit()` publishes the build-authoritative tier tag and the
    /// factor-channel rerun directives (§2.4). The tag is `embedded`
    /// until later tiers make it presence-driven.
    #[test]
    fn emits_embedded_seal_tag_and_factor_rerun_directives() {
        let directives = seal_tier_directives();
        assert!(
            directives
                .iter()
                .any(|d| d == "cargo:rustc-env=LITMASK_SEAL_TIER=embedded"),
            "missing tier tag; got {directives:?}",
        );
        assert!(
            directives
                .iter()
                .any(|d| d == "cargo:rerun-if-env-changed=LITMASK_MACHINE_ID"),
            "missing machine-id rerun directive; got {directives:?}",
        );
        assert!(
            directives
                .iter()
                .any(|d| d == "cargo:rerun-if-env-changed=LITMASK_UNLOCK_KEY"),
            "missing unlock-key rerun directive; got {directives:?}",
        );
    }

    /// AC1: the Embedded-tier `unlock_key` is derived from the wrapper
    /// nonce, NOT drawn from the seed's `ChaCha20` key stream. Pre-change it was
    /// the second key-stream block after `mask_key`; pin that it no
    /// longer is, so a future refactor cannot silently revert to the
    /// seed-derived key.
    #[test]
    fn unlock_key_is_independent_of_seed_key_stream() {
        let seed = [0x55u8; KEY_LEN];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut mask_key = [0u8; KEY_LEN];
        let mut old_stream_unlock = [0u8; KEY_LEN];
        rng.fill_bytes(&mut mask_key);
        rng.fill_bytes(&mut old_stream_unlock);

        let artifacts = BuildArtifacts::derive(&seed);
        assert_eq!(
            artifacts.mask_key, mask_key,
            "mask_key is still the first draw"
        );
        assert_ne!(
            artifacts.unlock_key, old_stream_unlock,
            "unlock_key must be nonce-derived, not the seed's second key-stream block",
        );
    }

    /// AC4: an Embedded-tier build round-trips with the `unlock_key`
    /// recomputed from the wrapper nonce alone — the runtime re-derives
    /// the same key with nothing stored. Recompute it independently from
    /// the seed-derived nonce, confirm it equals the sealed key, and
    /// open the wrapper with it.
    #[test]
    fn embedded_unlock_key_is_nonce_recomputable_and_round_trips() {
        use litmask_internal::{decrypt_wrapper, derive_embedded_unlock_key};
        let seed = [0x33u8; KEY_LEN];
        let artifacts = BuildArtifacts::derive(&seed);
        let recomputed = derive_embedded_unlock_key(&nonce_for_wrapper(&seed));
        assert_eq!(
            recomputed, artifacts.unlock_key,
            "unlock_key must be recomputable from the wrapper nonce",
        );
        let recovered = decrypt_wrapper(&recomputed, &artifacts.wrapper).expect("round-trip");
        assert_eq!(recovered, artifacts.mask_key);
    }

    /// AC5: `litmask.config` MUST begin with a `#`-prefixed comment
    /// block describing the file's purpose and warning that it
    /// contains a secret. Operators read this file in the deployment
    /// pipeline; the header is their first line of defense against
    /// accidental commit / log exposure.
    #[test]
    fn litmask_config_starts_with_hash_comment_block_warning_about_secret() {
        let dir = TempDir::new().expect("tempdir");
        let config_path = dir.path().join("litmask.config");
        write_config(&config_path, &[0u8; KEY_LEN]);
        let body = fs::read_to_string(&config_path).expect("read");
        let first_line = body.lines().next().expect("non-empty config");
        assert!(
            first_line.starts_with('#'),
            "first line must begin with `#`, got: {first_line:?}",
        );
        // The block must explicitly warn that the file holds a
        // secret — without that warning, operators reading just the
        // first line might miss the implication.
        assert!(
            body.lines()
                .take_while(|l| l.starts_with('#'))
                .any(|l| l.to_ascii_lowercase().contains("secret")),
            "comment block must mention 'secret' (case-insensitive); got:\n{body}",
        );
    }

    /// AC1: identical source + toolchain + deps + `LITMASK_RNG_SEED`
    /// → byte-identical per-string ciphertext. The build crate's
    /// `derive` was already pinned for byte-identical wrapper output
    /// under the same seed; this test extends that pin through the
    /// env-var ingestion path so the full env-decoded seed →
    /// wrapper bytes pipeline is locked.
    #[test]
    fn identical_env_seed_produces_byte_identical_wrappers() {
        let canned = [0x99u8; KEY_LEN];
        let encoded: OsString = base64url::encode(&canned).into();
        let dir_a = TempDir::new().expect("tempdir a");
        let dir_b = TempDir::new().expect("tempdir b");
        let (seed_a, _) =
            source_seed_with_env_and_profile(dir_a.path(), Some(encoded.clone()), Profile::Release);
        let (seed_b, _) =
            source_seed_with_env_and_profile(dir_b.path(), Some(encoded), Profile::Release);
        assert_eq!(seed_a, seed_b);
        assert_eq!(
            BuildArtifacts::derive(&seed_a).wrapper,
            BuildArtifacts::derive(&seed_b).wrapper,
        );
    }
}
