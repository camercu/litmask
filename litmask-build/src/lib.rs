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
//! - `target/<profile>/litmask.config` — TOML containing `unlock_key`
//!   (Embedded tier only; every keyed tier re-sources its key material
//!   at runtime, so none writes a config).

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
    CURRENT_CIPHER, EMBEDDED_UNLOCK_DERIVATION_CONTEXT, EXTERNAL_UNLOCK_DERIVATION_CONTEXT,
    FormatVersion, KEY_LEN, MACHINE_ID_DERIVATION_CONTEXT, MACHINE_ID_SALT_DERIVATION_CONTEXT,
    SealTierTag, TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT, WRAPPER_BODY_LEN, WRAPPER_LEN,
    WRAPPER_PLAINTEXT_LEN, aead_encrypt, assemble_wrapper, base64url, decode_machine_id_token,
    derive_embedded_unlock_key, derive_external_unlock_key, derive_machine_id_key,
    derive_two_factor_unlock_key, nonce_for_wrapper, strip_trailing_newline,
};

/// The keying tier `emit()` seals, selected purely from which build
/// inputs are present (§2.4, presence-driven).
enum SealTier {
    /// Keyless floor: the `unlock_key` is derived from the public
    /// wrapper nonce, so the runtime recomputes it with nothing stored.
    Embedded,
    /// `LITMASK_UNLOCK_KEY` was set at build: the `unlock_key` is
    /// `KDF("litmask-unlock-v1", trimmed material)`. The runtime
    /// re-sources the same material and applies the identical KDF, so
    /// the trim MUST match the provider byte-for-byte (single trailing
    /// newline). Held as the raw material (untrimmed) so the trim
    /// happens at one site — `derive` — exactly as the provider trims
    /// at its one derive site.
    External(Zeroizing<String>),
    /// `LITMASK_MACHINE_ID` was set at build: the `unlock_key` is
    /// `derive_machine_id_key(host id, wrapper nonce)`. The runtime
    /// `MachineIdProvider` recomputes the host id via `machine_uid::get()`
    /// and the salt from the embedded wrapper nonce, so a `machine`-tier
    /// binary opens only on the host whose id matches the build's. The
    /// machine id ships only into the build-time derivation, never into
    /// the binary, so it is held here (zeroized on drop) and consumed by
    /// `derive`.
    Machine(Zeroizing<String>),
    /// Both `LITMASK_MACHINE_ID` and `LITMASK_UNLOCK_KEY` were set at
    /// build: the `unlock_key` is the §2.3 two-factor composition of the
    /// machine factor's finished key and the external factor's finished
    /// key. Holds both raw inputs (zeroized on drop); each is trimmed and
    /// derived at the one `derive` site, then composed machine-first. The
    /// runtime re-sources the host id (`machine_uid::get()`) and the
    /// external material (its provider) and recomposes the identical key.
    MachineExternal(Zeroizing<String>, Zeroizing<String>),
}

impl SealTier {
    /// Presence-driven selection from the external channel. Reads
    /// `LITMASK_UNLOCK_KEY` through the same `std::env::var` (UTF-8)
    /// path the runtime [`EnvVarProvider`] uses, so build and runtime
    /// agree on the material bytes.
    fn from_env() -> Self {
        Self::from_material(
            std::env::var("LITMASK_UNLOCK_KEY").ok(),
            std::env::var("LITMASK_MACHINE_ID").ok(),
        )
    }

    /// Pure core of [`SealTier::from_env`]: maps the optional factor
    /// channels to a tier without touching process state, so the
    /// presence rule is unit-testable under `forbid(unsafe_code)`.
    ///
    fn from_material(unlock: Option<String>, machine: Option<String>) -> Self {
        match (unlock, machine) {
            (None, None) => Self::Embedded,
            (Some(s), None) => Self::External(Zeroizing::new(s)),
            (None, Some(m)) => Self::Machine(Zeroizing::new(m)),
            (Some(s), Some(m)) => Self::MachineExternal(Zeroizing::new(m), Zeroizing::new(s)),
        }
    }

    /// The build-authoritative tier this seal publishes. Its
    /// [`SealTierTag::as_str`] spelling rides `cargo:rustc-env` and the
    /// `init!` macro cross-checks against it.
    fn tag_kind(&self) -> SealTierTag {
        match self {
            Self::Embedded => SealTierTag::Embedded,
            Self::External(_) => SealTierTag::External,
            Self::Machine(_) => SealTierTag::Machine,
            Self::MachineExternal(_, _) => SealTierTag::MachineExternal,
        }
    }
}

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

    // Presence-driven tier selection (§2.4): which build inputs are set
    // decides the sealed tier.
    let tier = SealTier::from_env();

    // Publish the build-authoritative seal-tier tag and re-run when
    // either factor channel changes (§2.4).
    for directive in seal_tier_directives(&tier) {
        println!("{directive}");
    }

    let out_dir: PathBuf = std::env::var_os("OUT_DIR")
        .expect("cargo did not set OUT_DIR")
        .into();
    let profile_dir = profile_dir_of(&out_dir);
    let profile = Profile::from_env();

    // §1.1 silent-floor guard: a release build left at the Embedded floor
    // opens forever and looks healthy, so flag it on the build log.
    if let Some(warning) = embedded_floor_warning(&tier, profile) {
        println!("{warning}");
    }

    let (mut seed, _seed_source) = source_seed(&profile_dir, profile);

    let artifacts = BuildArtifacts::derive(&seed, &tier);
    seed.zeroize();
    artifacts.write_to(&out_dir, &profile_dir, &tier);
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
    /// 32-byte ChaCha20-Poly1305 key that encrypts the wrapper. Its
    /// origin is tier-dependent (nonce-derived for Embedded, a KDF of
    /// re-sourced material for the keyed tiers). Written into
    /// `litmask.config` only for the Embedded tier; keyed tiers
    /// re-derive it at runtime and never read the config.
    unlock_key: [u8; KEY_LEN],
    /// Assembled wrapper bytes — cleartext nonce followed by the AEAD
    /// sealing of `version_byte || mask_key` under `unlock_key`.
    /// Persisted to `OUT_DIR/litmask_wrapper.bin` and embedded into
    /// user binaries via `include_bytes!`.
    wrapper: [u8; WRAPPER_LEN],
}

/// Recover the raw machine id from the `LITMASK_MACHINE_ID` value, which
/// is a self-checking token minted by `litmask show-machine-id` (§4.1.1).
///
/// A single trailing newline is stripped first — exactly as the External
/// tier trims its material — so a token sourced through a newline-bearing
/// channel (a file read, `echo`) still validates. The check group is then
/// verified and the raw id returned; the runtime `MachineIdProvider`
/// recomputes that same raw id via `machine_uid::get()`, so build and
/// runtime stay in lock-step.
///
/// # Panics
///
/// Panics at build time if the value is not a valid token (no check
/// group, or a check mismatch from a mistyped id). Rejecting here turns
/// what would otherwise be an opaque runtime `decryption_failed` on the
/// deploy host into an actionable build error (§4.1.1).
fn machine_seal_id(env_value: &str) -> String {
    let trimmed = strip_trailing_newline(env_value.as_bytes());
    let token = core::str::from_utf8(trimmed).expect("LITMASK_MACHINE_ID is UTF-8");
    decode_machine_id_token(token)
        .unwrap_or_else(|e| {
            panic!(
                "LITMASK_MACHINE_ID is not a valid `litmask show-machine-id` token ({e}); \
                 capture it with `litmask show-machine-id` on the target host"
            )
        })
        .to_owned()
}

impl BuildArtifacts {
    /// Derive the full artifact set from a build seed and the selected
    /// keying `tier`. Pure: same seed + tier in, byte-identical fields
    /// out.
    fn derive(seed: &[u8; KEY_LEN], tier: &SealTier) -> Self {
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

        // The wrapper structure (nonce ‖ AEAD) is tier-independent; only
        // the key sealing it differs.
        //
        // - Embedded: unlock_key derived from the public wrapper nonce,
        //   so the runtime recomputes the identical key from the
        //   embedded nonce with no stored material (§1). The seed feeds
        //   only mask_key + the nonce.
        // - External: unlock_key = KDF("litmask-unlock-v1", trimmed
        //   operator material). The runtime provider re-sources the same
        //   material and applies the identical KDF — the trim here MUST
        //   match the provider byte-for-byte (single trailing newline).
        let unlock_key = match tier {
            SealTier::Embedded => {
                derive_embedded_unlock_key(EMBEDDED_UNLOCK_DERIVATION_CONTEXT, &wrapper_nonce)
            }
            SealTier::External(material) => derive_external_unlock_key(
                EXTERNAL_UNLOCK_DERIVATION_CONTEXT,
                strip_trailing_newline(material.as_bytes()),
            ),
            // Machine: unlock_key = derive_machine_id_key(host id, nonce).
            // The salt is the wrapper nonce (derived inside the KDF), so
            // the runtime recomputes the identical key from the embedded
            // nonce + the host's own machine id. The id is trimmed of a
            // trailing newline — exactly as External trims its material —
            // so a `LITMASK_MACHINE_ID` sourced through a newline-bearing
            // channel still matches `machine_uid::get()` (which emits no
            // trailing newline) at runtime.
            SealTier::Machine(machine_id) => derive_machine_id_key(
                MACHINE_ID_DERIVATION_CONTEXT,
                MACHINE_ID_SALT_DERIVATION_CONTEXT,
                machine_seal_id(machine_id).as_bytes(),
                &wrapper_nonce,
            ),
            // MachineExternal: the §2.3 two-factor composition. Each
            // factor is finished independently at this one site — the
            // machine factor exactly as the Machine tier (host id + nonce
            // salt), the external factor exactly as the External tier
            // (trimmed material) — then composed machine-first. The
            // runtime recomposes the identical key from the host id +
            // embedded nonce and the re-sourced external material, so a
            // newline on either build channel must be trimmed here to
            // match (§2.4).
            SealTier::MachineExternal(machine_id, material) => {
                let machine_key = derive_machine_id_key(
                    MACHINE_ID_DERIVATION_CONTEXT,
                    MACHINE_ID_SALT_DERIVATION_CONTEXT,
                    machine_seal_id(machine_id).as_bytes(),
                    &wrapper_nonce,
                );
                let external_key = derive_external_unlock_key(
                    EXTERNAL_UNLOCK_DERIVATION_CONTEXT,
                    strip_trailing_newline(material.as_bytes()),
                );
                derive_two_factor_unlock_key(
                    TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT,
                    &machine_key,
                    &external_key,
                )
            }
        };

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
    /// time; `profile_dir` receives `litmask.config` only for the
    /// Embedded tier.
    ///
    /// Only the Embedded tier writes a config: its `unlock_key` is the
    /// nonce-derived floor key, recomputed identically at runtime. The
    /// External and Machine tiers re-source their key material at runtime
    /// (operator channel / host machine id), so their derived `unlock_key`
    /// is neither needed nor reusable as material — emitting it would be a
    /// footgun and would write a secret to an artifact nothing consumes
    /// (§3.1).
    fn write_to(&self, out_dir: &Path, profile_dir: &Path, tier: &SealTier) {
        write_secret(&out_dir.join("litmask_seed.bin"), &self.seed);
        write_secret(&out_dir.join("litmask_key.bin"), &self.mask_key);
        write_secret(&out_dir.join("litmask_wrapper.bin"), &self.wrapper);
        if matches!(tier, SealTier::Embedded) {
            write_config(&profile_dir.join("litmask.config"), &self.unlock_key);
        }
    }
}

impl Drop for BuildArtifacts {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.mask_key.zeroize();
        self.unlock_key.zeroize();
    }
}

/// Indicates which of the three sources the seed came from. Retained
/// for `source_seed`'s unit tests, which assert the priority order;
/// `emit()` does not branch on it (the seed is never echoed, §6.2).
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

/// §1.1 Embedded-floor guard. Returns the `cargo:warning=` line to emit
/// when a *release* build seals at the Embedded floor — the tier whose
/// `unlock_key` is recoverable from the artifact.
///
/// Presence-driven: keyed off the resolved tier tag, not the `init!`
/// form, so the one emission covers both a deliberately bare `init!()`
/// and an omitted `init!` (lazy-init). Returns `None` for any keyed tier
/// (which fails loud at runtime when its key is absent) and for any
/// non-release profile. The string rides the build-log channel only — it
/// is never baked into the shipped binary (§7.2), and carries no secret.
fn embedded_floor_warning(tier: &SealTier, profile: Profile) -> Option<String> {
    (profile == Profile::Release && tier.tag_kind() == SealTierTag::Embedded).then(|| {
        "cargo:warning=litmask: Embedded obfuscation floor in a release build — the wrapper \
         key is recoverable from the artifact. Set LITMASK_UNLOCK_KEY or LITMASK_MACHINE_ID \
         to seal a stronger tier."
            .to_string()
    })
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
fn seal_tier_directives(tier: &SealTier) -> [String; 3] {
    [
        format!(
            "cargo:rustc-env=LITMASK_SEAL_TIER={}",
            tier.tag_kind().as_str()
        ),
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
    use litmask_internal::encode_machine_id_token;
    use tempfile::TempDir;

    #[test]
    fn machine_seal_id_decodes_a_valid_token_to_its_raw_id() {
        let token = encode_machine_id_token("host-id-abc");
        assert_eq!(machine_seal_id(&token), "host-id-abc");
    }

    #[test]
    fn machine_seal_id_strips_a_trailing_newline_before_decoding() {
        let token = encode_machine_id_token("host-id-abc");
        assert_eq!(machine_seal_id(&format!("{token}\n")), "host-id-abc");
    }

    #[test]
    #[should_panic(expected = "not a valid `litmask show-machine-id` token")]
    fn machine_seal_id_rejects_a_non_token_value() {
        // A raw id with no check group must be rejected at build time,
        // not silently sealed and surfaced as a runtime decrypt failure.
        let _ = machine_seal_id("host-id-abc");
    }

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
        let first = BuildArtifacts::derive(&seed, &SealTier::Embedded);
        let second = BuildArtifacts::derive(&seed, &SealTier::Embedded);
        assert_eq!(first.mask_key, second.mask_key);
        assert_eq!(first.unlock_key, second.unlock_key);
        assert_eq!(first.wrapper, second.wrapper);
    }

    /// Distinct seeds must yield distinct keys + wrappers. Guards
    /// against any future refactor that accidentally shares state
    /// across `derive` calls.
    #[test]
    fn build_artifacts_derive_is_seed_sensitive() {
        let a = BuildArtifacts::derive(&[0xAAu8; KEY_LEN], &SealTier::Embedded);
        let b = BuildArtifacts::derive(&[0xBBu8; KEY_LEN], &SealTier::Embedded);
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
        let artifacts = BuildArtifacts::derive(&seed, &SealTier::Embedded);
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
        let directives = seal_tier_directives(&SealTier::Embedded);
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

        let artifacts = BuildArtifacts::derive(&seed, &SealTier::Embedded);
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
        use litmask_internal::{
            EMBEDDED_UNLOCK_DERIVATION_CONTEXT, decrypt_wrapper, derive_embedded_unlock_key,
        };
        let seed = [0x33u8; KEY_LEN];
        let artifacts = BuildArtifacts::derive(&seed, &SealTier::Embedded);
        let recomputed = derive_embedded_unlock_key(
            EMBEDDED_UNLOCK_DERIVATION_CONTEXT,
            &nonce_for_wrapper(&seed),
        );
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
            BuildArtifacts::derive(&seed_a, &SealTier::Embedded).wrapper,
            BuildArtifacts::derive(&seed_b, &SealTier::Embedded).wrapper,
        );
    }

    fn external(material: &str) -> SealTier {
        SealTier::External(Zeroizing::new(material.to_string()))
    }

    /// Wrap a raw id in the self-checking token form `emit()` expects on
    /// the `LITMASK_MACHINE_ID` channel — the build decodes it back to the
    /// raw id before deriving (§4.1.1).
    fn machine(id: &str) -> SealTier {
        SealTier::Machine(Zeroizing::new(encode_machine_id_token(id)))
    }

    fn machine_external(id: &str, material: &str) -> SealTier {
        SealTier::MachineExternal(
            Zeroizing::new(encode_machine_id_token(id)),
            Zeroizing::new(material.to_string()),
        )
    }

    /// Presence-driven tier selection (§2.4): no channel floors to
    /// Embedded, the external channel selects External, the machine
    /// channel selects Machine.
    #[test]
    fn from_material_presence_selects_tier() {
        assert_eq!(
            SealTier::from_material(None, None).tag_kind(),
            SealTierTag::Embedded,
        );
        assert_eq!(
            SealTier::from_material(Some("operator secret".to_string()), None).tag_kind(),
            SealTierTag::External,
        );
        assert_eq!(
            SealTier::from_material(None, Some("host-id-abc".to_string())).tag_kind(),
            SealTierTag::Machine,
        );
        assert_eq!(
            SealTier::from_material(
                Some("operator secret".to_string()),
                Some("host-id-abc".to_string()),
            )
            .tag_kind(),
            SealTierTag::MachineExternal,
        );
    }

    /// §1.1 floor guard: only a *release* build sealed at the Embedded
    /// floor warns; every keyed tier and every debug build is silent.
    #[test]
    fn embedded_release_emits_floor_warning() {
        let warning = embedded_floor_warning(&SealTier::Embedded, Profile::Release)
            .expect("embedded release build must warn");
        assert!(
            warning.starts_with("cargo:warning="),
            "floor warning must ride the cargo:warning= channel; got {warning:?}",
        );
    }

    #[test]
    fn embedded_debug_is_silent() {
        assert!(embedded_floor_warning(&SealTier::Embedded, Profile::Debug).is_none());
    }

    /// Presence-driven: a keyed tier in release is NOT the floor, so no
    /// warning — even though the profile is release.
    #[test]
    fn keyed_release_tiers_are_silent() {
        for tier in [
            external("operator secret"),
            machine("host-id-abc"),
            machine_external("host-id-abc", "operator secret"),
        ] {
            assert!(
                embedded_floor_warning(&tier, Profile::Release).is_none(),
                "keyed tier {:?} must not emit the floor warning",
                tier.tag_kind(),
            );
        }
    }

    /// A `MachineExternal` build publishes the `machine_external` seal tag
    /// over rustc-env (the `init!(machine_id + <provider>)` form
    /// cross-checks against it).
    #[test]
    fn machine_external_tier_publishes_machine_external_seal_tag() {
        let directives = seal_tier_directives(&machine_external("host-id-abc", "operator secret"));
        assert!(
            directives
                .iter()
                .any(|d| d == "cargo:rustc-env=LITMASK_SEAL_TIER=machine_external"),
            "missing machine_external tier tag; got {directives:?}",
        );
    }

    /// The `MachineExternal` `unlock_key` is
    /// `compose(machine_key, external_key)` — byte-identical to what the
    /// runtime derives by composing the `MachineIdProvider` key with the
    /// external provider's key — and the sealed wrapper opens under it.
    /// Without this, a successful two-factor `emit()` could ship a wrapper
    /// no runtime can open.
    #[test]
    fn machine_external_unlock_key_is_composed_and_round_trips() {
        use litmask_internal::{
            TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT, decrypt_wrapper, derive_two_factor_unlock_key,
        };
        let seed = [0x71u8; KEY_LEN];
        let artifacts = BuildArtifacts::derive(&seed, &machine_external("host-id-abc", "secret"));
        let nonce = nonce_for_wrapper(&seed);
        let machine_key = derive_machine_id_key(
            MACHINE_ID_DERIVATION_CONTEXT,
            MACHINE_ID_SALT_DERIVATION_CONTEXT,
            b"host-id-abc",
            &nonce,
        );
        let external_key =
            derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, b"secret");
        let expected = derive_two_factor_unlock_key(
            TWO_FACTOR_UNLOCK_DERIVATION_CONTEXT,
            &machine_key,
            &external_key,
        );
        assert_eq!(
            artifacts.unlock_key, expected,
            "two-factor unlock_key must be the composed machine+external key",
        );
        let recovered = decrypt_wrapper(&artifacts.unlock_key, &artifacts.wrapper).expect("round");
        assert_eq!(recovered, artifacts.mask_key);
    }

    /// Both factors are trimmed of a single trailing newline before
    /// derivation, exactly as the single-factor tiers trim. The runtime
    /// sources the machine id from `machine_uid::get()` (no newline) and
    /// the external material from the provider (one newline stripped), so
    /// a newline on either build channel must not change the composed
    /// `unlock_key`.
    #[test]
    fn machine_external_factors_strip_trailing_newline() {
        let seed = [0x71u8; KEY_LEN];
        let clean = BuildArtifacts::derive(&seed, &machine_external("host-id-abc", "secret"));
        // Model a newline on each build channel: the machine-id token and
        // the external material each arrive with a trailing newline.
        let newlined = BuildArtifacts::derive(
            &seed,
            &SealTier::MachineExternal(
                Zeroizing::new(format!("{}\n", encode_machine_id_token("host-id-abc"))),
                Zeroizing::new("secret\n".to_string()),
            ),
        );
        assert_eq!(
            clean.unlock_key, newlined.unlock_key,
            "trailing newline on either factor must not change the composed unlock_key",
        );
        assert_eq!(clean.wrapper, newlined.wrapper);
    }

    /// The `MachineExternal` tier writes no `litmask.config`: both factors
    /// are re-sourced at runtime (host id + operator channel), so the
    /// composed key is neither needed nor reusable as material. Only
    /// Embedded writes a config.
    #[test]
    fn write_to_omits_config_for_machine_external_tier() {
        let seed = [0x71u8; KEY_LEN];
        let out = TempDir::new().expect("out dir");
        let profile = TempDir::new().expect("profile dir");
        let config = profile.path().join("litmask.config");

        BuildArtifacts::derive(&seed, &machine_external("host-id-abc", "secret")).write_to(
            out.path(),
            profile.path(),
            &machine_external("host-id-abc", "secret"),
        );
        assert!(
            !config.exists(),
            "machine_external tier must not write litmask.config",
        );
        assert!(out.path().join("litmask_wrapper.bin").exists());
    }

    /// A Machine build publishes the `machine` seal tag over rustc-env
    /// (the `init!(machine_id)` form cross-checks against it).
    #[test]
    fn machine_tier_publishes_machine_seal_tag() {
        let directives = seal_tier_directives(&machine("host-id-abc"));
        assert!(
            directives
                .iter()
                .any(|d| d == "cargo:rustc-env=LITMASK_SEAL_TIER=machine"),
            "missing machine tier tag; got {directives:?}",
        );
    }

    /// The Machine `unlock_key` is `derive_machine_id_key(host id, wrapper
    /// nonce)` — byte-identical to what the runtime `MachineIdProvider`
    /// derives from the same id + embedded nonce — and the sealed wrapper
    /// opens under it. Without this, a successful machine `emit()` could
    /// ship a wrapper no runtime provider can open.
    #[test]
    fn machine_unlock_key_is_id_and_nonce_derived_and_round_trips() {
        use litmask_internal::decrypt_wrapper;
        let seed = [0x71u8; KEY_LEN];
        let artifacts = BuildArtifacts::derive(&seed, &machine("host-id-abc"));
        let expected = derive_machine_id_key(
            MACHINE_ID_DERIVATION_CONTEXT,
            MACHINE_ID_SALT_DERIVATION_CONTEXT,
            b"host-id-abc",
            &nonce_for_wrapper(&seed),
        );
        assert_eq!(
            artifacts.unlock_key, expected,
            "machine unlock_key must be the id+nonce KDF",
        );
        let recovered = decrypt_wrapper(&artifacts.unlock_key, &artifacts.wrapper).expect("round");
        assert_eq!(recovered, artifacts.mask_key);
    }

    /// A trailing newline on the build-time machine id is stripped before
    /// derivation, exactly as the External tier trims its material. The
    /// runtime sources the id from `machine_uid::get()` (no trailing
    /// newline), so an operator who seals with `LITMASK_MACHINE_ID` set
    /// via a newline-bearing channel (a file read, `echo`) must still
    /// recover a binary that opens on the host — otherwise the seal and
    /// runtime diverge into an opaque `decryption_failed`.
    #[test]
    fn machine_id_trailing_newline_is_stripped_before_derivation() {
        let seed = [0x71u8; KEY_LEN];
        let clean = BuildArtifacts::derive(&seed, &machine("host-id-abc")).unlock_key;
        // Model a newline-bearing channel: the token arrives with a
        // trailing newline appended after its check group.
        let newline = BuildArtifacts::derive(
            &seed,
            &SealTier::Machine(Zeroizing::new(format!(
                "{}\n",
                encode_machine_id_token("host-id-abc")
            ))),
        )
        .unlock_key;
        assert_eq!(
            clean, newline,
            "trailing newline must not change the sealed machine unlock_key",
        );
    }

    /// The Machine tier writes no `litmask.config` (its key is re-sourced
    /// from the host at runtime, like External). Only Embedded writes one.
    #[test]
    fn write_to_omits_config_for_machine_tier() {
        let seed = [0x71u8; KEY_LEN];
        let out = TempDir::new().expect("out dir");
        let profile = TempDir::new().expect("profile dir");
        let config = profile.path().join("litmask.config");

        BuildArtifacts::derive(&seed, &machine("host-id-abc")).write_to(
            out.path(),
            profile.path(),
            &machine("host-id-abc"),
        );
        assert!(
            !config.exists(),
            "machine tier must not write litmask.config"
        );
        assert!(out.path().join("litmask_wrapper.bin").exists());
    }

    /// An External build publishes the `external` seal tag over
    /// rustc-env (the `init!(<provider>)` form cross-checks against it).
    #[test]
    fn external_tier_publishes_external_seal_tag() {
        let directives = seal_tier_directives(&external("operator secret"));
        assert!(
            directives
                .iter()
                .any(|d| d == "cargo:rustc-env=LITMASK_SEAL_TIER=external"),
            "missing external tier tag; got {directives:?}",
        );
    }

    /// The External `unlock_key` is `KDF("litmask-unlock-v1", material)`
    /// — byte-identical to what the runtime provider derives from the
    /// same `LITMASK_UNLOCK_KEY` material — and the sealed wrapper opens
    /// under it. Without this, a successful external `emit()` could ship
    /// a wrapper no runtime provider can open.
    #[test]
    fn external_unlock_key_is_kdf_of_material_and_round_trips() {
        use litmask_internal::decrypt_wrapper;
        let seed = [0x71u8; KEY_LEN];
        let artifacts = BuildArtifacts::derive(&seed, &external("operator secret"));
        let expected =
            derive_external_unlock_key(EXTERNAL_UNLOCK_DERIVATION_CONTEXT, b"operator secret");
        assert_eq!(
            artifacts.unlock_key, expected,
            "external unlock_key must be the KDF of the raw material",
        );
        let recovered = decrypt_wrapper(&artifacts.unlock_key, &artifacts.wrapper).expect("round");
        assert_eq!(recovered, artifacts.mask_key);
    }

    /// The build's trim MUST match the runtime provider's: a single
    /// trailing newline on the external material is stripped before
    /// derivation, so a key file (editor newline) and an env var
    /// carrying the same secret seal the identical wrapper.
    #[test]
    fn external_trim_strips_one_trailing_newline_matching_runtime() {
        let seed = [0x71u8; KEY_LEN];
        let bare = BuildArtifacts::derive(&seed, &external("secret"));
        let newlined = BuildArtifacts::derive(&seed, &external("secret\n"));
        assert_eq!(
            bare.unlock_key, newlined.unlock_key,
            "trailing newline must not change the derived unlock_key",
        );
        assert_eq!(bare.wrapper, newlined.wrapper);
    }

    /// The External tier writes no `litmask.config`: its derived key is
    /// neither consumed nor reusable as material, so emitting it would
    /// be a footgun and a needless secret-to-artifact write (§3.1). The
    /// Embedded tier still writes the config.
    #[test]
    fn write_to_omits_config_for_external_tier() {
        let seed = [0x71u8; KEY_LEN];
        let out = TempDir::new().expect("out dir");
        let profile = TempDir::new().expect("profile dir");
        let config = profile.path().join("litmask.config");

        BuildArtifacts::derive(&seed, &external("operator secret")).write_to(
            out.path(),
            profile.path(),
            &external("operator secret"),
        );
        assert!(
            !config.exists(),
            "external tier must not write litmask.config",
        );
        // The wrapper blob is still emitted for the runtime to embed.
        assert!(out.path().join("litmask_wrapper.bin").exists());

        BuildArtifacts::derive(&seed, &SealTier::Embedded).write_to(
            out.path(),
            profile.path(),
            &SealTier::Embedded,
        );
        assert!(config.exists(), "embedded tier must write litmask.config",);
    }
}
