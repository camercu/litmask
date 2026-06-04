# Pre-1.0 Security Audit

Audit date: 2026-05-27
Auditor: Cameron Unterberger + Claude

## Strings hygiene

**Status: pass**

Release-profile builds (strip=symbols, debug=false, panic=abort, lto=true)
are scrubbed by `example_scrub.rs` integration tests against a curated
forbidden-word list (`litmask`, `mask_key`, `unlock_key`, `decrypt`,
`cipher`, `chacha`, `aes`, `tamper`, `nonce`, `InitError`, `KeyError`).

Debug builds contain identifier strings from DWARF info and dependency
crate names — this is expected and not a security concern (debug builds
are not deployment artifacts).

Two examples are intentionally excluded from the identifier scrub
(`file_provider`, `machine_id_provider`) because they reference canonical
env-var names containing forbidden substrings for pedagogical clarity.
These are documented in `example_scrub.rs`.

**Category: accepted-risk**
Debug-build string leakage is inherent to Rust's debug info. The
recommended release profile eliminates it. Short `Display` variant
tags are accepted (they don't identify litmask); panic messages use
no identifying text.

## Panic hygiene

**Status: pass**

Grep of the runtime decryption path (`litmask/src/runtime.rs`) for
`.expect(`, `panic!("`, `unwrap_or_else(|_| panic!`, `unreachable!(`
with custom messages: **zero hits**.

All `panic!()` calls in the runtime are bare (no message argument).
The `.expect()` and `panic!("...")` hits in
`key.rs`, `error.rs`, and provider modules are exclusively in
`#[cfg(test)]` blocks.

**Category: accepted-risk**
Bare `panic!()` produces std's generic panic message, which appears in
many Rust programs and does not identify litmask.

## Key zeroization

**Status: pass**

- `UnlockKey` and `MaskKey` both derive `Zeroize` + `ZeroizeOnDrop`.
- Neither derives `Clone` — no accidental copies.
- Neither implements `Debug` with key contents — `UnlockKey`'s `Debug`
  prints `UnlockKey([REDACTED])`.
- `EnvVarProvider` wraps the env-var `String` in `Zeroizing<String>`.
- `MachineIdProvider` wraps the machine-id `String` in
  `Zeroizing<String>`.
- `FileProvider` reads into a `Zeroizing<Vec<u8>>` buffer.
- `bind.rs` uses `Zeroizing` for the decrypted `mask_key` intermediate.

No path was found where key bytes escape into `String` formatting,
log lines, error variants, or long-lived buffers.

**Category: accepted-risk**
`Zeroize` is best-effort against compiler optimizations (the standard
caveat for all Rust zeroization). The `zeroize` crate's approach
(volatile writes) is the state of the art. Runtime memory inspection
is explicitly out of scope.

## Threat-model claim verification

**Status: pass**

Reviewed `THREAT_MODEL.md`, `README.md`, `DEPLOYMENT.md`, and
crate-level rustdoc. No claim promises resistance against out-of-scope
capabilities:

- No mention of runtime memory protection.
- No anti-debugging claims.
- No side-channel resistance claims.
- "Does NOT protect against" section present in README, DEPLOYMENT.md,
  and THREAT_MODEL.md.
- Level 3 resistance explicitly hedged: "does not promise complete
  Level 3 resistance."

Tone conforms to deliberate understatement policy.

**Category: accepted-risk** (by design — honesty is the policy)

## Dependency surface

**Status: pass**

`cargo tree --all-features` review:

| Dependency | Purpose | Notes |
|---|---|---|
| `chacha20poly1305` | AEAD cipher | RustCrypto, widely audited |
| `aes-gcm` | AEAD cipher | RustCrypto, widely audited |
| `blake3` | Key derivation, nonce | Official impl, constant-time eq |
| `zeroize` | Key wiping | RustCrypto standard |
| `base64ct` | Base64url encoding | Constant-time, RustCrypto |
| `machine-uid` | Machine ID (CLI) | Small crate, reads `/etc/machine-id` or equivalent |
| `clap` | CLI argument parsing | Standard, CLI-only |
| `toml` | Config parsing | Standard, CLI-only |

No unexpected transitive dependencies. All crypto dependencies are from
the RustCrypto ecosystem. `deny.toml` enforces: no advisories, no
yanked crates, permissive licenses only, crates.io registry only.

**Category: accepted-risk**
`machine-uid` is a small crate without formal audit. Its failure mode
(returns error → exit 69) is well-handled. The alternative (reimplementing
platform-specific machine-ID lookup) would increase maintenance burden
without security benefit.

## Timing surface

**Status: informational**

The AEAD crates (`chacha20poly1305`, `aes-gcm`) use constant-time
primitives internally. `blake3` uses `constant_time_eq` for comparisons.

Surrounding Rust code (error branching, `locate_wrapper` scanning) is
not constant-time. Side-channel attacks are out of scope but noted
for users who assess timing properties.

**Category: accepted-risk** — side-channel attacks are out of scope.
Documented in THREAT_MODEL.md timing section.

## Bind atomicity

**Status: pass**

POSIX atomic commit protocol pinned by
`commit_sequence_matches_atomic_rename_protocol` unit test. The test
asserts the exact call sequence through the `CommitFs` trait:

1. Write temp config
2. Fsync temp config
3. Write temp binary
4. Copy permissions
5. Fsync temp binary
6. Rename temp binary → binary
7. Rename temp config → config
8. Fsync parent directories (best-effort, deduplicated)

Both files use temp+rename so a crash during any write step leaves the
originals intact (retryable).

`commit_writes_binary_and_config_atomically` exercises the real
`StdCommitFs` path on the host OS.

Windows bind uses `MoveFileExW` with `MOVEFILE_WRITE_THROUGH`.

**Category: accepted-risk**
Power loss between step 5 (binary rename) and step 6 (config rename)
leaves new binary + old config (inconsistent). Recovery requires
rebind. Filesystem journals on modern OS kernels make this window
extremely narrow.

## Reproducibility

**Status: pass**

`LITMASK_RNG_SEED` env var seeds all key and nonce derivation.
`litmask-build` sources the seed with priority:
1. `LITMASK_RNG_SEED` (deterministic, cross-machine)
2. Persisted seed file in target dir (same-machine stability)
3. Fresh random (new build)

Integration test `reproducible_builds_produce_identical_artifacts`
verifies byte-identical output with fixed seed. Reproducibility
conditions (same seed, same source, same toolchain) are documented.

**Category: accepted-risk**
Reproducibility depends on `LITMASK_RNG_SEED` being set explicitly.
Without it, each clean build generates a new seed. This is documented
behavior, not a vulnerability.

## Format-version and cipher-id rejection

**Status: pass**

`litmask-internal/src/cipher.rs` validates version and cipher bytes
before decryption:
- Unknown format version → `DecryptError::UnsupportedFormat` →
  `InitError::UnsupportedFormat` (exit 70)
- Unknown cipher ID → `DecryptError::UnsupportedCipher` →
  `InitError::UnsupportedCipher` (exit 70)
- Truncated wrapper → AEAD authentication failure →
  `InitError::Decryption` (exit 65)

Unit tests cover: bad version byte, bad cipher byte, truncated wrappers.

**Category: accepted-risk** — none; these are clean passes.

## Summary

| Finding | Category |
|---|---|
| Debug-build string leakage | accepted-risk |
| Bare `panic!()` in runtime | accepted-risk |
| `Zeroize` best-effort caveat | accepted-risk |
| Threat-model honesty policy | accepted-risk |
| `machine-uid` unaudited | accepted-risk |
| Non-constant-time Rust code | accepted-risk |
| Bind power-loss window | accepted-risk |
| Reproducibility requires explicit seed | accepted-risk |

**Blockers: 0**
**Fix-before-1.0: 0**
**Track-for-v2: 0**
**Accepted-risk: 8** (all with justification)
