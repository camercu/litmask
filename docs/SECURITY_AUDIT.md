# Pre-1.0 Security Audit

Audit date: 2026-05-27
Auditor: Cameron Unterberger + Claude

This is a point-in-time record of accepted-risk dispositions. The facts
each finding rests on live in code and tests (cited inline); THREAT_MODEL.md
is canonical for scope. Re-verify against those, not this prose.

## Strings hygiene

**Status:** pass

Release-profile builds are scrubbed against the forbidden-word list owned by
`litmask/tests/example_scrub.rs` (the list lives there so it cannot drift
from what is enforced). Two examples carry documented carve-outs in that
test: `file_provider` (references the `LITMASK_UNLOCK_KEY_FILE` env name) and
`machine_id_provider` (`blake3` allow-listed — the crate embeds its own name
in unstrippable symbols).

**Disposition:** accepted-risk. Debug-build identifier leakage is inherent to
Rust debug info; the recommended release profile (DEPLOYMENT.md) eliminates
it. Short `Display` tags and bare panic messages do not identify litmask.

## Panic hygiene

**Status:** pass

The runtime decryption path (`litmask/src/runtime/`) carries no custom panic
messages; the `no_custom_panic_messages_in_decryption_path` test enforces it.
Message-bearing `panic!`/`.expect()` outside that path are confined to
`#[cfg(test)]` and rustdoc examples.

**Disposition:** accepted-risk. Bare `panic!()` produces std's generic
message, which appears in many Rust programs and does not identify litmask.

## Key zeroization

**Status:** pass

`UnlockKey`/`MaskKey` (key.rs) derive `Zeroize` + `ZeroizeOnDrop`, do not
derive `Clone`, and redact key bytes from `Debug`; the providers read secrets
into `Zeroizing` buffers. No path leaks key bytes into formatting, logs, or
error variants.

**Disposition:** accepted-risk. `Zeroize` is best-effort against compiler
optimization (the standard caveat); runtime memory inspection is out of scope.

## Threat-model claim verification

**Status:** pass

THREAT_MODEL.md, README.md, DEPLOYMENT.md, and the rustdoc were reviewed: no
claim promises resistance to an out-of-scope capability, and each user-facing
surface states the out-of-scope limitations (inline or by reference to
THREAT_MODEL.md). Level 3 resistance is explicitly hedged.

**Disposition:** accepted-risk by design — deliberate understatement is the
policy.

## Dependency surface

**Status:** pass

`cargo tree --all-features` reviewed against `Cargo.toml`: all crypto
dependencies are RustCrypto-ecosystem; no unexpected transitive crates.
`deny.toml` enforces no advisories, no yanked crates, permissive licenses,
crates.io only.

**Disposition:** accepted-risk. `machine-uid` is small and unaudited; its
failure mode (error → exit 69) is well-handled, and reimplementing
platform-specific machine-ID lookup would add maintenance burden without
security benefit.

## Timing surface

**Status:** informational

The AEAD crates use constant-time primitives and `blake3` uses
`constant_time_eq`; surrounding Rust branching is not constant-time.

**Disposition:** accepted-risk — side-channel attacks are out of scope (see
THREAT_MODEL.md timing section).

## Reproducibility

**Status:** pass

Byte-identical output for a fixed `LITMASK_RNG_SEED` is verified by the
`litmask-build` tests `build_artifacts_derive_is_deterministic` and
`identical_env_seed_produces_byte_identical_wrappers`.

**Disposition:** accepted-risk. Without an explicit seed each clean build
generates a fresh one; this is documented behavior, not a vulnerability.

## Format-version rejection

**Status:** pass

`litmask-internal/src/decrypt.rs` authenticates before it trusts: the
format-version byte lives inside the AEAD plaintext and is checked only after
the tag verifies. Unknown version → `UnsupportedFormat` (exit 70); tamper →
`Decryption` (exit 65). No cipher-id byte exists on the wire — the cipher is
fixed at compile time (`CURRENT_CIPHER`). Unit tests cover both rejection
paths.

**Disposition:** clean pass; no residual risk.

## Summary

| Finding | Category |
|---|---|
| Debug-build string leakage | accepted-risk |
| Bare `panic!()` in runtime | accepted-risk |
| `Zeroize` best-effort caveat | accepted-risk |
| Threat-model honesty policy | accepted-risk |
| `machine-uid` unaudited | accepted-risk |
| Non-constant-time Rust code | accepted-risk |
| Reproducibility requires explicit seed | accepted-risk |

**Blockers: 0** · **Fix-before-1.0: 0** · **Track-for-v2: 0** ·
**Accepted-risk: 7** (all justified)
