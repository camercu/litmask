# SPEC_DEVEX Review Context

Companion to `docs/SPEC_DEVEX.md`. Purpose: give a fresh reviewer the
implementation-side context needed to review the DevEx spec changes
against the current codebase and docs, without the originating
conversation. Load this alongside `SPEC_DEVEX.md`.

Status as of 2026-06-01: `SPEC_DEVEX.md` is untracked/uncommitted, in the
refine-then-implement phase. No implementation has started. The doc edits
this spec owes to `DEPLOYMENT.md` and `THREAT_MODEL.md` are NOT yet made.

## Overlapping docs — what each currently holds

### README.md (177 lines) — user-facing
Quick-start ships the friction the spec targets. Lines 60-62:

```sh
LITMASK_UNLOCK_KEY=$(awk -F'"' '/^unlock_key/ {print $2}' target/debug/litmask.config) \
    cargo run
```

That `awk`-on-config ritual is friction **F2**. Holds the macro table,
key-provider table (line 122: `StaticProvider | Fixed key (tests only) | --`),
feature table, and the `bind` workflow. No mention of debug auto-key,
sidecar config, key-extractor, ledger, or `inspect --check-decrypt`.

### CONTEXT.md (208 lines) — ubiquitous-language glossary
Authoritative term definitions; any DevEx term must match it:
- **mask key** — 32-byte AEAD key encrypting every per-call-site blob.
- **unlock key** — encrypts the mask key into the wrapper; "Never embedded
  in the binary in the default deployment."
- **seed** — 32-byte build-time master value; derives mask key, unlock key,
  every nonce. Persisted at `target/<profile>/litmask-seed.bin`.
- **wrapper** — 62-byte envelope around the encrypted mask key.
- **blob** — per-call-site ciphertext (nonce + ciphertext + tag, no header).
- **locator** — first 12 bytes of the wrapper; recorded in `litmask.config`.
- **weak key** — 64-byte XOR key derived from the wrapper nonce; backs
  `weak_mask!` (survives bind because it depends only on the nonce).
- **`litmask.config`** — "Deployer-facing TOML... Secret; do not commit."
- **dirty-word scrub** (line 204) — regression test scanning built binaries
  for forbidden litmask-identifying substrings.

### THREAT_MODEL.md (121 lines)
Four-level attacker model; library targets L2 baseline, partial L3. Key
sections the spec must extend:
- **Init-failure plaintext limitation** — after init fails, `mask!()` is
  unusable; failure messages must be plaintext / opaque codes / sysexits.
- **Error variant strings** — derived `Debug`/`Display` emit short,
  non-identifying tags.

`SPEC_DEVEX` §1.7.2 (debug build is self-decrypting / must never be
distributed) is the new accepted trust boundary that belongs here.

### DEPLOYMENT.md (194 lines)
Per-provider runtime setup. Repeats the same `awk` ritual (line 11). Holds:
release profile table, rebind workflow, and **off-box `bind --machine-id`**
(lines 129-163) which matches the spec's vendor-side-default direction, plus
the sysexits exit-code table. The spec's §3.5/§3.6/§7.2 reference edits here
that are not yet made.

### SPECIFICATION.md (2315 lines) — the implementation contract
Section anchors used in the overlap map below.

## Overlap map: DevEx change -> current-impl anchor -> reviewer note

| DevEx item | Current-impl anchor | Reviewer note |
|---|---|---|
| **F1** opaque runtime death | §1.4.1: first `mask!()` lazy-inits with `EnvVarProvider::default()`, bypassing structured errors; §1.9.1 two-layer model (init=Result, decrypt=panic); §1.9.7 sysexit map | Confirmed real. `init_with!` + `sysexit_code()` is the existing good path the dev-loop default skips. |
| **§1.7 debug auto-key** | §1.4.1 init macros `include_bytes!` the caller's `OUT_DIR`; §1.6.1 `KeyProvider::unlock_key() -> Result<_, KeyError>`; §1.9.2 `KeyError::NotFound` vs `InitError::Decryption` are distinct | The NotFound/Decryption split already exists, so §1.7.0's structural "fire only on NotFound" trigger is sound. `StaticProvider` (`litmask/src/provider/static_key.rs`) is public, test-only, carries a "never wire into a release build" caution — reused unchanged as the fallback store. |
| **§1.7.1 single gate at emit** | §1.3.1-1.3.2 `emit` is PROFILE-driven; mask_key passed via `OUT_DIR` files, never `cargo:rustc-env` | `PROFILE` env detection already present; macro-bake path matches the proposed data-flow gate. |
| **S1 seed leak** | §1.3.1 step 3: in release, a freshly generated seed is printed via `cargo:warning=` to the terminal/CI logs | Exactly the leak. Spec's S1 fix (option 1) = warning carries no seed value. |
| **F7 / `inspect --check-decrypt`** | §2.9.2 `inspect` is locator-only: EX_OK (match) / EX_DATAERR (ambiguous) / EX_NOINPUT (absent) | Spec adds a decrypt-success dimension (coherent / incoherent / **indeterminate**). Reviewer MUST confirm the new exit-code table does not collide with these three existing locator-only codes. |
| **off-box bind as default** | §2.9.1.7 `bind --machine-id`; §2.9.3 `show-machine-id`; DEPLOYMENT lines 129-163 | Already implemented; spec promotes it to the documented default. |
| **`weak_mask!`'d env-var name** | §1.7.1 + CONTEXT weak-key def; default `LITMASK_UNLOCK_KEY` obfuscated against the wrapper nonce | `litmask/src/provider/env.rs:47` already does this. |
| **ledger / fingerprint (§7)** | No current equivalent; §1.7.3 wrapper format-version byte; §1.3.3 reproducibility conditions | New surface. Fingerprint = truncated-BLAKE3 of the (public) wrapper — derivable on demand, no impl conflict. |

## Consistency checks for the reviewer

- **Naming**: docs predate the hw-id -> machine-id rename (commit `8538435`).
  Re-grep for stale `hardware` / `hw-id` before implementing.
- **Seed-file path discrepancy** (pre-existing, not DevEx-introduced):
  CONTEXT.md says `target/<profile>/litmask-seed.bin`; SPECIFICATION §1.3.1
  and §1.3.2 say `target/litmask-seed`.
- **`StaticProvider`**: public + test-only is established surface. §1.7 must
  not contradict its "never release" caution — it deliberately leans on it.
- **No project config file** (§1.3.4): the spec's sidecar
  `<binary>.litmask.config` is a *deploy* artifact, not project config —
  distinct, but confirm the framing does not read as violating §1.3.4.
- **Edits owed but not done**: DEPLOYMENT.md + THREAT_MODEL.md
  (referenced by spec §3.5 / §3.6 / §1.7.2 / §7.2).
