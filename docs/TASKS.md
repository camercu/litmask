# litmask — Build-Sealed Devex Adoption Tasks

Source: [docs/SPEC_DEVEX.md](./SPEC_DEVEX.md)
Rolls into: [docs/SPECIFICATION.md](./SPECIFICATION.md), [CONTEXT.md](../CONTEXT.md)
Style reference: [github.com/camercu/relentless](https://github.com/camercu/relentless)

Vertical slices, walking skeleton first. Each task cuts through every
affected layer (wire / build / macro / runtime / CLI / docs) and is
demoable on its own. Docs update piece-by-piece inside each task — no
terminal doc-surgery task. TDD throughout: test first (RED), implement
(GREEN), test + impl in the same atomic pathspec commit.

The prior locator/bind devex (Tasks 1–34) is superseded; this file
replaces it.

---

## Task 1: Delete locator + CLI bind/inspect, then reformat wire (AFK)

**Implements:** §0 (one keying path), §5.1, §9 surface disposition; doc:
SPECIFICATION §1.7.1/§1.7.3/§1.7.4/§1.7.6–7, §2.9, CONTEXT.md
**Blocked by:** None — start here

Two coupled moves in one slice. The wire reformat drops the plaintext
cipher-id byte, which is exactly what dual-cipher `bind`/`inspect`
dispatch on — so the locator/bind teardown must land *with* the
reformat, not after it.

**Part A — teardown (prep):** delete the locator scan + config-render
helpers, the `litmask.config` artifact, the wrapper locator prefix, and
the CLI `bind` + `inspect` subcommands (their only consumers).
`show-machine-id` stays. Leaves exactly one keying path.

**Part B — reformat:** wrapper becomes `nonce(12) ‖ AEAD(version_byte ‖
mask_key) ‖ tag(16)` (~61 B): nonce at offset 0, cipher byte gone,
format version authenticated *inside* the AEAD. Keying stays
seed-derived (no tier behavior yet); cipher dispatch comes from the
compiled `CURRENT_CIPHER`, not a wire byte.

### Acceptance Criteria

- [ ] `litmask-internal/src/scan.rs` and `config.rs` deleted; no
      `locate_wrapper` / `count_occurrences` / `render_config_fields`
      exports remain
- [ ] `emit()` no longer writes `litmask.config`; no locator prefix is
      emitted into the wrapper
- [ ] `litmask bind` and `litmask inspect` removed; `litmask --help`
      lists neither; `show-machine-id` still works
- [ ] `assemble_wrapper` produces `nonce ‖ AEAD(version ‖ mask_key) ‖
      tag`; no plaintext cipher-id or version byte appears outside the
      AEAD; `NONCE_OFFSET == 0`; `WRAPPER_LEN == 61`
- [ ] `decrypt_wrapper` rejects a wrapper whose authenticated version
      byte is unknown (decrypt-then-check), distinct from an
      AEAD-tag-failure error
- [ ] `derive_weak_xor_key` reads the nonce at offset 0 and
      round-trips a `weak_mask!` literal
- [ ] Existing encrypt→embed→decrypt round-trip tests pass (behavior
      preserved); `just ci` green
- [ ] SPECIFICATION §1.7.3 describes the new layout; §1.7.1/§1.7.4/
      §1.7.6–7 locator/config/bind sections retired; §2.9 CLI trimmed;
      CONTEXT.md drops Locator / Bind / litmask.config and updates the
      wrapper entry

---

## Task 2: Tier-0 seal + tag plumbing (AFK)

**Implements:** §1, §2.4 (tag emission), §6.2; doc: SPECIFICATION §1
keying, CONTEXT.md
**Blocked by:** Task 1

Split key generation in `emit()`: the seed now derives only
`mask_key` + nonces; `unlock_key` becomes `KDF(wrapper_nonce,
"litmask-tier0-v1")` — recomputable at build and runtime from the
nonce alone. Emit the build-authoritative `LITMASK_SEAL_TIER=tier0`
tag and the rerun-if-env-changed plumbing. Remove the §6.2 seed echo.

### Acceptance Criteria

- [ ] `emit()` derives `unlock_key` as `KDF(wrapper_nonce,
      "litmask-tier0-v1")`, independent of the seed's key stream
- [ ] `emit()` emits `cargo:rustc-env=LITMASK_SEAL_TIER=tier0` and the
      relevant `cargo:rerun-if-env-changed` directives
- [ ] Seed echo at litmask-build/src/lib.rs:283 removed; no seed value
      reaches build output
- [ ] A Tier-0 build round-trips `mask!` literals (unlock_key derived
      identically at build and runtime)
- [ ] SPECIFICATION §1 documents Tier-0 derivation; CONTEXT.md gains
      `LITMASK_SEAL_TIER`

---

## Task 3: `init!()` proc macro + lazy Tier-0 (AFK)

**Implements:** §2 (no-arg form), §2.1 (no silent downgrade), §2.4
(cross-check); doc: SPECIFICATION §1.4.1/§1.8.2
**Blocked by:** Task 2

Convert `init!` from `macro_rules!` to a proc macro so it can parse
grammar and conditionally `compile_error!`. This task lands only the
no-arg `init!()` form. It reads `LITMASK_SEAL_TIER` and cross-checks
form↔tag: `init!()` requires tag `tier0`. The no-`init!` lazy path
becomes Tier-0 nonce-derived (drop `EnvVarProvider::default`).

### Acceptance Criteria

- [ ] `init!()` expands via proc macro and decrypts the wrapper under
      Tier-0
- [ ] `init!()` against a non-`tier0` tag → `compile_error!` naming
      the mismatch; absent tag → `compile_error!`
- [ ] Code with no `init!()` at all decrypts `mask!` literals via the
      lazy Tier-0 path (no `EnvVarProvider::default` reference remains)
- [ ] e2e test: a binary using `mask!` both with and without `init!()`
      produces correct plaintext under a Tier-0 build
- [ ] SPECIFICATION §1.4.1/§1.8.2 document the `init!()` form and the
      lazy Tier-0 fallback

---

## Task 4: External tier (AFK)

**Implements:** §2.2 (always normalize), §2.3 (single-factor), §3
(channels); doc: SPECIFICATION §1.6.1, §3
**Blocked by:** Task 3

Add the `init!(<expr>)` form for any `impl KeyProvider`. The provider
yields any-length material (`Zeroizing<Vec<u8>>`); the framework always
applies one KDF: `unlock_key = KDF("litmask-unlock-v1", material)`.
`UnlockKey` becomes an internal post-KDF type. Build reads the
`LITMASK_UNLOCK_KEY` channel and tags `external`.

### Acceptance Criteria

- [ ] `KeyProvider` yields `Zeroizing<Vec<u8>>` material of arbitrary
      length; `UnlockKey` is not publicly constructible
- [ ] Framework derives `unlock_key = KDF("litmask-unlock-v1",
      material)` for every external provider (env, file, custom)
- [ ] A build with `LITMASK_UNLOCK_KEY` set tags `external` and emits
      `rerun-if-env-changed=LITMASK_UNLOCK_KEY`
- [ ] `init!(<expr>)` against tag `external` round-trips; against any
      other tag → `compile_error!`
- [ ] Env/File providers pass raw bytes (no pre-hashing to 32 B)
- [ ] e2e: build with external material X, runtime provider supplying X
      → correct plaintext; supplying Y → decrypt failure
- [ ] SPECIFICATION §1.6.1 (KeyProvider trait) and §3 (channels)
      updated; init! expr form documented

---

## Task 5: Machine tier (AFK)

**Implements:** §4 (machine-id tier); doc: SPECIFICATION §4, CONTEXT.md
machine_id
**Blocked by:** Task 4

Add the `init!(machine_id)` keyword form. Machine salt becomes
nonce-derived: `machine_salt = KDF(wrapper_nonce,
"litmask-machine-id-salt-v1")` — drop the user-supplied salt param from
`derive_machine_id_key`; context string → `"litmask-machine-id-v1"`.
Build reads `LITMASK_MACHINE_ID`, tags `machine`. Runtime machine
derivation moves into init!-emitted internal code; the public
`MachineIdProvider` type is removed.

### Acceptance Criteria

- [ ] `derive_machine_id_key` takes no salt param; salt is
      `KDF(wrapper_nonce, "litmask-machine-id-salt-v1")`; context is
      `"litmask-machine-id-v1"`
- [ ] A build with `LITMASK_MACHINE_ID` set tags `machine` and emits
      `rerun-if-env-changed=LITMASK_MACHINE_ID`
- [ ] `init!(machine_id)` against tag `machine` round-trips on the
      sealing machine; a different machine id → decrypt failure
- [ ] `init!(machine_id)` against any non-`machine` tag →
      `compile_error!`
- [ ] Public `MachineIdProvider` removed from the `litmask` API;
      machine derivation lives in init!-emitted code
- [ ] No stale `hardware` / `hw-id` identifiers remain (grep clean)
- [ ] SPECIFICATION §4 documents the machine tier; CONTEXT.md gains the
      `machine_id` keyword and retires MachineIdProvider

---

## Task 6: Machine + external two-factor (AFK)

**Implements:** §2.3 (two-factor), §4; doc: SPECIFICATION §2.3
**Blocked by:** Task 5

Add the `init!(machine_id + <expr>)` grammar. Two-factor unlock_key is
`KDF(len_prefixed(machine_material) ‖ len_prefixed(external_material))`
— concatenate-only (never inner KDF), machine-first fixed order, 8-byte
LE length prefixes. Build tags `machine_external`. This completes the
4-way form↔tag cross-check matrix.

### Acceptance Criteria

- [ ] `init!(machine_id + <expr>)` parses; malformed grammar →
      `compile_error!`
- [ ] unlock_key = `KDF(len_prefixed(machine) ‖ len_prefixed(external))`,
      machine-first, 8-byte LE prefixes, single outer KDF
- [ ] A build with both `LITMASK_MACHINE_ID` and `LITMASK_UNLOCK_KEY`
      set tags `machine_external`
- [ ] Full 4-way matrix holds: each of the four `init!` forms compiles
      only against its matching tag; all 12 mismatches →
      `compile_error!`
- [ ] e2e: correct only when *both* factors match at runtime; either
      factor wrong → decrypt failure
- [ ] SPECIFICATION §2.3 documents two-factor composition

---

## Task 7: CLI additions — keygen + self-checking machine-id (AFK)

**Implements:** §4.4 (CLI surface), §4.1.1 (self-checking token); doc:
SPECIFICATION §2.9, man pages, CLI help
**Blocked by:** Task 5

Grow the trimmed CLI back to its final surface `{keygen,
show-machine-id}`. `keygen` prints 32 random base64url bytes to stdout
(pure, pipeable). `show-machine-id` gains an in-band self-checking
token: check digits on stdout, human prose on stderr, so a piped
capture stays clean and copy/paste corruption is detectable.

### Acceptance Criteria

- [ ] `litmask keygen` prints exactly 32 random bytes base64url-encoded
      to stdout, nothing on stderr, newline-terminated
- [ ] `litmask keygen | <consumer>` yields a usable `LITMASK_UNLOCK_KEY`
      value (round-trips through the external tier)
- [ ] `litmask show-machine-id` prints a self-checking token to stdout
      and explanatory prose to stderr; the token's check digits detect
      a single-character corruption
- [ ] `litmask --help` lists exactly `keygen` and `show-machine-id`
- [ ] SPECIFICATION §2.9, man pages, and `--help` text reflect the
      final CLI surface

---

## Task 8: Profile-split diagnostics + Tier-0 floor warning + AC4 (AFK)

**Implements:** §5.4 (profile-split diagnostics), §1.1 (floor
warning), §2.4 (AC4 narrowing); doc: SPECIFICATION §5.4, §1.1
**Blocked by:** Task 3

Split runtime diagnostics by profile: debug builds emit loud,
actionable panic messages; release builds emit bare `panic!()` to
preserve opacity. Add the §1.1 build-time Tier-0 floor warning
(`cargo:warning=` when a release build is sealed at `tier0`). Narrow
the AC4 test from "ban all `LITMASK*` rustc-env" to a whitelist that
permits `LITMASK_SEAL_TIER`.

### Acceptance Criteria

- [ ] Runtime failure panics carry actionable text under
      `cfg(debug_assertions)` and are bare `panic!()` in release
      (verified by build-profile-split test)
- [ ] A release build sealed at `tier0` emits a `cargo:warning=` floor
      notice; non-release or higher tiers do not
- [ ] AC4 test permits `cargo:rustc-env=LITMASK_SEAL_TIER` and still
      bans every other `LITMASK*` rustc-env
- [ ] `just ci` green
- [ ] SPECIFICATION §5.4 and §1.1 document the diagnostics split and
      the floor warning

---

## Task 9: Capstone — fold SPEC_DEVEX into SPECIFICATION + docs scrub (HITL)

**Implements:** §8 (doc edits owed), §9 (surface disposition); doc:
SPECIFICATION (whole), CONTEXT.md, README, CLAUDE.md, man pages
**Blocked by:** Tasks 1–8

Tasks 1–8 each updated the spec section-by-section in flight. This
capstone makes `docs/SPECIFICATION.md` the single canonical spec: fold
the remaining `docs/SPEC_DEVEX.md` content (rationale, residuals,
friction appendix) into it, then retire `SPEC_DEVEX.md`. Finish with a
full docs scrub so no stale locator/bind/config/MachineIdProvider
language survives anywhere and every cross-reference resolves.

### Acceptance Criteria

- [ ] All load-bearing `SPEC_DEVEX.md` content (keying model rationale,
      §10 residuals, Appendix A friction) is present in
      `SPECIFICATION.md`; `SPEC_DEVEX.md` removed (or reduced to a
      pointer)
- [ ] Repo-wide grep is clean of retired vocabulary — `locator`,
      `bind`, `inspect`, `litmask.config`, `MachineIdProvider`,
      `init_with!`, `MultiProvider`, `hardware`/`hw-id` — except where
      explicitly documenting their removal
- [ ] Every internal doc cross-reference (§ links, file links, CONTEXT
      glossary terms) resolves to a real target
- [ ] README, CLAUDE.md architecture notes, and man pages describe the
      build-sealed model and the final CLI surface
- [ ] SPECIFICATION section numbering is contiguous and the table of
      contents (if any) matches
- [ ] `just ci` green; `just lint` (typos/links) clean
