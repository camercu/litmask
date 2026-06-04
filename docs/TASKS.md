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

## Task 1: Delete locator + CLI bind/inspect, then reformat wire (AFK) ✅ DONE

**Status:** complete — commit `b8bbeb9`
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

- [x] `litmask-internal/src/scan.rs` and `config.rs` deleted; no
      `locate_wrapper` / `count_occurrences` / `render_config_fields`
      exports remain
- [x] `emit()` no longer writes a locator prefix into the wrapper;
      `litmask.config` carries only `unlock_key`
- [x] `litmask bind` and `litmask inspect` removed; `litmask --help`
      lists neither; `show-machine-id` still works
- [x] `assemble_wrapper` produces `nonce ‖ AEAD(version ‖ mask_key) ‖
      tag`; no plaintext cipher-id or version byte appears outside the
      AEAD; `NONCE_OFFSET == 0`; `WRAPPER_LEN == 61`
- [x] `decrypt_wrapper` rejects a wrapper whose authenticated version
      byte is unknown (decrypt-then-check), distinct from an
      AEAD-tag-failure error
- [x] `derive_weak_xor_key` reads the nonce at offset 0 and
      round-trips a `weak_mask!` literal
- [x] Existing encrypt→embed→decrypt round-trip tests pass (behavior
      preserved); `just ci` green
- [x] SPECIFICATION §1.7.3 describes the new layout; §1.7.1/§1.7.4/
      §1.7.6–7 locator/config/bind sections retired; §2.9 CLI trimmed;
      CONTEXT.md drops Locator / Bind / litmask.config and updates the
      wrapper entry

### Discoveries / unplanned work

- **`InitError::UnsupportedCipher` removed** (not in original plan). The
  cipher is compile-time only; with no wire cipher byte, a runtime
  cipher mismatch surfaces as `AuthenticationFailed`, so the variant was
  dead. Rippled through `error.rs`, `runtime.rs`, SPECIFICATION §1.9.2,
  and the renamed `init_unsupported_format.rs` test.
- **Test helpers must use `CURRENT_CIPHER`, never hardcode a cipher.**
  `decrypt.rs` wrapper-build helpers hardcoded ChaCha20 while
  `decrypt_wrapper` dispatches on `CURRENT_CIPHER`; the `--all-features`
  CI lane (where `CURRENT_CIPHER == Aes256Gcm`) failed the tag check.
  Future tasks that build wrappers/blobs in tests must seal with
  `CURRENT_CIPHER`.
- **`init_unsupported_format` test holds only `Err`-returning cases.**
  The process-global `mask_key` cell early-returns once set, so a
  happy-path test in the same binary masked the rejection tests. Happy
  path is covered by other test binaries. Keep this invariant when
  adding tier round-trip tests.
- **Pre-commit + partial commits are incompatible here.** `git commit --
  <subset>` makes pre-commit stash the rest, yielding a non-compiling
  tree. Interdependent changes that only build as a whole must land in
  one atomic commit (full pathspec).

---

## Task 2: Embedded seal + tag plumbing (AFK) ✅ DONE

**Implements:** §1, §2.4 (tag emission), §6.2; doc: SPECIFICATION §1
keying, CONTEXT.md
**Blocked by:** Task 1

Split key generation in `emit()`: the seed now derives only
`mask_key` + nonces; `unlock_key` becomes `KDF(wrapper_nonce,
"litmask-embedded-v1")` — recomputable at build and runtime from the
nonce alone. Emit the build-authoritative `LITMASK_SEAL_TIER=embedded`
tag and the rerun-if-env-changed plumbing. Remove the §6.2 seed echo.

### Acceptance Criteria

- [x] `emit()` derives `unlock_key` as `KDF(wrapper_nonce,
      "litmask-embedded-v1")`, independent of the seed's key stream
- [x] `emit()` emits `cargo:rustc-env=LITMASK_SEAL_TIER=embedded` and the
      relevant `cargo:rerun-if-env-changed` directives
- [x] Seed echo removed; no seed value reaches build output
- [x] An Embedded build round-trips `mask!` literals (unlock_key derived
      identically at build and runtime)
- [x] SPECIFICATION §1 documents Embedded derivation; CONTEXT.md gains
      `LITMASK_SEAL_TIER`

---

## Task 3: `init!()` proc macro + lazy Embedded (AFK)

**Implements:** §2 (no-arg form), §2.1 (no silent downgrade), §2.4
(cross-check), §2.5.5 (StaticProvider); doc: SPECIFICATION §1.4.1/§1.8.2
**Blocked by:** Task 2

Convert `init!` from `macro_rules!` to a proc macro so it can parse
grammar and conditionally `compile_error!`. This task lands only the
no-arg `init!()` form. It reads `LITMASK_SEAL_TIER` and cross-checks
form↔tag: `init!()` requires tag `embedded`. The no-`init!` lazy path
becomes Embedded nonce-derived (drop `EnvVarProvider::default`).

**Repurpose `StaticProvider` as the Embedded-tier runtime provider.**
Today it holds a verbatim `UnlockKey` in process memory ("FOR TESTS
ONLY", `static_key.rs:1`) — the opposite of the Embedded tier, which
stores no key and recomputes it from the public wrapper nonce. Drop the
verbatim-key storage entirely. The `KeyProvider::unlock_key(&self)` trait
takes no nonce (`mod.rs:54`), and the runtime calls `provider.unlock_key()`
with no wrapper in scope (`runtime.rs:89`), so the nonce is captured at
construction: `StaticProvider::new(&wrapper)` stores only the 12-byte
cleartext nonce (non-secret — no zeroize needed, drop the `Zeroize`/Drop
plumbing and the `Counted` test seam) and derives `unlock_key()` on
demand via `litmask_internal::derive_embedded_unlock_key`. The `init!()`
expansion and the lazy path both build it from the `include_bytes!`-
embedded wrapper and feed `__init_with_wrapper` / `mask_key_or_lazy_init`,
replacing `EnvVarProvider::default`.

**Move verbatim-key injection to a `TestProvider`.** The explicit-key
path is only ever a test seam, so it leaves the production surface: add
a `TestProvider` (holds a fixed `UnlockKey`, returns it verbatim) gated
behind `#[cfg(test)]` for in-crate unit tests (e.g. the `from_base64url`
seam at `lib.rs:368`). `cfg(test)` does NOT cross crate boundaries, so
the external users of the old `StaticProvider::new(UnlockKey)` —
`tests/static_provider.rs` and `examples/static_provider.rs` — cannot
see it; they each define a trivial inline `KeyProvider` impl instead
(the trait is public). The cautionary `static_provider` example's
"don't ship a static key" lesson is moot once `StaticProvider` is the
keyless floor; retire or repurpose it rather than port it.

### Acceptance Criteria

- [ ] `StaticProvider::new(&wrapper)` stores only the wrapper nonce and
      returns `derive_embedded_unlock_key(nonce)` from `unlock_key()`; no
      verbatim key bytes are held, no zeroize/Drop remains (TDD: assert
      equality vs. `derive_embedded_unlock_key`, and that the derived key
      round-trips a build-emitted wrapper through `decrypt_wrapper`)
- [ ] `TestProvider` exists only under `#[cfg(test)]`, holds a verbatim
      `UnlockKey`, and is absent from the public API (no `pub use`); a
      release build exposes no fixed-key provider
- [ ] `init!()` expands via proc macro and decrypts the wrapper under
      Embedded using `StaticProvider::new(&wrapper)`
- [ ] `init!()` against a non-`embedded` tag → `compile_error!` naming
      the mismatch; absent tag → `compile_error!`
- [ ] Code with no `init!()` at all decrypts `mask!` literals via the
      lazy Embedded path through `StaticProvider::new(&wrapper)` (no
      `EnvVarProvider::default` reference remains)
- [ ] `tests/static_provider.rs` and `examples/static_provider.rs` no
      longer reference `StaticProvider::new(UnlockKey)`; their `init_with!`
      coverage uses an inline `KeyProvider` impl (or the example is
      retired)
- [ ] e2e test: a binary using `mask!` both with and without `init!()`
      produces correct plaintext under an Embedded build
- [ ] SPECIFICATION §1.4.1/§1.8.2 document the `init!()` form, the lazy
      Embedded fallback, and the nonce-derived `StaticProvider`; CONTEXT.md
      updates the `StaticProvider` entry (now keyless, nonce-derived)

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
- [ ] `machine_id_provider` example migrated to `init!(machine_id)`; the
      stale `litmask-cli bind` comment in the `justfile` `test-examples`
      recipe is removed (deferred here from Task 1)
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

## Task 8: Profile-split diagnostics + Embedded floor warning + AC4 (AFK)

**Implements:** §5.4 (profile-split diagnostics), §1.1 (floor
warning), §2.4 (AC4 narrowing); doc: SPECIFICATION §5.4, §1.1
**Blocked by:** Task 3

Split runtime diagnostics by profile: debug builds emit loud,
actionable panic messages; release builds emit bare `panic!()` to
preserve opacity. Add the §1.1 build-time Embedded floor warning
(`cargo:warning=` when a release build is sealed at `embedded`).

> **Discovery (Task 2):** the AC4 narrowing originally scoped here had to
> move into Task 2. Emitting `LITMASK_SEAL_TIER` immediately trips the
> old "ban all `LITMASK*` rustc-env" test, so that test was narrowed to a
> whitelist as part of landing the tag. AC4 below is already satisfied.

### Acceptance Criteria

- [ ] Runtime failure panics carry actionable text under
      `cfg(debug_assertions)` and are bare `panic!()` in release
      (verified by build-profile-split test)
- [ ] A release build sealed at `embedded` emits a `cargo:warning=` floor
      notice; non-release or higher tiers do not
- [x] AC4 test permits `cargo:rustc-env=LITMASK_SEAL_TIER` and still
      bans every other `LITMASK*` rustc-env (done in Task 2)
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
- [ ] README, CLAUDE.md architecture notes, docs/DEPLOYMENT.md, and man
      pages describe the build-sealed model and the final CLI surface
- [ ] SPECIFICATION section numbering is contiguous and the table of
      contents (if any) matches
- [ ] `just ci` green; `just lint` (typos/links) clean
