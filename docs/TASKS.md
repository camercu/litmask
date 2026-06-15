# litmask — Build-Sealed Devex Adoption Tasks

Source: [docs/SPECIFICATION.md](./SPECIFICATION.md) (build-sealed model
folded in; the former `SPEC_DEVEX.md` is now a retired pointer)
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
dispatch on — so the locator/bind teardown must land _with_ the
reformat, not after it.

**Part A — teardown (prep):** delete the locator scan + config-render
helpers, the `litmask.config` artifact, the wrapper locator prefix, and
the CLI `bind` + `inspect` subcommands (their only consumers).
`show-machine-id` stays. Leaves exactly one keying path.

**Part B — reformat:** wrapper becomes `nonce(12) ‖ AEAD(version_byte ‖
mask_key) ‖ tag(16)` (~61 B): nonce at offset 0, cipher byte gone,
format version authenticated _inside_ the AEAD. Keying stays
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

## Task 3: `init!()` proc macro + lazy Embedded (AFK) ✅ DONE

**Implements:** §2 (no-arg form), §2.1 (no silent downgrade), §2.4
(cross-check), §2.5.5 (StaticProvider); doc: SPECIFICATION §1.4.1/§1.8.2
**Blocked by:** Task 2

Convert `init!` from `macro_rules!` to a proc macro so it can parse
grammar and conditionally `compile_error!`. This task lands only the
no-arg `init!()` form. It reads `LITMASK_SEAL_TIER` and cross-checks
form↔tag: `init!()` requires tag `embedded`. The no-`init!` lazy path
becomes Embedded nonce-derived (drop `EnvVarProvider::default`).

**Rename `StaticProvider` → `EmbeddedProvider` and make it the
Embedded-tier runtime provider.** Today it holds a verbatim `UnlockKey`
in process memory ("FOR TESTS ONLY", `static_key.rs:1`) — the opposite
of the Embedded tier, which stores no key and recomputes it from the
public wrapper nonce. The name "Static" is misleading once the key is
nonce-derived, so rename the type (and `static_key.rs` →
`embedded.rs`, updating the `mod.rs` doc list and the `lib.rs` prelude
re-export). This is a BREAKING public-API change — flag it in the
commit. Drop the verbatim-key storage entirely. The
`KeyProvider::unlock_key(&self)` trait takes no nonce (`mod.rs:54`), and
the runtime calls `provider.unlock_key()` with no wrapper in scope
(`runtime.rs:89`), so the nonce is captured at construction:
`EmbeddedProvider::new(&wrapper)` stores only the 12-byte cleartext
nonce (non-secret — no zeroize needed, drop the `Zeroize`/Drop plumbing
and the `Counted` test seam) and derives `unlock_key()` on demand via
`litmask_internal::derive_embedded_unlock_key`. The `init!()` expansion
and the lazy path both build it from the `include_bytes!`-embedded
wrapper and feed `__init_with_wrapper` / `mask_key_or_lazy_init`,
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
"don't ship a static key" lesson is moot once `EmbeddedProvider` is the
keyless floor; retire or repurpose it rather than port it.

### Acceptance Criteria

- [x] `EmbeddedProvider::new(&wrapper)` stores only the wrapper nonce and
      returns `derive_embedded_unlock_key(nonce)` from `unlock_key()`; no
      verbatim key bytes are held, no zeroize/Drop remains (TDD: assert
      equality vs. `derive_embedded_unlock_key`, and that the derived key
      round-trips a build-emitted wrapper through `decrypt_wrapper`)
- [x] `StaticProvider` is gone from the public API; `static_key.rs` is
      renamed to `embedded.rs` and the prelude re-export, `mod.rs` doc
      list, and CONTEXT.md all use `EmbeddedProvider` (breaking-change
      commit)
- [x] `TestProvider` exists only under `#[cfg(test)]`, holds a verbatim
      `UnlockKey`, and is absent from the public API (no `pub use`); a
      release build exposes no fixed-key provider
- [x] `init!()` expands via proc macro and decrypts the wrapper under
      Embedded using `EmbeddedProvider::new(&wrapper)`
- [x] `init!()` against a non-`embedded` tag → `compile_error!` naming
      the mismatch; absent tag → `compile_error!`
- [x] Code with no `init!()` at all decrypts `mask!` literals via the
      lazy Embedded path through `EmbeddedProvider::new(&wrapper)` (no
      `EnvVarProvider::default` reference remains)
- [x] `tests/static_provider.rs` and `examples/static_provider.rs` no
      longer reference `StaticProvider::new(UnlockKey)`; their `init_with!`
      coverage uses an inline `KeyProvider` impl (or the example is
      retired)
- [x] e2e test: a binary using `mask!` both with and without `init!()`
      produces correct plaintext under an Embedded build
- [x] SPECIFICATION §1.4.1/§1.8.2 document the `init!()` form, the lazy
      Embedded fallback, and the nonce-derived `EmbeddedProvider`;
      CONTEXT.md replaces the `StaticProvider` entry with `EmbeddedProvider`
      (keyless, nonce-derived)

---

## Task 4: External tier (AFK) ✅ DONE

**Implements:** §2.2 (always normalize), §2.3 (single-factor), §3
(channels); doc: SPECIFICATION §1.6.1, §3
**Blocked by:** Task 3

Add the `init!(<expr>)` form for any `impl KeyProvider`. The KDF lives in
a public `UnlockKey::derive(material)`; providers call it. The
`KeyProvider` trait stays `unlock_key() -> Result<UnlockKey, KeyError>`
(no `material()` rename, no framework-side KDF). Env/File providers read
any-length raw material, strip one trailing newline, and derive
(`unlock_key = KDF("litmask-unlock-v1", material)`). Build reads the
`LITMASK_UNLOCK_KEY` channel and tags `external`.

### Acceptance Criteria

- [x] `UnlockKey::derive(material)` is public and normalizes
      arbitrary-length material via `KDF("litmask-unlock-v1", material)`;
      the `KeyProvider` trait keeps `unlock_key() -> Result<UnlockKey,
      KeyError>`
- [x] Env/File providers read raw bytes (no pre-hashing to 32 B), strip a
      single trailing newline, and derive via `UnlockKey::derive`;
      `KeyEncoding` is removed
- [x] A build with `LITMASK_UNLOCK_KEY` set tags `external` and emits
      `rerun-if-env-changed=LITMASK_UNLOCK_KEY`
- [x] `init!(<expr>)` against tag `external` round-trips; against any
      other tag → `compile_error!`
- [x] e2e: build with external material X, runtime provider supplying X
      → correct plaintext; supplying Y → decrypt failure
- [x] SPECIFICATION (§1.6.3 encoding, §2.5.1–3 providers) and DEPLOYMENT
      updated to derive-semantics; `init!` expr form documented

---

## Task 5: Machine tier (AFK) ✅ DONE

**Implements:** §4 (machine-id tier); doc: SPECIFICATION §4, CONTEXT.md
bind_to_machine
**Blocked by:** Task 4

Add the `init!(bind_to_machine)` keyword form. Machine salt becomes
nonce-derived: `machine_salt = KDF(wrapper_nonce,
"litmask-machine-id-salt-v1")` — drop the user-supplied salt param from
`derive_machine_id_key`; context string → `"litmask-machine-id-v1"`.
Build reads `LITMASK_MACHINE_ID`, tags `machine`. The machine factor
yields a **finished `UnlockKey`** (the §2.2 composition currency), so the
same type serves single-factor machine and the two-factor external
compose in Task 6. `MachineIdProvider` is demoted to `pub(crate)`,
instantiated only by an `init!` seam fn in `litmask::__internal` that
injects the build-wrapper nonce; the macro never names the type in
expanded code (expansion lands in the user crate, which cannot reach a
`pub(crate)` type).

### Acceptance Criteria

- [x] `derive_machine_id_key` takes no salt param; salt is
      `KDF(wrapper_nonce, "litmask-machine-id-salt-v1")`; context is
      `"litmask-machine-id-v1"`
- [x] A build with `LITMASK_MACHINE_ID` set tags `machine` and emits
      `rerun-if-env-changed=LITMASK_MACHINE_ID`
- [x] `init!(bind_to_machine)` against tag `machine` round-trips on the
      sealing machine; a different machine id → decrypt failure
- [x] `init!(bind_to_machine)` against any non-`machine` tag →
      `compile_error!`
- [x] `MachineIdProvider` demoted to `pub(crate)`, reachable only via the
      `init!` seam (`__internal`); the macro instantiates it through a
      `#[doc(hidden)] pub` seam fn and never names the type in expanded code
- [x] The machine factor yields a finished `UnlockKey` (single-factor IS
      that key; reused as a compose input in Task 6)
- [x] No stale `hardware` / `hw-id` identifiers remain (grep clean)
- [x] `machine_id_provider` example migrated to `init!(bind_to_machine)`; the
      stale `litmask-cli bind` comment in the `justfile` `test-examples`
      recipe is removed (deferred here from Task 1)
- [x] SPECIFICATION documents the machine tier; CONTEXT.md gains the
      `bind_to_machine` keyword and notes MachineIdProvider is now `pub(crate)`
      (seam-only). Whole-spec consistency pass migrated §1.x and §2.x to the
      build-sealed design: machine tier via `init!(bind_to_machine)`, `pub(crate)`
      `MachineIdProvider`, no `litmask bind`/`inspect`/locator, CLI reduced to
      `show-machine-id`
- [x] README machine-id surface migrated to `init!(bind_to_machine)` (deferred
      here from Tasks 1–3): retire the `## Machine-ID binding (litmask
      bind)` section and the `MachineIdProvider::with_salt(...)` snippet
      (both name now-unreachable APIs — `litmask bind` was deleted in Task 1,
      `MachineIdProvider` is demoted to `pub(crate)` here), and update the "Why litmask"
      comparison-table `Machine-ID binding` row from `litmask bind` to the
      `init!(bind_to_machine)` form

---

## Task 6: Machine + external two-factor (AFK) ✅ DONE

**Implements:** §2.3 (two-factor), §4; doc: SPECIFICATION §2.3
**Blocked by:** Task 5

Add the `init!(bind_to_machine + <expr>)` grammar. Two-factor composes the two
**finished `UnlockKey`s** (machine + external) via `UnlockKey::compose`:
`unlock_key = KDF("litmask-2fa-v1", len_prefixed(machine_key) ‖
len_prefixed(external_key))` — machine-first fixed order, 8-byte LE
length prefixes, distinct `"…-2fa-v1"` context (no collision with a
single-factor key). The compose primitive lives in
`litmask-internal::kdf` (build computes the identical key to seal under);
`UnlockKey::compose` wraps it, mirroring `UnlockKey::derive`. Build tags
`machine_external`. This completes the 4-way form↔tag cross-check matrix.

### Acceptance Criteria

- [x] `init!(bind_to_machine + <expr>)` parses; malformed grammar →
      `compile_error!`
- [x] unlock_key = `UnlockKey::compose(machine_key, external_key)` =
      `KDF("litmask-2fa-v1", len_prefixed(machine_key) ‖
      len_prefixed(external_key))`, machine-first, 8-byte LE prefixes;
      compose primitive in `litmask-internal::kdf`, shared with build
- [x] Compose inputs are finished `UnlockKey`s (type-level anti-footgun:
      `compose` takes `UnlockKey`, not bytes)
- [x] A build with both `LITMASK_MACHINE_ID` and `LITMASK_UNLOCK_KEY`
      set tags `machine_external`
- [x] Full 4-way matrix holds: each of the four `init!` forms compiles
      only against its matching tag; all 12 mismatches →
      `compile_error!`
- [x] e2e: correct only when _both_ factors match at runtime; either
      factor wrong → decrypt failure
- [x] SPECIFICATION §2.3 documents two-factor composition

---

## Task 7: CLI additions — keygen + self-checking machine-id (AFK) ✅ DONE

**Implements:** §4.4 (CLI surface), §4.1.1 (self-checking token); doc:
SPECIFICATION §2.9, man pages, CLI help
**Blocked by:** Task 5

Grow the trimmed CLI back to its final surface `{keygen,
show-machine-id}`. `keygen` prints 32 random base64url bytes to stdout
(pure, pipeable). `show-machine-id` gains an in-band self-checking
token: check digits on stdout, human prose on stderr, so a piped
capture stays clean and copy/paste corruption is detectable.

### Acceptance Criteria

- [x] `litmask keygen` prints exactly 32 random bytes base64url-encoded
      to stdout, nothing on stderr, newline-terminated
- [x] `litmask keygen | <consumer>` yields a usable `LITMASK_UNLOCK_KEY`
      value (round-trips through the external tier)
- [x] `litmask show-machine-id` prints a self-checking token to stdout
      and explanatory prose to stderr; the token's check digits detect
      a single-character corruption
- [x] `litmask --help` lists exactly `keygen` and `show-machine-id`
- [x] SPECIFICATION §2.9, `--help` text, README/DEPLOYMENT/CONTEXT
      reflect the final CLI surface (no man pages exist in-repo; the CLI
      doc-comments + SPEC §2.9 + `--help` are the surface of record)

> **Discovery (Task 7):** shipping the token from `show-machine-id` makes
> the build-input contract for `LITMASK_MACHINE_ID` a **breaking change** —
> `emit()` now requires the token form (`raw_id "." checksum`) and panics
> on a bare id, because `machine_id_via_cli()` feeds CLI output straight
> into the build. The codec lives in `litmask-internal`
> (`encode_/decode_machine_id_token`) so the CLI (encode) and `emit()`
> (decode+validate) stay in lockstep. Every machine-tier fixture/test,
> `example_scrub`, and `scripts/platform-smoke.sh` had to switch their
> placeholder ids to valid tokens to keep building.

---

## Task 8: Profile-split diagnostics + Embedded floor warning + AC4 (AFK) ✅ DONE

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

- [x] Runtime failure panics carry actionable text under
      `cfg(debug_assertions)` and are bare `panic!()` in release
      (verified by build-profile-split test —
      `tampered_blob_panic_message_is_profile_split`, run under both
      profiles; messages live in the `#[cfg(debug_assertions)]`
      `litmask::diagnostics` module)
- [x] A release build sealed at `embedded` emits a `cargo:warning=` floor
      notice; non-release or higher tiers do not
      (`embedded_floor_warning`, presence-driven on the resolved tier)
- [x] AC4 test permits `cargo:rustc-env=LITMASK_SEAL_TIER` and still
      bans every other `LITMASK*` rustc-env (done in Task 2)
- [x] `just ci` green
- [x] SPECIFICATION §5.4 and §1.1 document the diagnostics split and
      the floor warning (§1.3.2 floor notice, §1.9.5 profile split)

### Discoveries / unplanned work

- **§1.9.5 needed the profile-split caveat.** The spec's panic policy
  banned all custom messages outright; that now contradicts the debug
  arm, so §1.9.5 was scoped to `cfg(not(debug_assertions))` with the
  debug routing through `litmask::diagnostics` documented inline.
- **Stale seed-echo doc removed.** SPECIFICATION §1.3.2 still claimed the
  release profile prints the seed via `cargo:warning=` (the echo was
  removed in Task 2); corrected while adding the floor-warning note, so
  the floor notice is now the _only_ sanctioned release `cargo:warning=`.

---

## Task 9: Capstone — fold SPEC_DEVEX into SPECIFICATION + docs scrub (HITL) ✅ DONE

**Implements:** §8 (doc edits owed), §9 (surface disposition); doc:
SPECIFICATION (whole), CONTEXT.md, README, CLAUDE.md, man pages
**Blocked by:** Tasks 1–8

Tasks 1–8 each updated the spec section-by-section in flight. This
capstone makes `docs/SPECIFICATION.md` the single canonical spec: fold
the remaining `docs/SPEC_DEVEX.md` content (rationale, residuals,
friction appendix) into it, then retire `SPEC_DEVEX.md`. Finish with a
full docs scrub so no stale locator/bind/config language survives
anywhere (and no public `MachineIdProvider` reference — it is now
`pub(crate)`) and every cross-reference resolves.

### Acceptance Criteria

- [x] All load-bearing `SPEC_DEVEX.md` content (keying model rationale,
      §10 residuals, Appendix A friction) is present in
      `SPECIFICATION.md`; `SPEC_DEVEX.md` removed (or reduced to a
      pointer). Done: folded into `SPECIFICATION.md` Appendix D
      (§D.1 build guarantees, §D.2 threat deltas, §D.3 residuals);
      `SPEC_DEVEX.md` reduced to a retired pointer. The origin-friction and
      surface-disposition narratives were later trimmed to git history.
- [x] Repo-wide grep is clean of retired vocabulary — `locator`,
      `MultiProvider`, `hardware`/`hw-id` — except where
      explicitly documenting their removal. `MachineIdProvider` survives
      only as `pub(crate)` (seam-only) in `litmask` source; scrubbed from
      THREAT_MODEL.md / DEPLOYMENT.md (now the machine tier framing).
      **Decision (2026-06-10, superseded):** at the time `litmask.config`
      was kept as the Embedded-tier diagnostic artifact. **Removed
      (2026-06-14):** a later audit found it unused — no shipped crate read
      it, the examples ignored it or reused its value as an arbitrary key
      string, and every test reader no-op'd on it or only asserted its
      existence — so `emit()` no longer writes it and arbitrary key material
      now comes from `litmask keygen`. `bind`/`inspect` as retired _commands_
      are gone; remaining `bind`/`inspect` hits are ordinary English ("bind a
      `&str`", "inspect text").
- [x] Every internal doc cross-reference (§ links, file links, CONTEXT
      glossary terms) resolves to a real target. The seven dangling
      §3/§5/§6/§7 refs into the old DevEx numbering now point at §D.x.
- [x] README, CLAUDE.md architecture notes, docs/DEPLOYMENT.md, and man
      pages describe the build-sealed model and the final CLI surface
      (no litmask man pages ship; CLI is `{keygen, show-machine-id}`).
- [x] SPECIFICATION section numbering is contiguous (Appendices A–D) and
      the cross-reference convention note matches.
- [x] `just ci` green; `just lint` (typos/links) clean

---

## Review follow-ups (2026-06-04) — keyless-Embedded + `init!` proc-macro

Code-level hazards surfaced reviewing `715fa55..HEAD`. None are current
bugs (every build seals Embedded today, and the workspace ships crates in
lockstep); they become live as higher tiers and external consumers land.
Doc drift from the same review (THREAT_MODEL/MIGRATION/SECURITY_AUDIT/
SPECIFICATION default-provider) is already fixed.

- [x] **Lazy-init silently picks Embedded in every config**
      (`litmask/src/runtime.rs`, `mask_key_or_lazy_init`). Fixed: the
      `mask!` expansion now carries the build-sealed `LITMASK_SEAL_TIER`
      tag into `__decrypt` via a new `__seal_tier!()` macro, and the lazy
      path refuses any non-Embedded tier with a dedicated
      `diagnostics::lazy_init_wrong_tier` panic (profile-split, names the
      init-ordering cause) instead of lazy-deriving the wrong key.
      Covered by the `lazy_higher_tier_refusal` e2e fixture (external
      seal, no `init!`) plus diagnostics unit tests. Spec §2.1.1.12a /
      §2.6.1.6 narrowed.
- [x] **`init!` tier-mismatch `compile_error!` branch has no end-to-end
      coverage** (`litmask-macros/src/init.rs`). Fixed: `init_tier_check_e2e`
      builds two isolated fixture crates in a subprocess with the
      `LITMASK_*` seal-input vars scrubbed — `init_mismatch_fixture` (an
      `external` seal against the Embedded-form `init!()` → `tier-mismatch`)
      and `init_unset_fixture` (no `emit()` → `unset`). The scrub defeats
      the ambient-tag leak; the unset fixture's build.rs declares
      `rerun-if-env-changed=LITMASK_SEAL_TIER` so the proc-macro's
      otherwise-untracked `env::var` read can't serve a stale artifact.
- [ ] **Cross-crate version skew is now a hard compile error.** A newer
      `litmask-macros` paired with an older `litmask-build` that doesn't
      emit `cargo:rustc-env=LITMASK_SEAL_TIER` makes `init!()` read `None`
      and emit `init! tier-mismatch: ... unset`, breaking an
      otherwise-valid Embedded build. **Decision (2026-06-09): keep the
      hard error — no code change.** The crates ship in lockstep, so the
      skew is unreachable today; adding a min-version gate or an
      unset→Embedded-assumption degrade would be speculative surface
      (YAGNI). The `unset` message already names `litmask_build::emit()` in
      `build.rs`, which is the correct fix for the realistic case (missing
      build wiring). Revisit only if/when the crates version independently.

---

## Masked-serde `#[serde(...)]` subset + `#[mask_all]` derive-swap (2026-06-13)

`#[mask_all]` now rewrites a type's plain `#[derive(Serialize)]` /
`#[derive(Deserialize)]` (under `unstable-serde`) and `#[derive(Debug)]`
to litmask's masking derives, closing the name-leak the literal rewrite
couldn't reach. `#[unmasked_derive]` opts a type out. The masking serde
derives gained the supported `#[serde(...)]` subset documented in spec
§E.2.5; each attribute ships as its own vertical slice with twin
wire-identity tests against the plain serde derive.

- [x] `#[mask_all]` derive-swap + `#[unmasked_derive]` opt-out.
- [x] `rename` / `rename_all` (with serialize/deserialize split; eight
      case rules ported byte-for-byte).
- [x] `skip` / `skip_serializing` / `skip_deserializing` /
      `skip_serializing_if`.
- [x] `default` / `default = "path"` (+ `skip_deserializing` interaction).
- [x] `alias` (field) + `deny_unknown_fields`.
- [x] `bound` (+ split) where-clause override.
- [x] `transparent`.
- [x] `with` / `serialize_with` / `deserialize_with`.

### Deferred (reject-loud until landed)

Tracked for later consideration; each currently fails with `<macro>!
invalid-arg` naming the key rather than diverging silently:

- [ ] `flatten` (map-based wire shape).
- [ ] enum representations: `tag` / `untagged` / `content`.
- [ ] container `getter` / `into` / `from` / `try_from`.
- [ ] explicit `borrow`.
- [ ] variant-level `alias`.
- [ ] `with` / `serialize_with` / `deserialize_with` on a **generic**
      type (the generated adapter is a local item that can't name the
      impl's type parameters).
- [ ] `skip` / `skip_serializing_if` on a **tuple** (positional) field
      (would shift element indices).
