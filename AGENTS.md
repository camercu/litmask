# litmask — AI collaborator notes

## What this is

Rust workspace that encrypts string literals at compile time (AEAD) and
decrypts at runtime. Five crates: `litmask` (runtime + macros),
`litmask-build` (build.rs helper), `litmask-macros` (proc-macro impl),
`litmask-internal` (shared wire format), `litmask-cli` (keygen +
show-machine-id).

## Dev workflow

```sh
nix-shell --run 'just setup'   # one-time
just ci                         # full CI gate
just test                       # fast test loop
just lint                       # fmt + clippy + typos + taplo + markdown + deny
```

Benchmarks (on demand, not in `just ci`):

```sh
just bench         # runtime overhead (divan) — captures target/bench/runtime.log
just bench-build   # build-time overhead (hyperfine) — writes target/bench-build/*.json
just bench-doc     # regenerate docs/BENCHMARKS.md from the above (run both first)
```

Tool versions pinned in `.tool-versions` — single source of truth.
`rust-toolchain.toml` is auto-generated; do not edit by hand.

## Key files

- `docs/ARCHITECTURE.md` — one-page mental model (read first)
- `CONTEXT.md` — domain glossary (ubiquitous language)
- `docs/SPECIFICATION.md` — full spec, section-numbered
- `docs/TASKS.md` — implementation tasks with acceptance criteria
- `.tool-versions` — pinned tool versions
- `justfile` — all dev recipes

## Architecture

- `litmask-build::emit()` runs in `build.rs`: generates seed, derives
  keys, and selects the seal tier from which key channels are present
  (`LITMASK_UNLOCK_KEY` → External, `LITMASK_MACHINE_ID` → Machine, both
  → MachineExternal, else Embedded). It writes key/seed/wrapper artifacts
  to `OUT_DIR` and publishes the `LITMASK_SEAL_TIER` tag via rustc-env. No
  `unlock_key` is written to disk (the runtime re-derives/re-sources it).
- `litmask-macros` reads the key/seed artifacts from the caller's
  `OUT_DIR` at macro expansion time, encrypts each literal, embeds
  ciphertext as `&[u8]` in the output.
- `litmask` runtime (ADR-0001 governing model): `init!(provider)` /
  `init!(bind_to_machine)` / `init!(bind_to_machine + provider)` install a
  process-global _governing provider_ (`runtime/governor.rs`) and eagerly
  unlock the host's own wrapper through it; once a governor is installed the
  lazy path unlocks every other crate's wrapper through it regardless of
  tier, while the keyless Embedded tier (no governor) self-initializes on
  the first `mask!()` (no bare `init!()`).
  The form is cross-checked against the sealed tier at compile time.
  Decrypted `mask_key`s live in the per-wrapper `runtime/mask_key_store.rs`
  cache; `mask!()` decrypts individual blobs using the wrapper's `mask_key`.
- `litmask-cli`: `keygen` mints unlock material; `show-machine-id` prints
  the host machine-id token used to build-seal the Machine tier. There is
  no post-build rebind step.

## Crate boundaries

| Crate | Runs at | Touches secrets |
|---|---|---|
| `litmask-build` | `build.rs` (compile time) | Yes: generates seed, keys |
| `litmask-macros` | proc-macro expansion | Yes: reads keys from `OUT_DIR` files |
| `litmask-internal` | both build + runtime | Wire format constants only |
| `litmask` | runtime | Yes: decrypts wrapper + blobs |
| `litmask-cli` | build-time helper | Generates unlock material (`keygen`); reads host id (`show-machine-id`). Never touches wrappers |

Changes to `litmask-internal` wire format constants affect all
consumers — verify with `just ci` (not just the crate's own tests).

## Ground rules

- Test-first TDD for every behavior change: write test first, observe red,
  implement, observe green.
- Commits: Conventional Commits (enforced by commitlint), atomic (one
  logical change), with pathspec (`git commit -- path1 path2`). No
  `Co-Authored-By` trailers.
- Comments: Ousterhout style — capture WHY / invariants / contracts only.
  No restating-the-obvious.
- Plans: vertical slices, walking skeleton first.
- Security: never overstate guarantees. Deliberate understatement applies
  to all docs and error messages.
- Public API follows the [Rust API Guidelines checklist](https://rust-lang.github.io/api-guidelines/checklist.html)
  (the upstream list is authoritative; don't mirror it into the repo).
- Docs: behavior is owned by code + tests, not duplicated prose; make
  claims executable, cite evidence in decisions, no self-describing-lie
  surfaces (see "Documentation principles" below). When prose and code
  disagree, the code wins.

## Common tasks

- **Add a new macro:** implement in `litmask-macros`, re-export from
  `litmask/src/lib.rs`, add trybuild compile tests, add integration
  test with `strings` scrub, add to `mask_all` substitution table if
  applicable.
- **Add a new provider:** implement `KeyProvider` in
  `litmask/src/provider/`, add example under `litmask/examples/`,
  gate behind a cargo feature if it pulls in new deps.
- **Change wire format:** bump `FormatVersion`, update
  `litmask-internal` constants, update build/runtime seal + unseal paths,
  add format-version rejection tests.

## Documentation principles

Prose drifts from code; these keep the docs honest (learned from the
`litmask.config` episode, where unverified prose claims survived for a long
time). When in doubt, verify against the code, not the prose.

- **Behavior lives in code + tests, not duplicated prose.** Docs capture the
  _why_, the invariants, and the wire format; they don't restate what the
  code does. Where a doc and the code disagree, the code wins (the doc is a
  bug). `docs/ARCHITECTURE.md` is the front door.
- **Make claims executable where feasible.** "Every build artifact is read"
  is a test (`litmask-build/tests/artifacts_have_consumers.rs`), not a
  promise; runnable example recipes are exercised by `scripts/test-examples.sh`,
  not just shown in prose.
- **Decisions cite checkable evidence.** A "keep/remove X because Y" note
  must name the specific test or `file:line` so Y can be re-verified.
  Unfalsifiable claims ("the tests assert it") are not acceptable.
- **No self-describing-lie surfaces.** A file/header/comment that asserts
  facts about itself must be generated from truth or pinned by a test — never
  hand-written prose that can rot (cf. the removed `litmask.config`
  "SECRET / consumed by the runtime" header, wrong on both counts).
