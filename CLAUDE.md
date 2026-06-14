# litmask — Claude Code project notes

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

Tool versions pinned in `.tool-versions` — single source of truth.
`rust-toolchain.toml` is auto-generated; do not edit by hand.

## Key files

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
  to `OUT_DIR` and publishes the `LITMASK_SEAL_TIER` tag via rustc-env;
  only the Embedded tier writes the `litmask.config` diagnostic artifact.
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

## Conventions

- Conventional Commits enforced by commitlint
- TDD: write test first, observe red, implement, observe green
- Atomic commits with pathspec (`git commit -- path1 path2`)
- No `Co-Authored-By` trailers
- Comments follow Ousterhout: capture WHY / invariants / contracts only
