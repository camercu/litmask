# litmask — Claude Code project notes

## What this is

Rust workspace that encrypts string literals at compile time (AEAD) and
decrypts at runtime. Five crates: `litmask` (runtime + macros),
`litmask-build` (build.rs helper), `litmask-macros` (proc-macro impl),
`litmask-internal` (shared wire format), `litmask-cli` (bind/inspect).

## Dev workflow

```sh
nix-shell --run 'just setup'   # one-time
just ci                         # full CI gate
just test                       # fast test loop
just lint                       # fmt + clippy + typos + taplo + deny
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
  keys, writes `litmask.config` and Rust env vars for the proc macro.
- `litmask-macros` reads env vars at macro expansion time, encrypts
  each literal, embeds ciphertext as `&[u8]` in the output.
- `litmask` runtime: `init!()` decrypts `mask_key` from the embedded
  wrapper using `unlock_key` from a `KeyProvider`. `mask!()` decrypts
  individual blobs using `mask_key`.
- `litmask-cli bind` re-encrypts the wrapper under a hardware-derived
  key. `inspect` verifies the wrapper is findable.

## Conventions

- Conventional Commits enforced by commitlint
- TDD: write test first, observe red, implement, observe green
- Atomic commits with pathspec (`git commit -- path1 path2`)
- No `Co-Authored-By` trailers
- Comments follow Ousterhout: capture WHY / invariants / contracts only
