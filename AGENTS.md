# AI collaborator notes

## Project context

See `docs/ARCHITECTURE.md` for the one-page mental model (read first).
See `CLAUDE.md` for dev workflow and architecture overview.
See `CONTEXT.md` for domain glossary (ubiquitous language).
See `docs/SPECIFICATION.md` for the full spec with section numbers.

## Ground rules

- Test-first TDD for every behavior change.
- Commits: Conventional Commits, atomic (one logical change), with
  pathspec. No `Co-Authored-By` trailers.
- Comments: Ousterhout style — WHY / invariants / contracts only.
  No restating-the-obvious.
- Plans: vertical slices, walking skeleton first.
- Security: never overstate guarantees. Deliberate
  understatement applies to all docs and error messages.

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
