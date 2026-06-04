# litmask — Remaining Tasks

Source: [docs/SPECIFICATION.md](./SPECIFICATION.md)
Style reference: [github.com/camercu/relentless](https://github.com/camercu/relentless)

Tasks 1–34 are complete except for the three acceptance criteria below.
Each remaining item is either deferred (blocked by an external constraint)
or pending a CI run. Original task numbering preserved for traceability.

---

## Task 7: `include_str!` tracked-path rebuild (DEFERRED)

**Implements:** §2.1.1.5, §2.1.1.6, §2.1.1.9, §2.1.1.10, §1.9.6 (mask! rows)

The rest of Task 7 shipped. One acceptance criterion remains unmet.

### Remaining Acceptance Criteria

- [ ] Editing `fixtures/quote.txt` triggers a rebuild of the dependent
      crate (verifies `tracked_path` registration)

**Deferment logic:** UNMET on stable. `proc_macro::tracked_path::path`
is a nightly-only API (rust-lang/rust#73921). Documented in
`litmask-macros/src/mask.rs::resolve_include_str` — until the API
stabilizes, users must `cargo clean` or touch a tracked source file
after editing an included file. Revisit when the API stabilizes.

---

## Task 29: Platform CI matrix — POSIX (PENDING CI)

**Implements:** §2.13.1.1–§2.13.1.3, §2.13.2.1–§2.13.2.6, §1.10.5
(Ubuntu / AlmaLinux / macOS / FreeBSD / OpenBSD)

Workflow `.github/workflows/platform-matrix.yml` is written and all
behavioral criteria pass. One criterion is a live-CI confirmation.

### Remaining Acceptance Criteria

- [ ] All five jobs green on a clean PR

**Deferment logic:** Requires a real PR run across all five POSIX
platforms (Ubuntu, AlmaLinux, macOS, FreeBSD, OpenBSD) to observe green.
The workflow, smoke script, and per-platform assertions (incl. OpenBSD
EX_UNAVAILABLE) are in place; this item closes when a clean PR shows all
five jobs passing.

---

## Task 33: Pre-1.0 security review — cross-machine reproducibility (DEFERRED)

**Implements:** CLAUDE.md step 6 (security review); gates v1.0 release

The audit (`docs/SECURITY_AUDIT.md`) is complete with zero blocker and
zero fix-before-1.0 findings. One verification step remains.

### Remaining Acceptance Criteria

- [ ] Reproducibility cross-machine check produces byte-identical
      artifacts

**Deferment logic:** Requires a second machine. Single-machine
reproducibility is already verified by the
`reproducible_builds_produce_identical_artifacts` test; cross-machine
verification under §1.3.3 conditions is deferred to CI (two clean
checkouts with the same `LITMASK_RNG_SEED`).
