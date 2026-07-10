# Mutation testing playbook

How to run, scope, and trust cargo-mutants here. Config and rationale live
in `.cargo/mutants.toml`; recipes in the `justfile`. This page owns the
_workflow_ knowledge — which scope fits which crate, and the discipline
that keeps the lane honest (learned the hard way; see "Fail-closed guard").

## Scope guide: which run for which crate

| Target | Command | Why |
|---|---|---|
| `litmask-internal`, `litmask-build`, `litmask-cli`, `litmask` (runtime) | `just mutants -p <crate>` | Self-testing crates: package-scoped is fast (1–40 min) and honest |
| `litmask-macros` _logic_ | `just mutants -p litmask-macros` | In-crate unit tests cover the pure cores (parsing, classification, analysis) |
| `litmask-macros` _codegen_ | covered by CI's `mutants-diff` only | Generated-code correctness is owned by downstream trybuild/integration; a whole-crate `--test-workspace` run rebuilds every downstream test binary per mutant (**hours** — don't) |
| Changed lines (any crate) | `just mutants-diff [base]` | `--test-workspace --in-diff`: the workspace-wide kill definition, kept tractable by diff scoping. Runs per PR in CI |

Package-scoped runs of `litmask-macros`/`litmask-build` report
_false survivors_ for anything only exercised downstream (trybuild
`.stderr` snapshots, consumer `build.rs`). That is expected — triage
against the workspace definition (`mutants-diff` or a scoped
`--test-workspace` run) before treating a survivor as a gap.

## Fail-closed guard

`just mutants-verify` (auto-runs before `mutants-diff`; required CI step)
asserts the config hasn't rotted: every crate still yields mutants, every
`exclude_re` entry matches 1..=8 mutants. History: an unescaped `||` in
one entry was regex alternation-with-empty-branch — it matched **every**
mutant and the suite reported clean having tested nothing. Survivor
results stay advisory in CI; harness health does not.

Baseline vitality is free: nextest exits nonzero when zero tests run,
which fails cargo-mutants' `--baseline run` before any mutant is tested.

## Harness-change protocol (positive controls)

Never trust a negative result from a filter you just wrote. After **any**
change to `exclude_re`, `exclude_globs`, `additional_cargo_args`, or run
scoping:

1. `just mutants-verify` — bounds + discovery still sane.
2. One positive control: a scoped run (`--file <one file>`) showing a
   mutant you _know_ a test kills is still caught.

And **small-before-big**: before any long run, do a one-`--file` run and
confirm one expected kill. A 3-hour run that was going to report garbage
announces itself in the first two minutes.

## Operational gotchas

- **Stale state lies.** Results in `mutants.out/` belong to the _last_
  run; reading them after a differently-scoped run misattributes
  survivors (a stale dir once produced a phantom "0 caught"). `just
  clean` purges it; `rm -rf mutants.out` between differently-scoped runs.
- **Read artifacts, not stdout.** cargo-mutants renders a live TTY
  progress bar; captured stdout stays empty until exit. Poll
  `mutants.out/{missed,caught,unviable}.txt` and `outcomes.json` instead.
- **`-p` vs `--test-package`.** `-p X` mutates only X (what you want);
  `--test-package X` mutates the _whole workspace_ and runs only X's
  tests — near-everything "survives".
- **Examples never build.** `additional_cargo_args = ["--tests"]` keeps
  the tier-gated examples out of every mutant build (no single env
  compiles every `init!` form — a designed constraint, not debt). Any
  "unused import" warnings seen while an example fails a tier-mismatch
  build are cascade noise from the failed `init!` expansion, not defects.

## Equivalent-mutant policy

Each `exclude_re` entry: one specific mutant, one falsifiable reason, in
the config next to the pattern. `#[mutants::skip]` was considered and
rejected — it would add the `mutants` proc-macro crate as a dependency of
the published crates (see the config header). Stale entries fail
`mutants-verify` at the commit that renames the function; delete them
there.
