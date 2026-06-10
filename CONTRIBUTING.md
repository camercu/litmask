# Contributing

[![CI](https://github.com/camercu/litmask/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/camercu/litmask/actions/workflows/ci.yml)

## First-time setup

The dev environment is pinned through Nix. One command does the rest:

```sh
nix-shell --run 'just setup'
```

`just setup` is idempotent; safe to re-run any time tool versions or
hook configs drift.

**Prerequisites:** Nix (install from <https://nixos.org/download>). The
script will refuse to run without `nix-shell` on `$PATH`.

`just setup` performs, inside a nix-shell:

1. Regenerates `rust-toolchain.toml` from `.tool-versions` (the
   canonical source for the pinned Rust channel).
2. Materializes the pinned Rust toolchain via `rust-overlay` when the
   nix-shell is entered (an immutable toolchain matching CI, built from
   `rust-toolchain.toml` — no `rustup`).
3. Verifies every tool in `.tool-versions` matches the active
   environment (`just check-tool-versions`).
4. Installs Node devDependencies for commitlint (`npm ci`).
5. Installs git hooks via `pre-commit install`.

After setup, prefer running every dev command inside `nix-shell` so
PATH resolves to the pinned tool versions; the hook layer wraps its
own invocations in `nix-shell --run` so they stay consistent
regardless.

## Everyday workflow

| Command                 | What it does                                                              |
| ----------------------- | ------------------------------------------------------------------------- |
| `just`                  | Lists every recipe.                                                       |
| `just fmt`              | Rustfmt + taplo across the workspace.                                     |
| `just lint`             | fmt-check, clippy, typos, taplo, cargo-deny.                              |
| `just test`             | `cargo nextest run` + doctests.                                           |
| `just test-examples`    | Builds and runs every example under `litmask/examples/`.                  |
| `just check-no-default` | Verifies `--no-default-features --features alloc` (no_std + alloc) build. |
| `just doc`              | Rustdoc with `-D warnings`.                                               |
| `just ci`               | The exact set canonical-gate runs in CI.                                  |

Adding a new example file under `litmask/examples/` is enough to wire
it into `just test-examples` and the strings-scrub test — both
discover examples by glob.

## Git hooks

Three tiers, wired into the local clone by `just setup`:

| Hook         | Stage      | What runs (recipe)                                              |
| ------------ | ---------- | --------------------------------------------------------------- |
| `pre-commit` | every commit | `just pre-commit` — fmt-check, lint-typos, lint-taplo, `cargo check` |
| `pre-push`   | every push   | `just pre-push` — `just lint test test-examples check-no-default doc` (mirrors `just ci`) |
| `commit-msg` | every commit | `commitlint` against Conventional Commits                       |

Push hooks are intentionally heavy: they mirror CI exactly so a green
local push implies a green canonical-gate.

If a hook fails because tool versions drifted (e.g., after a
`.tool-versions` bump), re-run `just setup`.

## Tool pinning

`.tool-versions` is the single source of truth:

- `shell.nix` pins a `nixpkgs` revision whose ports match every tool
  version in `.tool-versions`. Bumping a tool means bumping
  `.tool-versions` AND finding a `nixpkgs` revision that ships the
  new version.
- `rust-toolchain.toml` is **auto-generated** from `.tool-versions`
  by `just setup`. Do not edit it by hand; edit `.tool-versions` and
  re-run setup.
- `just check-tool-versions` enforces equality across every channel.
  Adding a new pin to `.tool-versions` without a matching case in
  `check-tool-versions` now fails loudly.

## Commit messages

Conventional Commits, enforced by:

- The `commit-msg` git hook (locally).
- The `commitlint` CI job (on every push **and** every PR).

The release pipeline parses the commit log to drive version bumps
and CHANGELOG.md sections (see `.releaserc.json`); deviating from
the convention silently drops your commit from the next release.

## CI surface

| Job                   | Toolchain         | Failure mode                                              |
| --------------------- | ----------------- | --------------------------------------------------------- |
| Canonical gate        | `.tool-versions`  | Blocks PR merge.                                          |
| Latest stable advisory | latest stable    | Blocks PR merge — drives `.tool-versions` bumps.          |
| Commitlint            | n/a              | Blocks PR merge / push.                                   |

Dependabot opens weekly PRs against cargo, GitHub Actions, npm, and
pre-commit hook dependencies.

## Release

Releases are driven by
[semantic-release](https://semantic-release.gitbook.io/) with the
[semantic-release-cargo](https://www.npmjs.com/package/semantic-release-cargo)
plugin in `.github/workflows/release.yml`:

1. Every push to `main` runs CI; on success `release.yml` fires
   (workflow_run trigger gated on `conclusion == 'success'`).
2. `just release` runs `npx semantic-release`, which analyzes the
   commit history since the last `v*` tag and either skips (no
   release-worthy commits) or computes the next version.
3. On a bump, the workflow updates `Cargo.toml` + `Cargo.lock`,
   appends to `CHANGELOG.md`, pushes a `chore(release): <version>`
   commit to `main`, tags `v<version>`, and cuts a GitHub Release.

To preview a release locally from a clean working tree:

```sh
npm ci
GITHUB_TOKEN=<personal-token> npx semantic-release --dry-run
```

**GitHub setup requirement:** the `release` job uses the `release`
environment. The first successful release requires this environment
to exist in the repository's GitHub settings (Settings →
Environments → New environment → "release"). The `CRATES_API_KEY`
secret can be added there once crates.io publish is enabled in
`.releaserc.json` (currently `publish: false`). Because the release
job pushes commits + tags directly to `main`, any branch-protection
rules must permit pushes from `github-actions[bot]` (or be relaxed
for this workflow's `GITHUB_TOKEN`).

## Reporting issues

File an issue at <https://github.com/camercu/litmask/issues>. For
security-sensitive findings, do not file a public issue; reach out
via the channel listed in `SECURITY.md` (once present).
