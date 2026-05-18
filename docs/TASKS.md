# litmask — Tasks

Source: [docs/SPECIFICATION.md](./SPECIFICATION.md)
Style reference: [github.com/camercu/relentless](https://github.com/camercu/relentless)

Tasks 1–4 establish the deterministic dev substrate (workspace, Nix shell,
hooks, CI). Task 5 is the feature walking skeleton — thinnest end-to-end
`mask!("text")` round-trip. Tasks 6–32 flesh out from that working core.
Task 33 is the pre-1.0 security audit gate.

Each task is a vertical slice through every layer it touches and is demoable
on its own.

## Spec amendments required (land in `SPECIFICATION.md` before affected tasks)

Three design decisions extend `SPECIFICATION.md`. Land them as ADRs
under `docs/adr/` or as inline amendments before the affected task
starts.

- **`include_str!` / `concat!` rewrite — proc-macro-time resolution
  (extends §2.3.2.5).** `mask!`'s parser is extended to accept two
  specific built-in macro invocations as inputs in addition to bare
  literals: `include_str!(<path>)` and `concat!(<args>)`. When detected,
  `mask!` reads the file (for `include_str!`) using `std::fs::read_to_string`
  with `proc_macro::tracked_path::path` to register the file as a build
  dependency, or evaluates `concat!` arguments (which must themselves
  be string / byte / cstr literals or further `concat!`/`include_str!`
  calls) at proc-macro time. The resulting string is then masked
  exactly as if it had been a bare literal. `#[mask_all]`'s rewrite of
  `include_str!` and `concat!` (§2.3.2.5) becomes the natural
  `mask!(include_str!("x"))` / `mask!(concat!(...))` form. Land before
  Task 13. Required Task 7 spec update: the "mask! accepts string,
  byte string, or C string literals" error substring is preserved, but
  `mask!`'s grammar formally also accepts `include_str!` and
  `concat!` invocations.
- **`#[mask_all]` warning emission via ghost-deprecation hack
  (extends §2.3.1.4 et al.).** Until `proc_macro::Diagnostic::emit`
  stabilizes, `#[mask_all]` emits warnings by injecting per-skip
  ghost items of the form
  `{ #[deprecated(note = "litmask: skipped literal at <file>:<line>: <reason>")] const _LITMASK_SKIP_<n>: () = (); _LITMASK_SKIP_<n> }`
  (or equivalent unused `const _` pattern that triggers the
  `deprecated` lint at the call site). Each ghost item is unique by
  counter to avoid name collision. The lint surfaces as a normal
  `warning: use of deprecated constant` in cargo output. Under
  `#[mask_all(strict)]`, ghost items use `compile_error!` instead.
  Migration to `Diagnostic::emit` is a v2 candidate once stabilized.
  Land before Task 12.
- **Runtime cipher dispatch in `litmask-cli` (extends §1.5.1, §1.7.3,
  §2.9.1).** `litmask-cli` does NOT mirror the `aes-gcm` feature flag.
  Instead, the CLI compiles BOTH `chacha20poly1305` and `aes-gcm` and
  dispatches at runtime based on the wrapper's cipher-id byte (`0x01`
  → ChaCha20-Poly1305, `0x02` → AES-256-GCM). This breaks the
  "exactly one cipher per build" rule for the CLI specifically (the
  rule still holds for the `litmask` runtime crate that ships in user
  binaries). Rationale: avoids the failure mode where a user builds a
  binary `--features aes-gcm` but `cargo install`s the default CLI
  and bind silently fails. Land before Task 18.

---

## Task 1: Cargo workspace + Rust toolchain + bare justfile (AFK)

**Implements:** infra (foundation)
**Blocked by:** None — start here

Workspace root `Cargo.toml` declaring three member crates: `litmask`
(proc-macro + library), `litmask-build` (build helper), `litmask-cli`
(binary). `rust-toolchain.toml` pins the toolchain (channel `1.88`,
`profile = "minimal"`, `components = ["clippy", "rustfmt"]`). `.gitignore`
covers `target/`, OS junk, editor junk; `Cargo.lock` IS committed because
the workspace contains a binary (`litmask-cli`) per Cargo convention.
Bare `justfile` exposes the minimal recipes needed to drive the project
from day one: `fmt`, `fmt-check`, `lint` (clippy with `-D warnings`),
`test` (cargo nextest preferred but plain `cargo test` acceptable until
Task 2 pins nextest), `build`, `doc` (`cargo doc --no-deps` with
`RUSTDOCFLAGS="-D warnings"`), and `ci` that chains `fmt-check`, `lint`,
`test`, `build`, `doc`. Empty crate stubs compile cleanly under the
pinned toolchain.

### Acceptance Criteria

- [ ] `cargo metadata --format-version 1` lists all three workspace crates
- [ ] Pinned toolchain is honored: `rustc --version` matches
      `rust-toolchain.toml` after `rustup show`
- [ ] `just fmt-check`, `just lint`, `just test`, `just build`, `just doc`,
      `just ci` each exit 0 against the empty workspace
- [ ] `git status` is clean after `just fmt` (no unformatted code in stubs)
- [ ] `Cargo.lock` is tracked by git (committed)

---

## Task 2: Nix dev shell + .tool-versions + tool-version drift check (AFK)

**Implements:** infra
**Blocked by:** Task 1

`shell.nix` pins nixpkgs by tarball URL + sha256 and exposes the development
toolchain: `rustup`, `just`, `pre-commit`, `cargo-deny`, `cargo-nextest`,
`typos`, `taplo`, `nodejs`. `.envrc` contains `use nix` for direnv. New
`.tool-versions` is the single source of truth for pinned tool versions
(rust, just, cargo-deny, cargo-nextest, typos-cli, taplo-cli). `shell.nix`
includes a leading comment instructing readers to mirror `.tool-versions`.
`justfile` gains `check-tool-versions` (parses `.tool-versions`, compares
against runtime tool versions, fails on drift) and `setup` (delegates to
`scripts/setup-dev.sh`). `scripts/setup-dev.sh` is a stub at this point;
fleshed out in Task 3.

### Acceptance Criteria

- [ ] `nix-shell` (or `direnv allow` then `cd`) produces an environment in
      which `rustc`, `just`, `cargo-deny`, `cargo-nextest`, `typos`, `taplo`,
      and `node` are all on `PATH` at the pinned versions
- [ ] `just check-tool-versions` exits 0 inside the Nix shell
- [ ] Bumping a version in `.tool-versions` without updating `shell.nix`
      causes `just check-tool-versions` to fail with a diagnostic
- [ ] `just setup` exits 0

---

## Task 3: Pre-commit + commit linting + dependency audit configs (AFK)

**Implements:** infra
**Blocked by:** Task 2

`.pre-commit-config.yaml` mirrors the relentless layout: upstream
`pre-commit/pre-commit-hooks` (`end-of-file-fixer`, `trailing-whitespace`,
`check-added-large-files`) plus three local hooks — `pre-commit` stage runs
`nix-shell --run 'just pre-commit'` (fast: fmt-check + lint-typos +
`cargo check --all-targets --quiet`), `pre-push` stage runs
`nix-shell --run 'just pre-push'` (slow: clippy + test + doc with
`-D warnings`), `commit-msg` stage runs `npx commitlint --edit`.
`commitlint.config.js` extends `@commitlint/config-conventional`.
`deny.toml` configures advisories, licenses, bans, sources. `.typos.toml`
is present with an empty allow list. `.prettierrc.yaml` formats
non-Rust files (yaml, json, md). `package.json` declares devDependencies
for `@commitlint/cli` and `@commitlint/config-conventional`. `justfile`
gains `lint-typos`, `lint-deny`, `pre-commit`, `pre-push`; `lint` recipe
expands to chain `fmt-check`, `lint-clippy`, `lint-typos`, `lint-deny`.
`scripts/setup-dev.sh` installs git hooks via
`pre-commit install --install-hooks --hook-type pre-commit --hook-type pre-push --hook-type commit-msg`
and runs `npm ci`.

### Acceptance Criteria

- [ ] `just setup` installs `pre-commit`, `pre-push`, and `commit-msg` hooks
      under `.git/hooks/`
- [ ] `pre-commit run --all-files` exits 0
- [ ] GIVEN a staged change, WHEN attempting `git commit -m "fix stuff"`,
      THEN commitlint rejects with non-zero exit
- [ ] GIVEN a staged change, WHEN attempting `git commit -m "feat: add x"`,
      THEN commit succeeds
- [ ] `just lint` runs typos + deny + clippy + fmt-check, all green
- [ ] `cargo deny check` advisories/licenses/bans/sources all green

---

## Task 4: GitHub Actions canonical-gate CI (AFK)

**Implements:** infra (foundation for §2.13)
**Blocked by:** Task 3

`.github/workflows/ci.yml` defines three jobs: `canonical-gate` (parses
`.tool-versions`, installs the pinned Rust toolchain via
`dtolnay/rust-toolchain`, installs pinned dev tools via
`taiki-e/install-action`, applies `Swatinem/rust-cache`, runs `just ci`),
`stable-advisory` (latest stable Rust, `continue-on-error: true`, runs
`just lint-clippy-stable` + `just test-stable`), and `commitlint`
(`actions/checkout@v4` with `fetch-depth: 0`, runs
`npx commitlint --from origin/${{ github.base_ref }} --to HEAD` on PRs;
catches contributors who skipped local hooks). Workflow triggers on
`push` and `pull_request`. `concurrency` group cancels in-progress runs on
non-`main` refs. `permissions: contents: read`. `justfile` gains
`lint-clippy-stable` and `test-stable` recipes (`cargo +stable ...`).

### Acceptance Criteria

- [ ] PR opened against `main` triggers the workflow
- [ ] `canonical-gate` job uses the toolchain version from `.tool-versions`
- [ ] `canonical-gate` runs `just ci` and exits 0
- [ ] `stable-advisory` job runs independently; failure does not block PR
- [ ] `commitlint` job runs on PRs and rejects non-Conventional commits
      (verified by opening a draft PR with a `bad message` commit)
- [ ] Second run of the same workflow shows a cache hit on `Swatinem/rust-cache`
- [ ] Pushing a new commit to a PR cancels the previous in-progress run

---

## Task 5: Walking skeleton — `mask!("text")` round-trip (AFK)

**Implements:** §2.1.1.1, §2.1.1.2, §2.1.1.7, §2.1.1.12, §2.4.1.1,
§2.4.1.6–§2.4.1.10, §2.5.1.1–§2.5.1.4, §2.5.2.1–§2.5.2.3,
§2.6.1.1–§2.6.1.4, §2.7.1–§2.7.9, §2.8.1.1, §2.8.2.1–§2.8.2.3
**Blocked by:** Task 4

Thinnest end-to-end feature path proving the architecture. `litmask-build`
exposes `emit()` which generates a fresh seed, derives `mask_key` and
`unlock_key` deterministically with `rand_chacha::ChaCha20Rng`, encrypts
`mask_key` under `unlock_key` using ChaCha20-Poly1305, writes
`$OUT_DIR/litmask_key.bin` and `$OUT_DIR/litmask_seed.bin`, and writes
`litmask.config` (TOML) with `unlock_key`, `locator`, `length` to
`target/<profile>/litmask.config`. The `litmask` crate exports the
`KeyProvider` trait, the `UnlockKey` 32-byte newtype with `Drop` zeroize,
the default `EnvVarProvider` (reads `LITMASK_UNLOCK_KEY` as base64url),
`init()` and `init_with()` (decrypt the embedded `mask_key` wrapper into a
process-global `OnceLock<MaskKey>`), and a `mask!` proc-macro accepting a
single string literal — emitting a `[u8; N]` blob (nonce derived per
§1.5.2 from file/line/column + seed) and runtime decryption returning
`String`. Lazy init triggers on first `mask!` call when no explicit
`init()` was called. The runtime crate is `#![no_std]` + `alloc` from day
one (gates `EnvVarProvider` behind the `std` feature so `litmask::init`
default chain compiles only with `std` enabled, which is the default);
this avoids a horizontal `no_std` retrofit later. The base64url helper
module is established here using `base64ct` with RFC 4648 §5 url-safe
no-padding encoding and is the single source for all subsequent providers
and CLI tooling. `InitError` ships in this task with one variant —
`KeyProvider(KeyError)` — sufficient for compilation and the happy path;
the `Decryption` variant and panic-hygiene policy are added in Task 8.
A walking-skeleton sample binary at `litmask/examples/hello_world.rs`
masks one fixture string and prints the decrypted result. The fixture
is a public-domain quotation chosen to be (a) memorable, (b) lexically
unusual enough that `strings` greps for substrings will not false-
positive against std / dependency text, and (c) free of copyright
encumbrance:
`"The reports of my death have been greatly exaggerated. — Mark Twain"`
(Twain d. 1910, US public domain). The unusual conjunction "greatly
exaggerated" plus the em-dash attribution makes substring collisions
in linked rlibs effectively impossible. An integration test at
`litmask/tests/walking_skeleton.rs` builds the example via
`cargo build --example hello_world`, verifies via `strings` that the
fixture substring `"greatly exaggerated"` is absent from the binary,
then runs the example with `LITMASK_UNLOCK_KEY` sourced from the
build's `litmask.config` and asserts stdout matches the fixture
followed by `\n`.

### Acceptance Criteria

- [ ] `cargo build --example hello_world` succeeds
- [ ] `strings target/<profile>/examples/hello_world` does NOT contain
      the substring `greatly exaggerated`
- [ ] GIVEN `LITMASK_UNLOCK_KEY` set to the value in `litmask.config`,
      WHEN running the example, THEN stdout is the Twain fixture
      followed by `\n` and exit code is 0
- [ ] `litmask.config` is present at the expected path with `unlock_key`,
      `locator`, and `length = 62` fields
- [ ] Calling `mask!("...")` without prior `init()` succeeds via lazy init
- [ ] `let _: Box<dyn KeyProvider> = Box::new(EnvVarProvider::default());`
      compiles (object-safety check)
- [ ] BLAKE3 nonce-derivation unit tests in the runtime crate cover:
      determinism (same seed + same call site → same nonce), uniqueness
      (distinct file/line/column → distinct nonces across a sample of
      ≥1000 sites), and independence (adding code AFTER a call site does
      not change that call site's nonce — only line numbers shift for
      code AFTER the addition)
- [ ] base64url helper module unit tests cover round-trip + reject of
      padded inputs
- [ ] `cargo build -p litmask --no-default-features --features alloc`
      succeeds (proves runtime is `no_std` + `alloc` clean from day one;
      `EnvVarProvider` is gated behind `std` so it disappears under
      `--no-default-features`)
- [ ] `justfile` gains a `test-examples` recipe that runs every example
      end-to-end (`cargo run --example hello_world` here; future
      examples added to the recipe in their owning tasks); `just ci`
      invokes it so example bitrot is caught
- [ ] `just ci` remains green

---

## Task 6: `mask!` byte + C string literals (AFK)

**Implements:** §2.1.1.1, §2.1.1.3, §2.1.1.4
**Blocked by:** Task 5

Extend `mask!` literal dispatch to handle `b"..."` (returning `Vec<u8>`)
and `c"..."` (returning `CString` with NUL terminator). Add example
coverage for each new return type to the `examples/` directory and
expand integration tests.

### Acceptance Criteria

- [ ] `let v: Vec<u8> = mask!(b"\x01\x02\x03");` decrypts to `vec![1, 2, 3]`
- [ ] `let c: CString = mask!(c"hello");` decrypts to a `CString` whose
      `to_bytes()` equals `b"hello"`
- [ ] Strings check on a binary masking byte / cstr literals shows no
      plaintext leakage
- [ ] Existing string-literal behavior unchanged

---

## Task 7: `mask!` invalid input + position rejection (AFK)

**Implements:** §2.1.1.5, §2.1.1.6, §2.1.1.9, §2.1.1.10, §1.9.6 (mask! rows)
**Blocked by:** Task 5, Task 6 — the required error substring "mask!
accepts string, byte string, or C string literals" is only truthful once
all three literal kinds are actually accepted

`mask!` produces compile errors with the exact required substrings when
given non-literal expressions, wrong literal types (int/float/bool/char),
or used in `const`/`static` initializers or pattern positions. Coverage
provided via `trybuild` fixtures under `litmask/tests/compile/`.
Per the spec amendment in the intro, `mask!`'s grammar is also extended
in this task to accept `include_str!(<path>)` and `concat!(<args>)`
invocations as inputs (resolved at proc-macro time). The error
substring "mask! accepts string, byte string, or C string literals"
remains the rejection message for everything else; the two built-in
exceptions are silent successes.

### Acceptance Criteria

- [ ] `mask!(42)` fails compilation with message containing
      `mask! accepts string, byte string, or C string literals`
- [ ] `mask!(some_var)` fails compilation with the same substring
- [ ] `const X: String = mask!("x");` fails with message containing
      `mask! cannot be used in const or static contexts`
- [ ] `match s { mask!("foo") => ... }` fails with message containing
      `mask! cannot be used in pattern position`
- [ ] All four cases covered by `trybuild` fixtures wired into `cargo test`
- [ ] `mask!(include_str!("fixtures/quote.txt"))` compiles AND the file
      contents are absent from the binary `strings` output (verifies the
      built-in extension; trybuild positive fixture)
- [ ] `mask!(concat!("a", "b", "c"))` compiles and `mask!` returns
      `String::from("abc")` at runtime
- [ ] Editing `fixtures/quote.txt` triggers a rebuild of the dependent
      crate (verifies `tracked_path` registration)

---

## Task 8: Tampering panic policy + decryption errors (AFK)

**Implements:** §2.1.1.11, §2.1.1.13, §2.7.7, §1.9.5, §1.9.2
(`Decryption` variant)
**Blocked by:** Task 5

Adds the `InitError::Decryption` variant introduced by this task (Task 5
shipped `InitError::KeyProvider(KeyError)` only). Decryption failure at
a `mask!` call site panics without contributing any litmask-specific
message text. Implementation uses `match`/`panic!()` (no message) or
`.unwrap()` on a std/dependency-crate result. Init-time decryption
failure returns `Err(InitError::Decryption)`. AEAD authentication
failure on either the embedded `mask_key` wrapper (init path) or on any
per-string blob (call-site path) is detected and surfaced through the
appropriate channel — `Result` for init, panic for call site.

### Acceptance Criteria

- [ ] GIVEN a binary with a single per-string blob byte flipped, WHEN
      `mask!` is invoked at that call site, THEN the process panics
- [ ] `strings` over the binary reveals NO panic-message text containing
      `litmask`, `mask`, `tamper`, `decrypt`, or any other litmask-specific
      identifier
- [ ] GIVEN a corrupted `mask_key` wrapper, WHEN `init()` is called,
      THEN it returns `Err(InitError::Decryption)`
- [ ] No `.expect("...")` or `panic!("...")` with custom message exists in
      the runtime decryption path (verified by grep test or clippy lint)

---

## Task 9: `unmasked!` macro (AFK)

**Implements:** §2.1.2.1–§2.1.2.4
**Blocked by:** Task 6

`unmasked!` is an identity macro that accepts any string / byte string /
C string literal and expands to that literal unchanged, preserving its
original type. It is recognized by `#[mask_all]` (added in Task 12) as an
explicit opt-out marker.

### Acceptance Criteria

- [ ] `let s: &str = unmasked!("plain");` compiles and equals `"plain"`
- [ ] `let b: &[u8; 3] = unmasked!(b"abc");` compiles with the array type
- [ ] `let c: &CStr = unmasked!(c"hi");` compiles with `&CStr` type
- [ ] Generated code for `unmasked!(literal)` and the bare literal are
      equivalent (no extra runtime overhead — verified by checking
      expansion equals the input token)

---

## Task 10: `maskfmt!` basic — literal template, positional args (AFK)

**Implements:** §2.2.1.1–§2.2.1.4, §2.2.2.1, §2.2.2.5, §2.2.2.7,
§2.2.2.8, §2.2.3.1, §2.2.3.2
**Blocked by:** Task 5

`maskfmt!(template_literal, args...)` parses the template, masks each
static fragment between placeholders individually under the same
encryption as `mask!`, preserves format specifications verbatim
(`{:>10}`, `{:.3}`, `{:#x}`, `{:?}`, `{:#?}`), splices positional args
through to a runtime `format!` of the reconstructed template. Returns
`String`. Compile error for non-literal templates contains the substring
required by §1.9.6.

### Acceptance Criteria

- [ ] `maskfmt!("x={}, y={:.2}", 1, 2.5)` returns `"x=1, y=2.50"`
- [ ] Output of `maskfmt!(t, args...)` byte-equals output of `format!(t,
      args...)` across debug, hex, padded, and precision specifiers
- [ ] `maskfmt!(some_var, 1)` fails compilation with the substring
      `maskfmt! requires a string literal template at the call site`
- [ ] Strings check shows template fragments are not present in plaintext

---

## Task 11: `maskfmt!` named args + implicit captures (AFK)

**Implements:** §2.2.2.2, §2.2.2.3, §2.2.2.4, §2.2.2.6
**Blocked by:** Task 10

Named arguments (`maskfmt!("{x}", x = expr)`) are rewritten to introduce
a `let` binding before the runtime `format!` call so each `expr`
evaluates exactly once, then referenced positionally. Implicit-capture
placeholders (Rust 2021 `{var}` with no corresponding named argument) are
rewritten to positional references to the existing `var` local; no new
`let` binding is introduced. Dynamic width/precision (`{:>w$}`,
`{:.p$}`) supported with positional rewriting. Placeholder names do not
appear anywhere in the compiled binary.

### Acceptance Criteria

- [x] GIVEN a side-effecting expression `e` that increments a counter,
      WHEN `maskfmt!("{x} {x}", x = e)` is evaluated, THEN the counter
      increments exactly once
- [x] `let var = 7; maskfmt!("{var}")` returns `"7"`
- [x] `maskfmt!("{:>w$}", "hi", w = 5)` returns `"   hi"`
- [x] Strings check shows no placeholder name (`x`, `var`, etc.) present
      in plaintext
- [x] Output matches `format!` byte-for-byte for all named/implicit cases

---

## Task 12: `#[mask_all]` — bare literal substitution (AFK)

**Implements:** §2.3.1.1–§2.3.1.6, §2.3.2.1, §2.3.2.6
**Blocked by:** Task 9

`#[mask_all]` proc-macro attribute applied to a module recursively walks
its AST and rewrites bare string / byte string / C string literal
expressions to `mask!(literal)`. Recurses into nested modules,
functions, blocks, and closures. Skips literals in pattern positions,
`const`/`static` initializers, attribute arguments, and inside
`mask!`/`maskfmt!`/`unmasked!` invocations. Skips `dbg!`, `stringify!`,
`assert_eq!`/`assert_ne!` (no-message form). Each skip emits a
compile-time warning naming file, line, and reason via the
**ghost-deprecation hack** decided in the spec amendments: an injected
unused `const _LITMASK_SKIP_<n>: () = ();` carrying
`#[deprecated(note = "litmask: skipped literal at <file>:<line>: <reason>")]`,
referenced once in the same scope so rustc fires its own
`use of deprecated constant` warning. Counter `<n>` ensures uniqueness
within a module. Migration to `proc_macro::Diagnostic::emit` is filed as
a v2 candidate.

### Acceptance Criteria

- [x] GIVEN a module with `let s = "secret";`, WHEN `#[mask_all]` is
      applied, THEN compiled binary contains no `secret` plaintext and
      `s` decrypts to `String::from("secret")` at runtime
- [x] `match x { "literal" => ... }` is left unchanged and warned about
- [x] `const X: &str = "foo";` is left unchanged and warned about
- [x] `mask!("already masked")` inside the module is not double-masked
- [x] Warnings include file:line and a reason string
- [x] Coverage spans nested modules, functions, blocks, and closures

---

## Task 13: `#[mask_all]` — full macro substitution table (AFK)

**Implements:** §2.3.2.2–§2.3.2.5, §2.3.2.7
**Blocked by:** Task 12, Task 11

`#[mask_all]` recognizes and rewrites macro families per §2.3.2:
- `format!(lit, ...)` → `maskfmt!(lit, ...)`; non-literal template:
  warn, mask literal args recursively
- `println!`/`eprintln!`/`print!`/`eprint!`/`write!`/`writeln!` with
  literal template: rewrite to
  `{ let __s = maskfmt!(t, args...); <macro>("{}", __s) }`
- Panic family (`panic!`, `todo!`, `unimplemented!`, `debug_assert!`,
  `assert!`/`assert_eq!`/`assert_ne!` with custom message form):
  analogous wrapping with `"{}"` template
- `include_str!`, `concat!`: wrap entire invocation in `mask!()` —
  works because of the spec amendment in the intro: `mask!`'s parser
  is extended (Task 7 / amended §2.3.2.5) to accept these two specific
  built-ins as inputs and resolve them at proc-macro time via
  `proc_macro::tracked_path::path` + `std::fs::read_to_string` (for
  `include_str!`) or by recursive evaluation of literal arguments (for
  `concat!`). The resulting string is masked exactly like a bare literal.
- Unrecognized / user-defined macros: leave literal arguments unmasked
  with per-literal warning (via the ghost-deprecation hack from Task 12)

### Acceptance Criteria

- [x] GIVEN `println!("hi {}", n);` inside `#[mask_all]`, WHEN compiled,
      THEN plaintext `"hi "` is absent from the binary; runtime output
      identical to original
- [x] `format!("x={x}", x = 1)` rewritten correctly and produces same
      output as without `#[mask_all]`
- [x] `panic!("boom")` rewritten so panic still fires with `"boom"`
      string at runtime, but `"boom"` is absent from binary plaintext
- [x] `include_str!("file.txt")` runtime value equal to file contents
      and file contents absent from binary plaintext
- [x] User-defined `my_macro!("foo")` left alone, warning emitted

### Known limitations (track in security docs)

Document these for users so they understand which literals stay
plaintext under `#[mask_all]`:

- **Literals inside `vec!` / `thread_local!` / `lazy_static!` /
  other user-defined or `macro_rules!` macros.** `syn::VisitMut` does
  not descend into a macro invocation's `mac.tokens`, so the walker
  cannot see and rewrite literals nested inside arbitrary macro
  bodies. Workaround: wrap each literal manually with `mask!()` /
  `maskfmt!()` / `unmasked!()`.
- **Literals inside `format_args!` invocations.** `format_args!`
  returns `core::fmt::Arguments<'_>` (a borrowed view, not a
  `String`), so it cannot be swapped for `maskfmt!` (which returns
  `String`). Treated as `UserDefined` and warned on. Workaround:
  rewrite the call to a `format!` (rewritten to `maskfmt!`) and
  thread the resulting `String` through manually.
- **`include_str!(...)` / `include_bytes!(...)` / `env!(...)` /
  `option_env!(...)` are rewritten via the `mask!(include_str!(...))`
  shim, which only recognizes `include_str!` and `concat!` today.**
  Symmetric `include_bytes!` / `env!` / `option_env!` support
  requires dedicated `include_masked_str!` / `include_masked_bytes!`
  / `env_masked!` / `option_env_masked!` macros (Task 34 below).

---

## Task 14: `#[mask_all(strict)]` (AFK)

**Implements:** §2.3.3.1, §2.3.3.2
**Blocked by:** Task 13

The `strict` argument upgrades skip warnings (from §2.3.1.4, §2.3.2.2,
§2.3.2.3, §2.3.2.4 non-literal-template branches, and §2.3.2.7) to
compile errors. Every string literal in a `#[mask_all(strict)]` module
must be either covered by the substitution table or marked with
`unmasked!()`.

### Acceptance Criteria

- [ ] GIVEN a `#[mask_all(strict)]` module containing a bare literal in a
      pattern position, WHEN compiled, THEN compilation FAILS
- [ ] GIVEN the same module after wrapping the literal with `unmasked!()`,
      WHEN compiled, THEN compilation succeeds
- [ ] `#[mask_all(strict)]` with `format!(non_literal_template, ...)`
      fails compilation
- [ ] `#[mask_all]` (non-strict) variant is unchanged: still warns

---

## Task 15: `FileProvider` (AFK)

**Implements:** §2.5.3.1–§2.5.3.4
**Blocked by:** Task 5

`FileProvider::new(path)` reads `unlock_key` from a filesystem path with
default base64url encoding (using the helper module from Task 5).
`FileProvider::with_encoding(path, encoding)` allows `KeyEncoding::Raw`
as alternative. In-memory copy of file contents is zeroed via `zeroize`
immediately after key extraction. Errors map to `KeyError::NotFound`
(missing file), `KeyError::Permission` (unreadable file),
`KeyError::InvalidFormat` (wrong length or bad encoding). Rustdoc
includes a TOCTOU note: a file replaced between permission probe and
read is not protected against; production deployments should rely on
filesystem-level access control rather than `FileProvider` alone for
trust. Adds `litmask/examples/file_provider.rs` masking the same Twain
fixture but sourcing `unlock_key` from a path instead of an env var
(spec §2.12.1.5: example binary per provider).

Zeroize-on-drop is verified concretely via a `Counted<T>` newtype
wrapper used only in tests: `Counted` wraps the file-buffer `Vec<u8>`,
implements `Zeroize` by both zeroing the buffer AND incrementing a
`AtomicUsize` counter, then implements `Drop` calling `Zeroize::zeroize`.
The test asserts the counter increments after the provider returns.
This avoids reading dropped memory (UB) while still proving the path
runs.

### Acceptance Criteria

- [ ] GIVEN a file with a base64url-encoded 32-byte key, WHEN
      `FileProvider::new(path).unlock_key()`, THEN returns `Ok(UnlockKey)`
      with the expected bytes
- [ ] Missing file → `Err(KeyError::NotFound)`
- [ ] File mode 000 → `Err(KeyError::Permission)`
- [ ] File contents not 32 decoded bytes → `Err(KeyError::InvalidFormat)`
- [ ] `Counted<T>` zeroize-tracking test confirms the file-buffer
      zeroize path runs exactly once after the provider returns
- [ ] Raw-encoding variant accepts a 32-byte raw file
- [ ] `litmask/examples/file_provider.rs` builds and runs end-to-end
      against a generated key file
- [ ] Rustdoc on `FileProvider` includes the TOCTOU caveat

---

## Task 16: `HardwareIdProvider` (`hw-id` feature) (AFK)

**Implements:** §2.5.4.1–§2.5.4.3, §1.6.5
**Blocked by:** Task 5

Feature-gated provider behind `hw-id`. `HardwareIdProvider::new()`
constructs with no salt; `with_salt(&'static [u8])` mixes salt via
BLAKE3-keyed-hash. `unlock_key()` reads machine ID via `machine-uid`,
applies BLAKE3-keyed-hash with salt (or zero salt) to derive 32 bytes,
and returns `Ok(UnlockKey)`. On `machine-uid` failure, returns
`Err(KeyError::Provider(Box::new(err)))`. `KeyError::Provider` carries
`Box<dyn core::error::Error + Send + Sync>` (Send + Sync required so
errors propagate across thread boundaries; under no_std the bound uses
`core::error::Error`, requires `alloc` for `Box`). Adds
`litmask/examples/hw_id_provider.rs` masking the Twain fixture and
sourcing `unlock_key` from the host machine ID (spec §2.12.1.5).

### Acceptance Criteria

- [ ] On a host with a stable machine ID, two consecutive
      `HardwareIdProvider::new().unlock_key()` calls return identical bytes
- [ ] Different `with_salt` values produce different keys for the same host
- [ ] `cargo build --no-default-features` (no `hw-id`) does NOT include
      `HardwareIdProvider` symbol
- [ ] On a host where `machine-uid::get()` fails, returns
      `Err(KeyError::Provider(_))` with a non-empty `Display` message
- [ ] `KeyError::Provider`'s inner type is `Box<dyn core::error::Error +
      Send + Sync + 'static>` (verified by sending across a
      `std::thread::spawn` in the test)
- [ ] `litmask/examples/hw_id_provider.rs` builds with `--features hw-id`
      and runs end-to-end on a host with a stable machine ID

---

## Task 17: `StaticProvider` (AFK)

**Implements:** §2.5.5.1, §2.5.5.2
**Blocked by:** Task 5

`StaticProvider::new(key: UnlockKey)` constructs a provider that always
returns the held key. Intended for tests; `unlock_key()` returns
`Ok(self.key.clone())` unconditionally. The clone duplicates the secret
in process memory by design; rustdoc on `StaticProvider` carries an
explicit warning: `// FOR TESTS ONLY — clones the unlock key on every
call. Production code should use EnvVar/File/HardwareId providers.`
Adds `litmask/examples/static_provider.rs` masking the Twain fixture
with a hard-coded unlock key (spec §2.12.1.5; the example itself
doubles as a "do not do this in production" cautionary fixture).

### Acceptance Criteria

- [ ] `StaticProvider::new(k).unlock_key()` returns `Ok(k')` with `k' == k`
- [ ] Successive calls return identical keys
- [ ] `init_with(StaticProvider::new(k))` succeeds when `k` matches the
      build's `unlock_key`
- [ ] Rustdoc on `StaticProvider` contains the FOR-TESTS-ONLY warning
      (verified by a doctest that intentionally references the warning
      text, or by `cargo doc` inspection in CI)
- [ ] `litmask/examples/static_provider.rs` builds and runs end-to-end

---

## Task 18: AES-256-GCM cipher feature (AFK)

**Implements:** §1.5.1, §2.7.1, §2.7.9, §1.7.3 (cipher id branch)
**Blocked by:** Task 5

`aes-gcm` Cargo feature replaces ChaCha20-Poly1305 in the `litmask`
runtime crate and `litmask-build` via `#[cfg]` selection. Exactly one
cipher is compiled per `litmask` runtime build (this is the property
that ships in user binaries). Cipher id byte in the wrapper becomes
`0x02` when the feature is enabled. **`litmask-cli` is the deliberate
exception** per the spec amendment in the intro: the CLI compiles BOTH
ciphers and runtime-dispatches based on the wrapper's cipher-id byte,
so a single `cargo install litmask-cli` works against binaries built
with either cipher.

### Acceptance Criteria

- [ ] `cargo build -p litmask --features aes-gcm` succeeds and the
      resulting binary uses AES-256-GCM
- [ ] `cargo build -p litmask` (default) uses ChaCha20-Poly1305
- [ ] Wrapper cipher id is `0x02` under `--features aes-gcm`, `0x01`
      otherwise
- [ ] Strings check still passes under `--features aes-gcm`
- [ ] `cargo tree -p litmask --features aes-gcm` does NOT show
      `chacha20poly1305` (single-cipher property holds for runtime crate)
- [ ] `cargo tree -p litmask-cli` shows BOTH `chacha20poly1305` and
      `aes-gcm` regardless of feature flags (CLI runtime-dispatches)
- [ ] GIVEN a default-cipher-built `litmask-cli`, WHEN running
      `litmask-cli inspect` against a binary built `--features aes-gcm`,
      THEN the cipher-id byte `0x02` is detected and the inspect succeeds
- [ ] GIVEN a default-cipher-built `litmask-cli`, WHEN running
      `litmask-cli bind` against an `--features aes-gcm` binary, THEN
      the rebind succeeds end-to-end

---

## Task 19: Reproducible build seeding (AFK)

**Implements:** §2.1.1.8, §2.4.1.2–§2.4.1.5, §2.4.1.9, §2.4.1.11, §1.3.2,
§1.3.3
**Blocked by:** Task 5

`litmask-build::emit()` honors profile-dependent seed sourcing per §1.3.2.
Debug: `LITMASK_RNG_SEED` env → `target/litmask-seed` file → fresh +
persist. Release: `LITMASK_RNG_SEED` env → fresh, no persistence,
emit `cargo:warning=` directives printing the seed for reproducibility
capture. Emits only the Cargo directives listed in §2.4.1.9
(`cargo:rerun-if-env-changed=LITMASK_RNG_SEED`,
`cargo:rerun-if-changed=build.rs`, plus release-only warning when
fresh). Writes a deployer-facing comment block at the top of
`litmask.config`.

### Acceptance Criteria

- [ ] GIVEN identical source + toolchain + deps + `LITMASK_RNG_SEED`,
      WHEN building twice, THEN the per-string ciphertext bytes are
      byte-identical
- [ ] In debug profile without env var, second build reuses
      `target/litmask-seed`
- [ ] In release profile without env var, fresh seed each build and
      seed value is printed via `cargo:warning=`
- [ ] No `cargo:rustc-env=LITMASK_*` directive ever emitted (grep test on
      build script output)
- [ ] `litmask.config` first lines are a `#`-prefixed comment block
      describing purpose and warning the file is secret

---

## Task 20: `InitError::sysexit_code()` mapping (AFK)

**Implements:** §2.6.2.1, §2.6.2.2, §1.9.7
**Blocked by:** Task 8

`InitError` gains `pub fn sysexit_code(&self) -> i32` returning the
sysexits.h-compatible exit code per the §1.9.7 mapping. Numeric constants
are inline literals — no external crate dependency.

### Acceptance Criteria

- [ ] `InitError::KeyProvider(KeyError::NotFound).sysexit_code()` == 78
- [ ] `InitError::KeyProvider(KeyError::Permission).sysexit_code()` == 77
- [ ] `InitError::KeyProvider(KeyError::InvalidFormat).sysexit_code()` == 65
- [ ] `InitError::KeyProvider(KeyError::Provider(_)).sysexit_code()` == 69
- [ ] `InitError::Decryption.sysexit_code()` == 65
- [ ] `InitError::UnsupportedFormat.sysexit_code()` == 70
- [ ] `InitError::UnsupportedCipher.sysexit_code()` == 70
- [ ] `cargo tree` shows no `sysexits` crate dependency

---

## Task 21: Init error variants — UnsupportedFormat / UnsupportedCipher (AFK)

**Implements:** §1.9.2 (UnsupportedFormat, UnsupportedCipher), §1.12.2
**Blocked by:** Task 18

`init()` checks the wrapper's format-version byte (must be `0x01`) and
cipher-id byte (must match the runtime-compiled cipher) before
attempting decryption, returning `InitError::UnsupportedFormat` or
`InitError::UnsupportedCipher` on mismatch.

### Acceptance Criteria

- [ ] GIVEN a fabricated wrapper with format byte `0x99`, WHEN `init()`,
      THEN returns `Err(InitError::UnsupportedFormat)`
- [ ] GIVEN a wrapper with cipher id `0x02` and runtime built without
      `aes-gcm`, WHEN `init()`, THEN returns
      `Err(InitError::UnsupportedCipher)`
- [ ] Format/cipher checks happen before AEAD decryption (so a tampered
      cipher-id byte does not surface as `Decryption`)
- [ ] Matching format + cipher continues to succeed

---

## Task 22: `Display` tag strings for `InitError` / `KeyError` (AFK)

**Implements:** §1.9.3
**Blocked by:** Task 20

`Display` impls produce short ASCII `category:variant` tags only — no
English explanations. Tags align with the examples in §1.9.3.

### Acceptance Criteria

- [ ] `format!("{}", InitError::KeyProvider(KeyError::NotFound))` ==
      `"key_provider:not_found"`
- [ ] `format!("{}", InitError::KeyProvider(KeyError::Permission))` ==
      `"key_provider:permission"`
- [ ] `format!("{}", InitError::Decryption)` == `"decryption_failed"`
- [ ] `format!("{}", InitError::UnsupportedFormat)` == `"unsupported_format"`
- [ ] `format!("{}", InitError::UnsupportedCipher)` == `"unsupported_cipher"`
- [ ] No English tag strings (e.g., "the key was not found") appear in
      Display output

---

## Task 23: `no_std` cross-target verification (AFK)

**Implements:** §2.10.1–§2.10.6
**Blocked by:** Task 15, Task 17

Walking-skeleton runtime is already `#![no_std]` + `alloc` (Task 5);
this task verifies the property holds across an embedded target after
all providers have landed and adds the explicit cross-build to CI.
`rust-toolchain.toml` adds `thumbv7m-none-eabi` to `targets`. Justfile
gains `check-no-std` recipe (`cargo check --target thumbv7m-none-eabi
--no-default-features` for the `litmask` crate). `just ci` invokes it.
Confirms `OnceLock`-equivalent on `no_std` uses `once_cell::race::OnceBox`,
`EnvVarProvider`/`FileProvider` are gated behind `std`, `StaticProvider`
and `HardwareIdProvider` (with `hw-id`) remain available, `core::error::Error`
impls are unconditional, and `std::error::Error` impls are gated behind
`std`.

### Acceptance Criteria

- [ ] `cargo check --target thumbv7m-none-eabi -p litmask --no-default-features`
      succeeds via `just check-no-std`
- [ ] `cargo build -p litmask --no-default-features --features alloc`
      succeeds (host)
- [ ] `cargo build -p litmask --no-default-features --features alloc,hw-id`
      succeeds (host)
- [ ] `EnvVarProvider` and `FileProvider` symbols absent from the
      `litmask` crate API under `--no-default-features` (verified via
      `cargo public-api` or doc inspection)
- [ ] `StaticProvider` and (with `hw-id`) `HardwareIdProvider` remain
      callable under `--no-default-features --features alloc`
- [ ] `core::error::Error` impl present on `InitError` and `KeyError`
      under `--no-default-features --features alloc`
- [ ] `just ci` runs `check-no-std` and passes

---

## Task 24: `litmask-cli inspect` (AFK)

**Implements:** §2.9.2.1–§2.9.2.3
**Blocked by:** Task 5

`litmask-cli inspect <binary> --config <litmask.config>` scans the binary
for occurrences of the locator (12 bytes) recorded in the config and
exits with the appropriate sysexits code. Does not modify any file.
The `toml` crate is added as a `litmask-cli` dependency with an exact
version pin (`toml = "=0.8.x"` — pin the current minor at task time;
caret ranges have produced breaking surprises historically) so config
parsing behavior cannot drift from a transitive update.

### Acceptance Criteria

- [ ] Single match → exit 0, prints `verified`
- [ ] Multiple matches → exit 65, prints `ambiguous:<count>`
- [ ] No match → exit 66, prints `not_found`
- [ ] Binary file unchanged after invocation (mtime / sha256 match)
- [ ] Argument parsing errors → exit 64
- [ ] `Cargo.toml` for `litmask-cli` pins `toml` at an exact version

---

## Task 25: `litmask-cli bind` — POSIX atomic commit (AFK)

**Implements:** §2.9.1.1–§2.9.1.5 (POSIX), §1.7.6, §1.7.7 (POSIX), §1.7.1
**Blocked by:** Task 24, Task 16

`litmask-cli bind <binary> --config <litmask.config> [--salt <BASE64URL>]`
rebinds a binary to a hardware-derived `unlock_key`: locates the wrapper
via the locator, decrypts with current `unlock_key`, derives new
`unlock_key` from the host's machine ID (BLAKE3-keyed-hash with optional
salt), re-encrypts `mask_key`, and atomically commits both binary patch
and config update via the §1.7.7 POSIX protocol (tempfile in same dir,
fsync, in-place binary patch, fsync, rename, parent-dir fsync). Exit
codes per §2.9.1.3.

### Acceptance Criteria

- [ ] GIVEN a freshly built binary + config and a host with a stable
      machine ID, WHEN `bind` runs, THEN exit 0 and the bound binary
      executes correctly with the new key (no env var needed if provider
      is `HardwareIdProvider`)
- [ ] Multiple locator matches → exit 65, output `ambiguous`
- [ ] No locator match → exit 66, output `not_found`
- [ ] Wrong current `unlock_key` (forced by hand-edited config) → exit 65,
      output `decryption_failed`
- [ ] On a host where `machine-uid` fails → exit 69, output
      `hardware_id_unavailable`
- [ ] Failure injected before in-place write leaves binary AND config
      byte-identical to pre-bind state
- [ ] Failure injected after binary write but before rename leaves
      original config intact (so retry is safe)
- [ ] Parent-directory fsync is performed on POSIX (verified via strace
      or instrumented test)

---

## Task 26: `litmask-cli bind` — Windows atomic commit (HITL)

**Implements:** §2.9.1.1–§2.9.1.5 (Windows), §1.7.7 (Windows)
**Blocked by:** Task 25

Windows code path uses `MoveFileExW` with
`MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH` flags for atomic
config replacement; no separate directory fsync needed. Same exit-code
semantics as the POSIX path. Requires Windows host or VM for
verification.

### Acceptance Criteria

- [ ] On Windows, full bind cycle on a freshly built binary succeeds
- [ ] Failure injected before write leaves binary + config unchanged
- [ ] `MoveFileExW` flags used (verified by code inspection or
      Procmon trace)
- [ ] Exit codes match POSIX behavior

---

## Task 27: Coverage + semver-checks tooling (AFK)

**Implements:** infra
**Blocked by:** Task 5

Add `cargo-llvm-cov` and `cargo-semver-checks` to `.tool-versions` and
`shell.nix`, plus the CI tooling install step. Justfile recipes:
`coverage` (HTML report), `coverage-text`, `coverage-lcov`,
`semver-check`. Wire `coverage-text` into `just ci` (best-effort: tolerate
non-zero coverage thresholds pre-1.0). Wire `semver-check` into a
separate CI job (continue-on-error pre-1.0 since baseline may not
exist).

This task also adds **feature-matrix and cross-compile coverage** to
`just ci` so combinatorial drift across `{default, --features aes-gcm}
× {default, --features hw-id} × {std, no-default-features + alloc}`
cannot rot silently. New justfile recipes mirror relentless's pattern:
`test-no-default` (`--no-default-features --features alloc`),
`test-all-features`, `test-aes-gcm`, `test-hw-id` (only on hosts with a
stable machine ID — gracefully skip on others), and `check-cross`
which runs `cargo check --target <T>` for two cross targets:
`x86_64-pc-windows-gnu` (host-Linux build proves Windows codegen path
of `litmask` runtime + `litmask-cli`) and `aarch64-apple-darwin`
(host-Linux build proves macOS codegen path). Cross targets are added
to `rust-toolchain.toml`. `just ci` chains all new recipes so a single
local invocation matches CI behavior.

### Acceptance Criteria

- [ ] `just coverage` produces `target/llvm-cov/html/index.html`
- [ ] `just coverage-lcov` produces `target/llvm-cov/lcov.info`
- [ ] `just semver-check` runs `cargo semver-checks check-release`
- [ ] CI canonical-gate runs `coverage-text` (best-effort)
- [ ] CI has a separate semver-check job (continue-on-error pre-1.0)
- [ ] `just test-no-default`, `just test-all-features`, `just test-aes-gcm`
      all exit 0
- [ ] `just check-cross` exits 0 for both `x86_64-pc-windows-gnu` and
      `aarch64-apple-darwin`
- [ ] `just ci` chains the matrix recipes and remains green

---

## Task 28: Fuzz targets (AFK)

**Implements:** §2.12.1.6, §1.10.4
**Blocked by:** Task 10, Task 24 — `parse_format_template` only needs
the parser introduced in Task 10; named-args (Task 11) extend behavior
but do not alter the input domain

Add `cargo-fuzz` to `.tool-versions`, `shell.nix`, and CI tooling. Create
`litmask/fuzz/` with two fuzz targets: `parse_format_template` (the
`maskfmt!` parser) and `locator_scan` (the CLI scanner). Seed corpora
committed under `litmask/fuzz/corpus/<target>/`. CI runs each for ≥10s
per PR and uploads any new crashes as artifacts.

### Acceptance Criteria

- [ ] `cargo fuzz list` shows both targets
- [ ] `cargo fuzz run parse_format_template -- -max_total_time=10` exits
      cleanly on a fresh checkout
- [ ] `cargo fuzz run locator_scan -- -max_total_time=10` exits cleanly
- [ ] CI executes both targets per PR with the 10s budget
- [ ] Seed corpora are versioned in git

---

## Task 29: Platform CI matrix — POSIX (AFK)

**Implements:** §2.13.1.1–§2.13.1.3, §2.13.2.1–§2.13.2.6, §1.10.5
(Ubuntu / AlmaLinux / macOS / FreeBSD / OpenBSD)
**Blocked by:** Task 25, Task 4

New workflow `.github/workflows/platform-matrix.yml` runs the per-platform
smoke test sequence on each platform in §1.10.5. AlmaLinux as Docker job;
FreeBSD/OpenBSD via `cross-platform-actions/action`. Smoke test (shared
shell script under `scripts/platform-smoke.sh`): build a test binary
with at least one high-entropy UUID-formatted marker via `mask!`, run
`strings` pre- and post-bind asserting marker absent, run `bind` and
expect success on platforms with stable machine ID, expect EX_UNAVAILABLE
(69) on stock OpenBSD per §2.13.2.4, perform rebind cycle (skipped on
OpenBSD failure path).

### Acceptance Criteria

- [ ] Workflow runs on Ubuntu, AlmaLinux, macOS, FreeBSD, OpenBSD
- [ ] All five jobs green on a clean PR
- [ ] OpenBSD asserts the EX_UNAVAILABLE failure mode (not treating it
      as a test failure)
- [ ] `strings` post-bind shows no marker on any platform
- [ ] Rebind cycle (bind → run → bind with different salt → run) green on
      stable-ID platforms
- [ ] Failure of any matrix job blocks PR merge

---

## Task 30: Platform CI — Windows (HITL)

**Implements:** §1.10.5 (Windows), §2.13.2.x for Windows
**Blocked by:** Task 26, Task 29

Windows job added to platform-matrix workflow on `windows-latest`. Same
smoke sequence, accounting for `MachineGuid` registry lookup and NTFS
atomic-rename behavior.

### Acceptance Criteria

- [ ] Windows job runs the smoke script (PowerShell or bash via
      `shell: bash`) and exits 0
- [ ] Strings check passes (uses `findstr` or built `strings.exe`)
- [ ] Bind + rebind cycle succeeds on Windows runner

---

## Task 31: Documentation — README + crate rustdoc (AFK)

**Implements:** §2.11.1, §2.11.2, §2.11.5, §2.11.7, §1.11.1 (README +
lib.rs rows), §1.1.6, §1.1.4
**Blocked by:** Task 18, Task 20

`README.md` includes project overview, the security level table from
§1.1.4, the value-proposition table from §1.1.6, a prominent
"What `litmask` does NOT protect against" section, and a quick-start
example. `lib.rs` crate-level rustdoc mirrors README's API overview and
includes both tables. Every public API item carries rustdoc with at least
one usage example. Tone respects §1.11.3 (understatement of guarantees;
no claims against out-of-scope attacker capabilities).

### Acceptance Criteria

- [ ] `README.md` contains the §1.1.4 security level table verbatim
- [ ] `README.md` contains the §1.1.6 value-proposition table verbatim
- [ ] `README.md` includes a prominently formatted "does NOT protect
      against" section
- [ ] `cargo doc --no-deps --all-features` produces docs for every public
      item without missing-docs warnings
- [ ] `cargo test --doc` passes — every public item's doctest compiles
      and runs
- [ ] `cargo test --doc --no-default-features --features alloc` also
      passes (proves doctests for the `no_std`-available API surface
      compile under that configuration)
- [ ] No documentation surface promises resistance to out-of-scope
      capabilities listed in §1.1.3

---

## Task 32: Project docs — THREAT_MODEL / DEPLOYMENT / MIGRATION / contrib / release (AFK)

**Implements:** §2.11.3, §2.11.4, §2.11.6, §1.11.1 (remaining), §1.11.2,
§1.11.3, §1.9.4
**Blocked by:** Task 26, Task 20

`THREAT_MODEL.md` documents in-scope and out-of-scope attacker
capabilities (§1.1.2 + §1.1.3) and the init-failure plaintext limitation
(§1.9.4). `DEPLOYMENT.md` includes per-`KeyProvider` operational guide,
the recommended release profile snippet (strip/debug/panic/lto) with
rationale, the rebind workflow, `litmask.config` handling, and a
sysexits.h code reference table mirroring §1.9.7. `MIGRATION.md` covers
moving from `litcrypt` (v1 and v2) and `obfstr` with side-by-side API
comparisons. `CONTRIBUTING.md` documents the dev shell + just workflow.
`AGENTS.md` and `CLAUDE.md` capture project-specific notes for AI
collaborators. Dual-license: `LICENSE-MIT` + `LICENSE-APACHE` at repo
root. `CHANGELOG.md` per Keep-a-Changelog format. Semantic-release
configured via `.releaserc.json` + `package.json` devDependencies
(`semantic-release`, `@semantic-release/changelog`,
`@semantic-release/git`). New `.github/workflows/release.yml` runs
`npx semantic-release` on `main`. `justfile` gains `release` recipe
mirroring the workflow steps.

### Acceptance Criteria

- [ ] All listed documentation files exist at repo root
- [ ] `THREAT_MODEL.md` enumerates in-scope levels 1–3 and out-of-scope
      level 4 + the §1.1.3 list, plus the §1.9.4 init-failure caveat
- [ ] `DEPLOYMENT.md` includes the release-profile TOML snippet and the
      sysexits.h reference table
- [ ] `MIGRATION.md` has side-by-side code blocks for `litcrypt` v1,
      `litcrypt2`, and `obfstr`
- [ ] `CONTRIBUTING.md` walks a new contributor through `nix-shell` →
      `just setup` → `just ci`
- [ ] `LICENSE-MIT` and `LICENSE-APACHE` present and referenced in
      `Cargo.toml` `license = "MIT OR Apache-2.0"`
- [ ] Tagging a Conventional-Commits-driven semantic version on `main`
      produces a GitHub Release via the release workflow
- [ ] `just release` recipe documented in `--list` output

---

## Task 33: Pre-1.0 security review (HITL)

**Implements:** CLAUDE.md step 6 (security review); gates v1.0 release
**Blocked by:** Task 32

Final audit pass before tagging v1.0. Goes beyond the per-feature
acceptance criteria to look for cross-cutting failures and threat-model
drift. HITL because findings drive judgment calls (defer to v2 vs.
fix-now vs. document-and-ship). Output is a checklist file at
`docs/SECURITY_AUDIT.md` with each finding categorized as
blocker / fix-before-1.0 / track-for-v2 / accepted-risk.

Audit surface:

- **Strings hygiene.** Build every example + integration binary across
  the full feature matrix (cipher × hw-id × std). Run `strings` on each
  and grep for: `litmask`, `mask_key`, `unlock_key`, `decrypt`, `cipher`,
  `chacha`, `aes`, `tamper`, `nonce`, common variant names from
  `InitError` / `KeyError`. Flag any litmask-identifying or operation-describing
  plaintext.
- **Panic hygiene grep.** Search the runtime decryption path for
  `.expect(`, `panic!("`, `unwrap_or_else(|_| panic!`, `unreachable!("`,
  any custom panic message. Any hit is a §1.9.5 violation.
- **Key zeroization at boundaries.** Audit every place `UnlockKey` and
  `MaskKey` are constructed, cloned, or moved. Confirm `Drop` runs and
  no copies escape into long-lived buffers (e.g., String formatting,
  log lines, error variants, file-content buffers from `FileProvider`).
- **Threat-model claim verification.** Read `THREAT_MODEL.md`,
  `README.md`, `DEPLOYMENT.md`, crate rustdoc; flag any claim of
  resistance against §1.1.3 out-of-scope capabilities. Verify the
  "deliberate understatement" tone of §1.1.5 holds.
- **Dependency surface review.** `cargo tree --all-features` audit:
  unexpected transitive deps, deps with poor security track record,
  deps that pull in `unsafe` not justified by the use case. Cross-check
  `deny.toml` allowlist.
- **Timing surface (informational).** Note any non-constant-time
  comparison in security-sensitive paths. v1 explicitly excludes
  side-channel attacks (§1.1.3) but document for users who care.
- **Bind atomicity dry-run.** Walk through §1.7.7 protocol manually
  (POSIX + Windows), verify implementation matches step-for-step.
  Inject failures via `LD_PRELOAD` (POSIX) / Detours-equivalent
  (Windows) at each step; confirm recovery state matches §1.7.7
  documentation.
- **Reproducibility verification.** Build twice with same
  `LITMASK_RNG_SEED` on two different machines (or two clean checkouts
  on same machine) and confirm byte-identical artifacts under §1.3.3
  conditions.
- **Format-version + cipher-id rejection paths.** Manually fabricate
  wrappers with bad version / bad cipher-id / truncated length; confirm
  `init()` rejects with the right `InitError` variant in each case.

### Acceptance Criteria

- [ ] `docs/SECURITY_AUDIT.md` exists with all surface items addressed
      and categorized
- [ ] Zero findings in the `blocker` category
- [ ] All `fix-before-1.0` findings have linked PRs that land before tag
- [ ] `track-for-v2` findings are filed as GitHub issues with the
      `v2-candidate` label
- [ ] `accepted-risk` findings each have a one-paragraph justification
      referencing the relevant `SPECIFICATION.md` section
- [ ] Strings-hygiene grep passes on all example + integration binaries
      across the full feature matrix
- [ ] Panic-hygiene grep returns zero hits in the runtime decryption path
- [ ] Reproducibility cross-machine check produces byte-identical
      artifacts

---

## Task 34: Dedicated masked-include + masked-env macros (AFK)

**Implements:** spec amendment forthcoming
**Blocked by:** Task 13

Macro expansion rules mean a macro doesn't actually expand inside
another macro's arguments — `mask!(include_str!("p"))` works today
only because `mask!`'s parser has a hand-rolled shim that reads the
file at proc-macro time. The shim is one-off and asymmetric: it
covers `include_str!` and `concat!` but not `include_bytes!`,
`env!`, or `option_env!`, leaving `mask_all` to special-case some
families and leave others unhandled (a `UserDefined` warning).

Introduce four new public macros that fold the file-read / env-var
lookup AND the encryption into a single proc-macro pass:

- `include_masked_str!("path")` → `String`
- `include_masked_bytes!("path")` → `Vec<u8>`
- `env_masked!("VAR")` → `String` (panics at proc-macro time if the
  env var isn't set, matching `env!`'s contract)
- `option_env_masked!("VAR")` → `Option<String>`

`#[mask_all]` rewrites the un-masked stdlib forms to the dedicated
masked counterparts:

- `include_str!(...)` → `include_masked_str!(...)`
- `include_bytes!(...)` → `include_masked_bytes!(...)`
- `env!(...)` → `env_masked!(...)`
- `option_env!(...)` → `option_env_masked!(...)`

Drop the `mask!(include_str!(...))` / `mask!(concat!(...))` shim
from `litmask-macros/src/mask.rs` once the dedicated path covers it
(deprecate the shim with a doc-note in the intermediate release;
remove in the breaking-change cycle).

### Acceptance Criteria

- [ ] `include_masked_str!("relative.txt")` returns the file's
      contents as `String`; file contents absent from binary plaintext
- [ ] `include_masked_bytes!("relative.bin")` returns the file's
      contents as `Vec<u8>`; bytes absent from binary plaintext
- [ ] `env_masked!("FOO")` returns the env-var value as `String` at
      runtime; value absent from binary plaintext; missing env var
      panics at proc-macro time with the same message style as `env!`
- [ ] `option_env_masked!("FOO")` returns `None` when the env var is
      unset at build time, `Some(masked_value)` otherwise
- [ ] `#[mask_all]` rewrites the four stdlib forms above; round-trip
      tests cover each
- [ ] Doc notes on `mask!`'s `include_str!` / `concat!` shim point
      users at the new macros and announce the deprecation horizon
