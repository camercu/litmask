# litmask Developer-Experience — Specification (Variant A: Operator-Owned Key)

> **Status:** design variant, refine phase. Companion comparison to
> `docs/SPEC_DEVEX.md` (the "build-generated key" design). This variant
> **inverts key ownership** — the choice `SPEC_DEVEX.md` lists under
> "Explicitly rejected (do not re-litigate)". It is drafted here for a
> deliberate side-by-side decision, not to silently override that spec. If
> adopted, this replaces `SPEC_DEVEX.md`; if not, it is the documented record
> of why inversion was reconsidered and where it lands.

## Summary

The friction surface `SPEC_DEVEX.md` enumerates (F1–F7) and the leak it found
(S1) all trace to **one decision**: the build *generates* the `unlock_key` and a
human must then *discover* and *re-inject* it at runtime. Every pain is a symptom
of a secret crossing the build → human → runtime boundary by hand; the leak (S1)
is that boundary spilling the secret into shared logs.

This variant removes the boundary instead of mitigating it. **The `unlock_key`
becomes an operator-owned input**, supplied at build time (to seal the
`mask_key` into the wrapper) and at run time (to unseal it, via the unchanged
`KeyProvider`). The build generates *nothing the human must chase*.

What this collapses, by removal rather than tooling:

- **F1 (opaque death):** the dev loop self-decrypts via a debug constant (§3); a
  release miss is diagnosed (§4), not the only path.
- **F2 (awk ritual) / F6 (key-wire helper):** gone — the operator already holds
  the key; nothing is extracted.
- **F3 (silent rotation):** gone for runtime decryptability — an owned key never
  rotates under the developer; only the internal seed (blobs) varies, invisibly.
- **F4 (config clobber):** moot — `litmask-meta.toml` loses its secret and becomes
  committable metadata (§7).
- **F5 (hand-rolled seed/key):** `litmask keygen` mints provisioning keys with
  correct encoding (§6.1); seed minting demotes to the rare bit-repro case (§8).
- **F7 (inspect false-pass):** addressed by `verify` (§4) checking decrypt-success
  by default with the *owned* key over a non-argv channel (§5); the weak
  locator-only check is now an explicit opt-in, so the false-pass is unreachable by
  accident.
- **S1 (seed in logs):** the `unlock_key` leak is gone by removal — the build no
  longer generates or prints it. **But the observed S1 leak was the *seed*, not the
  `unlock_key`** (`cargo:warning=…LITMASK_RNG_SEED=<seed>`), and the seed is **still
  fresh-generated** every release for per-build-unique blobs (A.2). So S1 is **not**
  gone for free: §8.5 drops the fresh-seed warning entirely (under owned keys nobody
  needs to capture the seed for normal repro).

**What is preserved unchanged.** The masking promise (plaintext absent from the
binary), per-build-unique blobs (the internal seed still randomizes `mask_key`),
the wrapper **wire format**, the `KeyProvider` model, the `mask!*` macro surface,
and the zero-identifying-strings release scrub. The change is concentrated in
`litmask_build::emit()` and the CLI; the **runtime and binary wire format barely
move**, so a binary built under this variant is byte-compatible with existing
tooling at the wrapper level.

**The governing tradeoff (stated, not hidden).** `SPEC_DEVEX.md` keeps an
*independence-by-construction* guarantee: the build mints a fresh `unlock_key`
per build, so keys *cannot* be reused across builds. This variant gives that up —
an operator *could* paste one key across customers. It is recovered at the
**provisioning layer** instead of the binary layer (§6.1 `keygen` per customer →
distinct keys by default), which makes the secure path the lazy path but does not
make reuse impossible. This is the deliberate cost of removing F1–F7/S1; it is
defensible because (a) the old guarantee only prevented key *reuse*, never
governed key *storage* — always operator discipline — and (b) operator-supplied-
from-vault has a *smaller* secret-egress surface than generate-into-config-then-
`awk`, the very pattern that produced S1.

## Audience & Mode Model

- **Developer / operator loop** — iterate, run examples/tests, ship per-customer
  builds. Debug builds seal under a fixed **non-secret** dev constant `K_dev`, so
  `cargo run` / `cargo test` decrypt with zero wiring. Consequence (unchanged from
  the other design): a **debug build is self-decrypting and must never be
  distributed** — but here the dev key is a public constant, not a baked
  per-build secret, so no key-baking machinery is required.
- **Production** — CI builds release supplying the operator's per-customer
  `unlock_key` from a secret store; the same value reaches the runtime provider
  out-of-band. The attacker holds **the shipped binary only**; the release binary
  is mute and free of litmask-identifying strings.

## Foundation (what changes vs the build-generated design)

- **A.1 (inverted):** the `unlock_key` is an **operator-supplied input**, not a
  build output. The build seals `mask_key` under the supplied key. Independence
  across builds is no longer by construction; it is a provisioning practice
  (§6.1).
- **A.2 (unchanged):** a per-build seed deterministically derives `mask_key` and
  build-time nonces. Fresh seed ⇒ per-build-unique blobs; pinned seed ⇒
  reproducible blob bytes. The seed remains sensitive (it derives `mask_key`,
  which decrypts blobs directly) but is **no longer required for normal
  operation** — runtime decryptability depends only on the owned `unlock_key`.
  Because it stays a master secret, the fresh-seed build warning that leaks it
  (observed S1) is removed under this variant (§8.5).
- **A.3 (unchanged):** `unlock_key` is never embedded in a **release** binary;
  only the wrapper is. Debug seals under the public constant `K_dev`.
- **A.4 (unchanged):** release runtime failure paths stay mute (bare `panic!()` /
  `Err(Decryption)`, no identifying text).

## 1. Key Ownership Model (inversion)

- **1.1**: `litmask_build::emit()` obtains the `unlock_key` from a build-time
  environment variable (default `LITMASK_UNLOCK_KEY`), validates it (base64url, exactly
  32 bytes), and seals the freshly-derived `mask_key` into the wrapper under it.
  The key is **never generated** by the build and **never written back** to any
  artifact.
- **1.1.1 (default name matches the runtime — normative)**: The build's default key
  variable is `LITMASK_UNLOCK_KEY`, **the same name** the runtime `EnvVarProvider`
  default reads (`litmask/src/provider/env.rs`). This is load-bearing: a binary built
  under the default and run under the default decrypts with **one** secret-store
  entry and no name translation. The build, `verify` (§5.1), and the runtime provider
  MUST share this default; a divergence (e.g. build `LITMASK_KEY` vs runtime
  `LITMASK_UNLOCK_KEY`) silently produces a `NotFound` at runtime for every default
  user and is a spec violation.
- **1.1.2 (input normalization — normative)**: Every key channel (env, `--key-file`,
  `--key-stdin`, and the build var) **trims surrounding ASCII whitespace** — notably a
  trailing newline — before base64url-decoding, so `echo "$KEY" > file` and
  `printf %s` both work. The length/encoding validation (§1.1) runs on the trimmed
  value.
- **1.2**: The build-time key variable name is configurable to match a renamed
  runtime provider, via an optional builder
  (`litmask_build::Emit::new().key_var("CRYPTIO_KEY").run()`), paired with
  `EnvVarProvider::new("CRYPTIO_KEY")` at runtime. The default bare `emit()` reads
  `LITMASK_UNLOCK_KEY` (§1.1.1); a custom name must be set on **both** sides or the
  runtime `NotFound`s.
- **1.3**: A malformed build-time key reports the required encoding (base64url),
  the required length (32 bytes), and points at `litmask keygen` (§6.1).
  (Build-time developer input — not subject to the runtime message-hygiene rule.)

## 2. Build-time key absence policy

- **2.1 (fail-safe polarity, normative)**: The `K_dev` debug path fires **only
  when `PROFILE == "debug"` exactly**. Every other value — `"release"`, any custom
  profile (`[profile.dist]` inheriting release), or an unset/unexpected `PROFILE` —
  is treated as **release behavior**: a missing build-time key is a **hard build
  error** naming the expected variable and pointing at `litmask keygen`, and no
  `K_dev` is sealed or compiled in (§3.4, §9.2). This polarity is the inverse of
  the seed-persistence default, which conservatively treats unknown profiles as
  Debug (litmask-build's current `Profile::from_env`); the two concerns share the
  `PROFILE` value but **must not share the default** — persistence may fail toward
  Debug, the security gate **must** fail toward Release. A consumer using a custom
  release-derived profile must therefore never silently get a self-decrypting,
  signature-bearing binary.
- **2.1.1 (custom debug-derived profiles lose zero-wiring — accepted papercut)**:
  The flip side of §2.1's strict `== "debug"` test is that a **custom profile
  inheriting `dev`** (whose `PROFILE` is not the literal `"debug"`) is also treated as
  release: it gets the hard "missing key" build error and no `K_dev`. This is a
  usability papercut, not a security defect (it fails *safe*). Documentation states
  the consequence: iterate under the literal `dev`/`test` profiles to keep
  zero-wiring, or supply a key for the custom profile. Cargo only guarantees
  `PROFILE ∈ {"debug","release"}` for the built-in profiles, which is exactly why the
  gate keys on `"debug"` and treats everything else as release.
- **2.2**: In a **debug** build (`PROFILE == "debug"`), a missing build-time key
  falls back to the per-crate `K_dev` (§3.3) so the dev loop needs no
  provisioning. The fallback is announced once at build time (debug-only,
  non-secret) so the developer knows the binary is self-decrypting.

## 3. Debug zero-wiring

- **3.1**: A debug build sealed under `K_dev` is decryptable by the runtime
  without any provider configuration: the debug runtime's resolution is "use the
  configured provider; if it reports the key **absent** (`KeyError::NotFound`),
  use `K_dev`." `cargo run` and `cargo test` therefore decrypt with **zero key
  wiring** (eliminates the dev-loop halves of F1/F2/F6).
- **3.2 (fallback trigger — structural, normative)**: The `K_dev` fallback fires
  **only** on `KeyError::NotFound`, because it sits at the key-retrieval layer
  (before decryption) and can only observe found/not-found. A key that is present
  but wrong (stale env, unbound `MachineIdProvider`) flows through unchanged and is
  surfaced by §4 — not masked. Consequence (doc): a dev with a **stale
  `LITMASK_UNLOCK_KEY` exported in their shell** gets the §4.3 wrong-key diagnostic,
  not zero-wiring — the fix is to `unset` it; the fallback deliberately does not
  override an explicit-but-wrong key.
- **3.3 (per-crate `K_dev`, normative)**: `K_dev` is **not a global constant** —
  it is derived per consumer crate, `K_dev = KDF(crate-identity ‖ a fixed
  litmask domain salt)` (e.g. `CARGO_PKG_NAME` + version, available to `emit()`),
  so it is **not the same value across litmask users**. Rationale: a single
  constant compiled into the published `litmask` crate would be a **global
  skeleton key** — one value, readable from crates.io, that decrypts *every*
  accidentally-shipped debug build from *every* litmask consumer. Per-crate
  derivation bounds the blast radius of an accidentally-distributed debug build to
  that one project and forces an attacker to derive the project's key rather than
  read a published constant. `K_dev` is still **non-secret by design** (it is the
  price of zero-wiring); per-crate derivation is blast-radius reduction, not
  secrecy. It carries no per-build secret, so there is **no cross-crate key-baking
  and no emit-time secret gate** — the debug/release decision is the single
  fail-safe `PROFILE` gate (§2.1).
- **3.3.1 (`K_dev` reaches the runtime, debug-only — normative)**: The runtime
  fallback needs `K_dev`, so it must travel build → runtime. Because `K_dev` derives
  from the consumer crate's identity (§3.3), both ends can recompute it from the same
  `CARGO_PKG_*` inputs **without baking the key value into the binary**: `emit()`
  derives it to seal in debug, and the runtime fallback derives it from the same
  inputs (threaded via the existing macro/`OUT_DIR` plumbing that already carries
  build outputs). "No cross-crate" (§3.3) means **no secret crosses** — a recomputed
  non-secret constant is not a secret. In release this derivation and the fallback
  branch are `cfg`-stripped entirely (§3.4/§9.3), so nothing — neither the value nor
  the code that recomputes it — survives into the shipped binary.
- **3.4 (release absence is mandatory — normative, scrub-invariant)**: A release
  binary MUST contain **zero `K_dev` bytes** — not merely an unused branch.
  Rationale: any litmask-specific constant that survives into release is a **clear
  signature** that fingerprints the binary as litmask-built, breaking the
  zero-identifying-strings scrub invariant (THREAT_MODEL.md) independently of
  whether the key is ever used. The `K_dev` value, its derivation, and the fallback
  branch are therefore `cfg`-stripped from release by the §9 `PROFILE` gate — a
  **MUST**, not the defense-in-depth "MAY" of the build-generated design. This
  fuses with §2.1: the same gate that decides "use `K_dev`" decides "compile
  `K_dev` in at all", so a misfiring gate would ship *both* a self-decrypting
  *and* a signature-bearing binary — which is exactly why the gate fails toward
  Release. The `example_scrub` harness asserts the `K_dev` value is absent from the
  release binary.
- **3.4.1 (debug distribution caveat, normative)**: A debug build carries `K_dev`
  and the ciphertext, so it is **self-decrypting** and offers no extraction
  resistance. It MUST NOT be distributed. Per-crate `K_dev` (§3.3) bounds — does
  not eliminate — the damage if one is leaked. Documented loudly (§10) and recorded
  as an accepted trust boundary (THREAT_MODEL.md). It does not weaken *deployment*
  security: release is untouched and embeds no plaintext literal.
- **3.5**: Because `K_dev` is a constant, debug builds are **bit-reproducible for
  free** when the seed is also fixed (§8.3) — a deterministic, self-decrypting dev
  loop. Release keeps fresh-seed unique blobs.
- **3.6**: A debug `cargo run` using `init_with!(MachineIdProvider::new())` is
  **not** rescued by §3.1 (the provider returns a derived key that fails to
  decrypt until bound — §3.2). Documentation states the consequence: in the dev
  loop use the default/env provider or seal under the machine key (§6.3);
  machine-id is a deployment concept, not a dev-loop one.
- **3.7 (zero-wiring masks broken provider wiring — normative caveat)**: Because the
  `K_dev` fallback fires on `NotFound` (§3.2), a debug run where the **configured
  provider itself is misconfigured** (env var unset, file path wrong) is *rescued* —
  it decrypts and looks correct, yet the real key path was never exercised. Debug
  success therefore **does not prove** the deployed provider is wired correctly (a
  dev-loop analog of F7). The authoritative test of the real key path is `verify` on
  the **release** artifact with the production key over a §5 channel (§4.4.1).
  Documentation states this so a green `cargo run` is not mistaken for a validated
  deployment.

## 4. Coherence & Failure Diagnostics

- **4.1 (`verify`, authoritative by default)**: `litmask verify` performs the
  authoritative **decrypt-success** check using the **owned** key supplied per §5.
  It is the renamed successor to `inspect`, with the default **flipped**: where the
  build-generated design defaulted to the cheap secret-free check (the key was hard
  to obtain), this variant makes the strong check the default because the owned key
  is trivially suppliable via env. In its keyed mode `verify` reports **four** outcomes
  via four distinct exit codes:
  - *coherent* — locator present **and** key decrypts;
  - *locator-absent* — no matching locator in the binary (wrong metadata for this
    binary);
  - *key-fails* — locator present but the supplied key does **not** decrypt;
  - *indeterminate* — locator present, decrypt not checkable (e.g. machine-id off-box
    without `--machine-id`/`--salt`, §4.4).

  *locator-absent* and *key-fails* are **separate** outcomes (a CI script must tell
  "wrong binary/metadata" from "wrong key"). *Indeterminate* MUST NOT collapse into
  *coherent*.
- **4.1.1 (`--locator-only`, opt-in keyless check)**: `litmask verify --locator-only`
  performs the **secret-free locator-presence** check and never loads a key — for
  contexts that lack the owned key (third-party wrapper verification, a keyless
  "did litmask wire in at all" smoke test, a build stage not trusted with the
  runtime secret). It reports only the presence outcomes (`EX_OK` match /
  `EX_DATAERR` ambiguous / `EX_NOINPUT` absent) — it cannot reach *coherent* or
  *key-fails* because it never tests a key.
- **4.1.2 (no-key default is an error, not a silent weak pass — normative)**: Running
  `verify` **without** a key source — no §5 key **and** no `--machine-id`/`--salt`
  derivation path (§4.4) — and **without** `--locator-only` is a **usage error**
  ("supply a key via §5, pass --machine-id, or pass --locator-only"), NOT a silent
  fall-through to the locator-only check. This is what kills **F7 by construction**:
  the false-pass (locator present, key untested, reported as success) is no longer
  reachable by accident — an operator must *explicitly* ask for the weak check.
- **4.1.3 (exit-code namespace, normative)**: The four keyed outcomes carry **four
  distinct** exit codes, and they MUST be disambiguable from the `--locator-only`
  presence codes (`EX_OK` / `EX_DATAERR` / `EX_NOINPUT`). A natural assignment reuses
  `sysexits` consistently — coherent ⇒ `EX_OK`, locator-absent ⇒ `EX_NOINPUT`,
  key-fails ⇒ `EX_DATAERR`, indeterminate ⇒ a distinct fourth (e.g. `EX_UNAVAILABLE`)
  — so a CI script keying on the numeric code can tell "wrong binary" from "wrong key"
  from "couldn't check". A regression test pins the full code table across both modes
  to prevent silent collision.
- **4.2**: The two failure shapes carry distinct messages (F3): *locator-absent*
  reports "wrong metadata for this binary" (also the only failure `--locator-only`
  can report, secret-free); *key-fails* reports "locator present but key does not
  decrypt."
- **4.3**: In **debug** builds only, a key failure not resolved by §3.1 — a
  provider that returned a key which then fails to decrypt — names the
  **provider-specific source** the runtime tried (`EnvVarProvider::var_name()`, a
  file path) instead of a bare `explicit panic` (F1). Custom providers may
  participate via the optional `fn source_hint(&self) -> Option<&str> { None }`
  trait method (default `None`, non-breaking). Release keeps the mute abort.
- **4.4**: For a `MachineIdProvider` binary, off-box decrypt-success needs the
  machine key the CLI cannot reproduce; `verify` accepts the same
  `--machine-id`/`--salt` flags as `bind` and derives it. Without them it returns
  **indeterminate**, never *coherent*.
- **4.4.1 (verify against the runtime key, normative)**: A coherence check is only
  meaningful if it uses the **same key the runtime will use**. `verify` MUST read
  the key from the same secret-store entry that feeds the deployed provider (the CI
  example passes the identical `secrets[...]` to both the verify step and the
  runtime). Verifying against a freshly-`keygen`'d or otherwise *different* key
  proves nothing about the shipped artifact and is a false-confidence trap;
  documentation states this explicitly.
- **4.5 (bind/provider mismatch — observed, mechanism sharpened)**: `bind` re-keys
  the wrapper to a machine-derived key **and rotates the key recorded in the metadata
  file**, but cannot see the binary's compiled-in provider. The failure is **not** that
  the artifact is unconditionally broken — an `EnvVarProvider` binary still decrypts
  when given the *rotated* key via its env var (observed live). What breaks is the
  **deployment expectation** that a bound binary self-decrypts **with no env
  supplied**, which only a `MachineIdProvider` binary satisfies; an `EnvVarProvider`
  binary shipped on that expectation dies `NotFound` on the customer host. `bind`
  reports success regardless (it is blind to the provider), and `verify
  --locator-only` still passes (compounding F7 — another reason the keyed check is the
  default). `verify --machine-id` of such a binary MUST report *key-fails* (the machine
  key seals the wrapper but the runtime never consults the machine id). Documentation
  states `bind` is meaningful only for `MachineIdProvider` builds — `bind` success is
  not evidence the binary self-decrypts. Under this variant the common machine-id path
  seals under the machine key at build (§6.3), so there is usually no `bind` step to
  misapply.

## 5. Secret input channels (normative)

- **5.1**: Any CLI subcommand that consumes a secret key (`verify` in its default
  keyed mode) accepts it **only** through non-argv channels: the default
  environment variable `LITMASK_UNLOCK_KEY`, an explicit `--key-env <NAME>`, a
  `--key-file <path>`, or `--key-stdin`. **There is no `--key <value>` flag.**
- **5.2 (rationale, normative)**: A secret passed as an argv value lands in each
  process's **argument vector**, which is readable by **every user on the host** via
  plain `ps`; a process **environment** is restricted to the owner (and root) via
  `/proc/<pid>/environ` permissions, and a file/stdin secret is never exposed in the
  process table at all. Argv is also not reliably masked in CI logs (masking breaks
  under any transformation of the value), whereas CI secret stores mask registered
  env values. (Note: shell **history** is *not* a discriminator — command
  substitution like `--key $(vault read …)` keeps the literal out of history, and a
  pasted-literal `LITMASK_UNLOCK_KEY=… cmd` would land in history just as a `--key …` would;
  the real exposure is the resolved value in the *process table*, not the typed
  line.) Env/file/stdin are the acceptable channels. This is the same discipline
  `vault`, `op`, and `gh` follow.
- **5.3**: Any subcommand that *emits* a secret (`keygen`, §6.1) prints **only**
  the value to stdout with no decoration, so it pipes directly into a secret store
  without an intermediate file, and carries the egress warning of §5.2 in its docs
  (never route into shared/CI logs).
- **5.4 (build-time key injection — same discipline, not litmask-enforceable)**:
  The build reads `LITMASK_UNLOCK_KEY` from the **environment** (§1.1), not argv, so it
  obeys the same no-argv rule. But the injection happens at the *cargo* boundary
  (`LITMASK_UNLOCK_KEY=… cargo build`), which litmask does not control; litmask **cannot
  enforce** that an operator didn't write the key into a checked-in script or a
  logged command line. Documentation (§10) states the discipline — inject from a
  secret store into the build env, never inline the literal — and notes litmask can
  only *facilitate* it (env-read, `keygen`), not guarantee it.

## 6. Tooling / CLI surface

The distributable CLI is **{`verify`, `bind`, `keygen`, `machine-key`,
`show-machine-id`}**, plus an optional `seed` minter (§8). It never compiles and
has no `run` verb — building is cargo's, run-loop convenience is `just`'s.

- **6.1 (`keygen`, new)**: Mints a fresh `unlock_key` — 32 bytes from the same
  CSPRNG and base64url (no-padding) encoding `emit()` and the providers expect —
  and prints **only** the key to stdout (§5.3). It touches no binary or metadata
  file; it is a pure generator. It replaces the hand-rolled `head -c32 /dev/urandom |
  basenc` ritual (F5) and its encoding footguns (observed: stray `=` padding).
  Provisioning is one pipe per customer:
  `litmask keygen | gh secret set CRYPTIO_KEY_BOB`.
- **6.1.1 (distinctness by provisioning, normative)**: Running `keygen` once per
  customer yields **distinct keys by default** (independent CSPRNG draws;
  collision negligible). This is how this variant recovers cross-customer
  isolation — at the provisioning layer, not the binary layer (see Summary
  tradeoff). `keygen` cannot *enforce* distinctness (an operator may reuse a
  value), but it makes the distinct path the lazy path.
- **6.2 (`verify`)**: As §4; the renamed successor to `inspect`. Default mode reads
  the owned key per §5 and checks decrypt-success; `--locator-only` is the keyless
  opt-in (§4.1.1); no-key-no-flag is a usage error (§4.1.2). Provider-agnostic —
  bytes and wrapper only (no `unlock_key` in the metadata file to read).
- **6.3 (`machine-key`, new)**: `litmask machine-key --machine-id <id> --salt <s>`
  derives the machine key off-box using the **same KDF** as the runtime
  `MachineIdProvider` and `bind`, printing it per §5.3. Feeds the
  *build-under-machine-key* path so a known-ahead machine-id deployment needs **no
  `bind` step**:
  `LITMASK_UNLOCK_KEY=$(litmask machine-key --machine-id "$BOB_ID" --salt cryptio-v1) cargo build --release`.
- **6.4 (`bind`)**: Kept, **narrowed** to the residual case where the machine id
  is not known at build time. Writes its re-keyed metadata to a per-binary sidecar
  `<binary>.litmask-meta.toml` (or `--output`) and never overwrites the shared
  metadata file. No longer mutates a *secret* file (the shared file is
  non-secret under §7).
- **6.4.1 (machine-id decision tree, doc-normative)**: Documentation MUST give a
  one-branch decision for machine-id deployments: **if the target machine-id is
  known at build time**, derive the machine key off-box with `machine-key` (§6.3)
  and build under it (`LITMASK_UNLOCK_KEY=$(litmask machine-key …) cargo build`) — ship a
  **bind-free** binary, the metadata file never travels. **If the machine-id is only
  knowable on the target host**, ship a binary built under a placeholder owned key and
  `bind` on-host (§6.4) over secure transport, deleting the sidecar after. The
  build-under-key path is the documented default; `bind` is the residual case.
- **6.5 (`show-machine-id`, kept)**: Prints this host's machine ID — the exact
  bytes `MachineIdProvider` feeds into derivation. Retained unchanged: it is the
  input an operator captures from a customer host to feed `machine-key` (§6.3) or
  `bind` (§6.4), and it emits a **non-secret** identifier, so it is exempt from §5.

## 7. Metadata file isolation

- **7.1**: `litmask-meta.toml` holds **only non-secret build metadata** — the
  `locator` and `length`. It does **not** hold the `unlock_key` (the operator owns
  it). Its header reflects this (no "SECRET" warning). The name signals its nature:
  generated build *metadata*, not hand-authored *config* (there is no litmask
  project config — §1.3.4 of the build-generated design).
- **7.1.1 (attribution tell — gitignore by default)**: Although the file carries
  no *secret*, a committed `litmask-meta.toml` is an **attribution tell**: its presence
  and field names link the repository to litmask, which a source-level adversary can
  read even though the *binary* scrubs identifying strings. The build therefore
  emits a `.gitignore` entry for it by default and documentation does **not**
  recommend committing it. Committing is *permitted* (nothing secret leaks) but is
  an opt-in attribution choice, not the default.
- **7.2**: Because the shared metadata file is non-secret, the build-time clobbering
  across successive per-customer builds (F4a) is **harmless** — the file is the
  latest build's locator, nothing secret is lost. `bind`'s sidecar (§6.4)
  eliminates F4b.
- **7.3**: Metadata-file resolution for the locating subcommands (`verify`, `bind`)
  follows a deterministic precedence: explicit `--meta <path>` > per-binary sidecar
  (`<binary>.litmask-meta.toml`) > shared `litmask-meta.toml` in the binary's
  directory. (The override flag is renamed `--config` → `--meta` to match the file.)

## 8. Reproducibility

- **8.1 (decrypt-reproducibility — free)**: Because the operator owns the
  `unlock_key`, **every rebuild decrypts with the same key** regardless of the
  internal seed. The F3 pain ("my captured key went stale") cannot occur. Rebuild
  freely while debugging; the key never breaks.
- **8.2 (bit-identical reproducibility — opt-in)**: Reproducing identical binary
  *bytes* (for attestation, supply-chain hashing, patch-and-diff) still requires
  pinning the seed via `LITMASK_RNG_SEED`, exactly as the other design — but here
  it is a *rare* need, not a daily one, because debugging only needs §8.1.
- **8.3**: The optional `litmask seed` verb mints a valid `LITMASK_RNG_SEED`
  (base64url, 32 bytes) for the §8.2 case. The seed remains a master secret
  (derives `mask_key`); when pinned it is stored with at-least-`unlock_key`
  sensitivity. Debug builds may fix the seed for free bit-repro (§3.5).
  **Observed (current `litmask-build/src/lib.rs:258`):** a malformed pinned
  `LITMASK_RNG_SEED` already **hard-fails the build** (build-script panic, exit 101)
  — correct fail-direction — but the message
  (`"LITMASK_RNG_SEED must be base64url-encoded: Invalid"`) omits the 32-byte length
  and a pointer to `litmask seed`; closing that is implementation work.
- **8.4 (pinned-seed + edited-source nonce-reuse hazard, normative)**: Pinning
  `LITMASK_RNG_SEED` makes build-time nonces deterministic. Reusing the **same**
  pinned seed across builds whose **masked literals changed** can reuse an AEAD
  nonce against different plaintext — a nonce-reuse break that leaks plaintext
  relationships. Documentation MUST warn: pin a seed only for reproducing a
  **specific unchanged source tree** (attestation, patch-diff), and mint a fresh
  seed whenever the masked content changes. The owned-key model makes this safe by
  default because everyday debugging needs only decrypt-repro (§8.1), never a pinned
  seed.
- **8.4.1 (build-time guard preferred over a doc warning — normative)**: Because the
  break is **silent and catastrophic**, a doc warning is insufficient on its own.
  `emit()` SHOULD record a hash of the masked-literal set alongside a pinned seed and
  **fail the build** if the same pinned seed is reused with a *changed* literal set,
  turning a silent nonce-reuse into a loud build error. (If per-call-site nonces are
  instead derived from a per-build-random salt independent of literal *content*, the
  hazard does not arise and the guard is unnecessary — the implementation MUST
  document which nonce-derivation it uses so this requirement is correctly scoped.)
- **8.5 (fresh-seed warning dropped — S1 fix, normative)**: The build MUST NOT emit
  a `cargo:warning=` (or any build-log line) containing the `LITMASK_RNG_SEED`
  value. **Observed (current `litmask-build/src/lib.rs`):** a fresh **release** build
  prints the generated seed via `cargo:warning=` and cargo **caches and replays** it
  on every subsequent build until `build.rs` reruns — so the master secret persists
  in shared CI logs on no-op rebuilds, not just once. Under operator-owned keys this
  warning loses its purpose: runtime decryptability and everyday rebuilds depend only
  on the owned `unlock_key` (§8.1), so no one needs to capture the generated seed.
  The warning is therefore **dropped entirely** for the common case — not merely
  scrubbed of its value — and an operator who wants bit-identical reproducibility pins
  `LITMASK_RNG_SEED` up front (§8.2) and already holds it. (Contrast SPEC_DEVEX §4.5,
  which keeps a *seed-free* "fresh seed generated" notice because that design still
  benefits from it; under owned keys even that notice earns nothing, so A removes the
  line rather than rewording it.)

## 9. Diagnostics Gating (security-correctness)

- **9.1**: Debug-only loud diagnostics (§4.3 identifying strings) are gated on the
  **actual build profile** via a `PROFILE`-derived `cfg` plumbed from a
  runtime-crate `build.rs` — not on `debug_assertions` (user-tunable per profile,
  which would leak strings into release and break the scrub invariant). The gate is
  automatic and fail-safe: a release build is mute without the developer disabling
  anything.
- **9.2**: This cfg governs **strings**, not the key. The key gate is `emit()`'s
  release error (§2.1); there is no generated key to gate, so the cross-crate
  concern of the build-generated design does not arise.
- **9.3 (`K_dev` release-absence — MUST, scrub-invariant)**: The release binary
  MUST NOT contain the `K_dev` value or the fallback branch that references it. A
  litmask-specific constant surviving into release is a **distinguishing signature**
  — a fixed byte pattern a static-analysis adversary can fingerprint to identify the
  binary as litmask-protected, defeating the whole point. This is **not**
  defense-in-depth; it is a hard correctness requirement on the same footing as
  "no plaintext literal in the binary". It fuses with §2.1/§3.4: the single
  `PROFILE` gate that selects "seal under `K_dev`" also selects "compile `K_dev` in
  at all", and that gate fails toward Release, so a misfiring gate cannot ship the
  signature. The `example_scrub` harness asserts the `K_dev` bytes are absent from
  every release artifact.

## 10. Examples, Fixtures & Documentation

- **10.1**: Each example declares its secret/masked fixtures in a single source of
  truth that the scrub test consumes (no duplication across source, doc comments,
  and the scrub test).
- **10.2**: Every example header documents how to **run** it: in debug, plain
  `cargo run` works with no key wiring (§3); for verifying the *release* artifact,
  supply the owned key over a §5 channel — no `awk` line, no inferring an env var
  from another file.
- **10.3**: Documentation states the dev-vs-release split: why release is mute, why
  debug is loud and self-decrypting under `K_dev` (and must never be distributed),
  how coherence is verified (§4), that a release build with no key **fails at build
  time** (§2.1) rather than aborting opaquely at runtime, and that `init_with!` +
  explicit `InitError` handling distinguishes the failure cause (observed:
  `NotPresent` vs `Decryption`).
- **10.3.1 (sysexits claim corrected — observed gap, normative)**: The bare
  `init_with!(…)?` propagation path yields Rust's default `Err` termination —
  **exit 1 with a `Debug`-printed variant**, **not** a `sysexits` code; observed live,
  and no current example wires `InitError::sysexit_code()`. Documentation MUST NOT
  claim `init_with!` "yields the `sysexits` codes" for the `?` path (both the
  build-generated design's §6.3 and this variant inherited that overstatement). At
  least one example MUST map `InitError` to `sysexit_code()` (returning `ExitCode`) so
  the documented `sysexits` behavior is real and copy-pasteable, and docs MUST
  distinguish the `?`→exit-1 path from the explicit-mapping→`sysexits` path.
- **10.4**: `machine_id_provider` / `EnvVarProvider` docs match observed output and
  show the configurable-variable-name / non-env-provider cases so readers do not
  assume the default `LITMASK_UNLOCK_KEY` name is fixed.
- **10.5**: Documentation shows the per-customer pipeline end-to-end: `keygen` per
  customer into the secret store (§6.1.1), build with the key injected via env
  (§5), `verify` (env channel, keyed by default), and inject the same key into the
  runtime provider — or seal under the machine key (§6.3) and ship a bind-free
  binary.

## CI shape (illustrative, normative on the secret-channel points)

Per-customer keys are provisioned once with `keygen` (§6.1), then referenced by
both build and deploy. Secrets travel via **env only** (§5); no value appears in
argv or logs.

```yaml
jobs:
  ship:
    strategy:
      matrix:
        customer: [bob, carol]
    steps:
      - uses: actions/checkout@v6
      - uses: dtolnay/rust-toolchain@stable
      - name: Build for ${{ matrix.customer }}
        env:
          LITMASK_UNLOCK_KEY: ${{ secrets[format('CRYPTIO_KEY_{0}', matrix.customer)] }}
        run: cargo build --release
      - name: Verify coherence
        env:
          LITMASK_UNLOCK_KEY: ${{ secrets[format('CRYPTIO_KEY_{0}', matrix.customer)] }}
        run: litmask verify target/release/cryptio   # keyed by default; reads env; no --key arg
      - name: Ship
        run: ./deploy ${{ matrix.customer }} target/release/cryptio
        # runtime provider reads CRYPTIO_KEY = the SAME secret — no capture step
```

One-time provisioning (distinct keys by default, §6.1.1):

```sh
for c in bob carol; do litmask keygen | gh secret set "CRYPTIO_KEY_${c^^}"; done
```

## Architecture notes

**Provider-agnostic CLI / runtime-owned diagnostics.** Unchanged from the other
design: the key-retrieval mechanism is compile-time consumer source, invisible to
the CLI; the CLI deals in key bytes and the wrapper only. Provider-aware
"missing/wrong key" messaging lives in the debug runtime (§4.3).

**Debug zero-wiring via a constant.** Sealing debug under a public `K_dev`
constant replaces the build-generated design's `DebugFallbackProvider<P>` holding
a *baked per-build secret* and its cross-crate emit-gate. Because `K_dev` is not a
secret, there is nothing to gate across crates — `emit()` seals under it in debug
and refuses in release (§2.1, §3.3). Same "debug self-decrypting, never
distribute" caveat (§3.4), far less mechanism.

**Inversion preserves the wire format.** Only the *source* of the `unlock_key`
moves (output → input) and the *config contents* (drop the secret field). The
wrapper bytes, `mask_key` derivation, blob format, and `KeyProvider` trait are
untouched; a binary built this way is wrapper-compatible at the wrapper level with
the existing `bind` / locator tooling (`verify --locator-only`).

**Distinctness moved, not lost.** The build-generated design enforced key
uniqueness in the binary; this variant enforces it at provisioning (`keygen` per
customer, §6.1.1). The guarantee weakens from "impossible to reuse" to "easy to
not reuse"; in exchange the entire F1–F7/S1 surface and the secret-into-logs
egress disappear.

**API/config shape change (no migration burden — pre-release).** Inversion changes
two contracts: `emit()` *requires* `LITMASK_UNLOCK_KEY` at build (was self-generating), and
`litmask-meta.toml` **drops** the `unlock_key` field. The project is **private and
unreleased**, so there are no external consumers to migrate and no
backward-compatibility or version-bump obligation — the change lands as a direct
edit. (For the build-generated design this same delta would be non-breaking; that
distinction is moot while pre-release and is **not** an input to the decision.)

**Secret hygiene.** The seed is the master secret; pinned only for bit-repro
(§8.2), stored with `unlock_key`-grade care. The owned `unlock_key` travels via
env/file/stdin only (§5), never argv or logs. The debug binary embeds the
non-secret `K_dev` and is self-decrypting — never distribute it. `litmask-meta.toml`
is non-secret (§7.1). The build host holding all customers' keys is an accepted,
documented trust boundary (THREAT_MODEL.md). The fresh-seed build warning that would
leak the seed (observed S1) is dropped under this variant (§8.5) — removing the
`unlock_key` from logs does not address it, because the *seed* was the leaked value.

**Testing strategy.** Build two examples under two distinct owned keys; assert
`verify` (default keyed mode) reports *coherent* for the matching key and *key-fails*
for the other, and *locator-absent* against an unrelated binary, over an
env/file/stdin channel (and assert no argv `--key` flag exists, §5.1); assert the
**four** keyed outcomes carry four distinct exit codes disambiguable from the
`--locator-only` presence codes (§4.1.3); assert `verify` with **no key source and no
`--locator-only`** is a **usage error**, not a silent locator-only pass (§4.1.2 — F7
unreachable by accident); assert `verify --locator-only` runs keyless and returns
only the presence codes (§4.1.1); assert the machine-id off-box path returns
*indeterminate* without flags and full decrypt-success with `--machine-id`/`--salt`
(§4.4); assert `bind` of an `EnvVarProvider` binary then `verify --machine-id`
reports *key-fails* (§4.5); assert the build default and the runtime
`EnvVarProvider` default read the **same** `LITMASK_UNLOCK_KEY` name, so a
default-built binary decrypts under the default runtime with one secret (§1.1.1), and
that a key with a trailing newline is accepted (§1.1.2); assert a **debug** build
decrypts with the key **unset** (`K_dev` rescues `NotFound`, §3.1) but a **wrong**
explicit env value is not rescued and hits the §4.3 diagnostic (§3.2 trigger), and
that a debug run whose configured provider is **misconfigured** is silently rescued
(§3.7 — documents why debug success ≠ wired); assert a
**release** build with no key **fails at build time** (§2.1), that a **custom
release-derived profile** (and an unset/unexpected `PROFILE`) takes the release
branch — hard error, no `K_dev` — not the debug fallback (§2.1 fail-safe polarity),
and that a release artifact embeds **zero `K_dev` bytes** and stays scrub-clean
(§3.4/§9.3); assert the keyed exit-code table does not collide with the
`--locator-only` codes (§4.1.3); assert `emit()` does not write
`unlock_key` to the metadata file and that file is non-secret (§7.1); assert
`keygen` output is valid base64url/32-byte, distinct across runs (§6.1/§6.1.1), and
that `machine-key` reproduces the runtime `MachineIdProvider` derivation (§6.3);
assert the §4.3 diagnostic string form is absent from the release binary
(§9.1); assert metadata-file resolution follows §7.3 precedence; assert a fresh
**release** build emits **no** `cargo:warning` containing the seed value, including on
a cached no-op rebuild (§8.5); assert the sysexits example maps `InitError` to
`sysexit_code()` so the documented codes are real (and that the bare `?` path is
documented as exit 1, not a sysexits code, §10.3.1); reuse the
`example_scrub` harness with one fixtures source per example (§10.1).

## Out of Scope

- A CLI verb that compiles a target, and a `litmask run` exec/key-wiring verb.
- A managed seed/key **secret store**, or solving the build-host-holds-all-keys
  trust boundary (documented in THREAT_MODEL.md, accepted here).
- Build-emitted provider metadata / build-declared provider selection (the runtime
  owns provider identity via §4.3).
- Changing the wrapper wire format or the release-runtime failure paths.
- Enforcing cross-customer key distinctness in the binary (moved to provisioning,
  §6.1.1) — `keygen` makes it easy, not mandatory.

## Decision delta vs `SPEC_DEVEX.md`

| Axis | `SPEC_DEVEX.md` (build-generated) | This variant (operator-owned) |
|---|---|---|
| `unlock_key` | build output, chased back | operator input, build + run |
| Dev-loop wiring | §1.7 baked per-build key | `K_dev` constant |
| Awk/extract ritual | extractor CLI (§2.1) | none (key already owned) |
| Secret in build logs | S1 fix needed (seed-free warning) | `unlock_key` not generated; seed warning **dropped** (§8.5) |
| `litmask-meta.toml` | secret (`unlock_key`) | non-secret (locator only) |
| Reproducibility | opt-in ledger (§7) | decrypt-repro free; bit-repro = pin seed |
| Cross-customer isolation | by construction | `keygen` per customer (provisioning) |
| CLI surface | inspect, bind, extract, seed, record, show-machine-id | verify, bind, keygen, machine-key, show-machine-id (+opt seed) |
| Coherence check default | locator-only (secret-free) | `verify` decrypt-success keyed; `--locator-only` opt-in (F7 unreachable by accident) |
| Secret CLI input | (config-read) | env/file/stdin only, never argv (§5) |
| Biggest risk | friction → S1-style leaks | lazy key reuse (mitigated §6.1.1) |
| Runtime/wire-format blast radius | moderate | minimal |
