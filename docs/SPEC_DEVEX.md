# litmask Developer-Experience — Specification

## Summary

Walking a real consumer through the loop — a developer (Alice) writing an app
(Cryptio) she ships as a **unique build per customer** (Bob, Carol), using the
`examples/` as Cryptio stand-ins — surfaced seven DevEx friction points plus one
security leak. The fixes live in tooling, docs, a debug-only auto-key path, and a
build-identity ledger; none changes how keys are minted, and the **release**
binary embeds exactly what it does today (debug builds gain an embedded key —
§1.7).

Observed live (not theorized):

1. **F1 — Opaque runtime death.** A missing *or* wrong `unlock_key` both abort
   with the same opaque `explicit panic` and no hint. Observed exit codes differ
   by profile, not by cause: **debug aborts with 101** (default unwind), **release
   with 134** (`panic = "abort"` is release-only). Missing-key and wrong-key are
   internally distinct (`runtime.rs:292` NotFound vs `:317` decrypt) yet present
   identically. The default `mask!`-only path (implicit init) aborts and bypasses
   the otherwise-good `sysexits` codes, which only fire when the developer uses
   `init_with!` and handles `InitError` — confirmed live: an `init_with!` example
   surfaces a clean `Err(Decryption)` / exit 1 where the `mask!`-only path panics
   opaquely. The dev-loop half of this (missing key) is *eliminated* by the debug
   auto-key path (§1.7); the wrong-key half is *diagnosed* (§1.4).
2. **F2 — `awk` ritual.** Extracting the key for every run/deploy needs
   `awk -F'"' '/^unlock_key/...' litmask.config`. Eliminated in the dev loop by
   §1.7 (no key wiring needed in debug); the §2 extractor remains for release.
3. **F3 — Silent key rotation.** Any `build.rs` rerun (touch, CI, fresh
   checkout) rotates the release `unlock_key`; a previously-captured key then
   dies with the same opaque panic, with no signal that the cause is staleness.
   Made reproducible by pinning a recorded per-customer seed (§7) and diagnosable
   by §1.2. **Root cause (observed):** `emit()` (build.rs) and macro-expansion
   (compile) are decoupled. `emit` reruns and rewrites `litmask.config` + the
   `OUT_DIR` key files, but cargo does not always recompile the consumer when only
   `OUT_DIR` contents change — so a freshly-emitted config can carry a key the
   on-disk binary's baked wrapper does not match (observed: a just-built example
   failed `inspect` against its own freshly-written config, locator absent). This
   decoupling is the mechanism behind both F3 and F4 and is an independent argument
   for §1.7: baking the key into the debug binary makes it self-consistent
   regardless of `litmask.config` drift.
4. **F4 — Shared-config clobbering.** (a) Every build overwrites the single
   `target/<profile>/litmask.config`, so building Carol after Bob *loses Bob's
   config/locator*; per-customer config management is manual copy-aside. (b)
   `bind` mutates that same shared file in place. The per-customer identity is
   given a managed home by the build-identity ledger (§7).
5. **F5 — No per-customer build/key ergonomics.** Minting a per-customer seed is
   hand-rolled (`head -c32 /dev/urandom | basenc --base64url`); key capture and
   config filing are manual. `litmask seed` (§4.1) mints; the ledger (§7) records
   the identity.
6. **F6 — No key-wire helper.** Nothing wires the matching key to a binary; the
   operator hand-assembles the `LITMASK_UNLOCK_KEY=… ./app` invocation. The dev
   loop no longer wires anything (§1.7); release deployment still wires the key
   out-of-band, which is a boundary, not a litmask job.
7. **F7 — `inspect` is locator-only.** It confirms the config's `locator` is
   present in the binary but never confirms the `unlock_key` actually decrypts the
   wrapper. A right-locator/wrong-key config passes `inspect` yet dies at runtime.
8. **S1 (security) — Seed leak into CI logs.** A fresh **release** build emits a
   `cargo:warning=` containing `LITMASK_RNG_SEED=<seed>` (observed verbatim). The
   seed is the master secret (derives both `mask_key` and `unlock_key`); CI
   captures build warnings into shared logs, leaking it. **Worse than once-per-build
   (observed):** cargo *caches* the build-script warning and *replays* it on every
   subsequent build until `build.rs` reruns — the same seed value re-emits to the
   log on no-op builds — so the seed persists in cargo's cache and the leak surface
   is every build, not just the fresh one. This is a deployment-security defect
   surfaced by the DevEx walk, fixed here under §4.

What already works and must not regress: the masking promise (plaintext absent
from the binary), per-customer uniqueness and cross-customer key isolation *by
construction*, pinned-seed reproducible rebuilds, `inspect`'s guiding error text,
`bind --machine-id` off-box flow, and the `sysexits` codes.

**Governing constraint: a dev-loop fix must not weaken deployment security.** The
build **generates a fresh `unlock_key` per build** — an independence guarantee
*by construction* (a key cannot be reused across builds). Any change that
introduces a developer-chosen stable key would turn that into operator discipline
and create a shared-key single-point-of-compromise. This spec therefore leaves
the key model **untouched** and fixes every pain through **tooling and
documentation** that lives in the never-shipped CLI and the debug profile, plus
the one security fix (S1). No deployment-security property is weakened: same
generated per-build key, same secret-config transport, same per-build seed, same
**release** embedded bytes, same zero-identifying-strings scrub invariant. The
debug-only embedded key (§1.7) sits entirely behind the §5.1 PROFILE gate and
never reaches a release binary.

**Division of labor (a hard constraint, not a preference).** The key-retrieval
mechanism is **compile-time consumer source and is invisible to the CLI.** A
binary may use `EnvVarProvider` under *any* variable name
(`EnvVarProvider::new("CRYPTIO_SECRET")`), `FileProvider` at some path,
`MachineIdProvider` (self-deriving), or a custom `KeyProvider` (vault/HSM). The
CLI sees only the binary + config and cannot know which. Therefore:

- **The runtime owns provider-aware diagnostics.** Only the runtime holds the
  provider instance and can name the exact source it tried (`EnvVarProvider`
  exposes `var_name()`; a `FileProvider` knows its path). The "missing/wrong key"
  message (§1.4) is a debug-runtime concern and is accurate per-app for free.
- **The CLI stays provider-agnostic — it deals in key *bytes* and the wrapper,
  never env/file semantics.** It never assumes `LITMASK_UNLOCK_KEY` or that the
  provider is env-based.
- **Building is cargo's job; the CLI never compiles and has no `run` verb.** The
  consumer already has cargo and `just`. The dev loop is plain `cargo run` /
  `cargo test` — §1.7 auto-key means no wiring at all. Any build-and-run
  convenience for a *release* artifact is a `just` recipe composing the §2
  extractor with the prebuilt binary. The distributable CLI is `inspect` +
  key-extractor + `seed` (+ the §7 record command).

Explicitly rejected (do not re-litigate): `unlock_key`-as-input (inversion),
per-instance reseal, sealmap provisioning, wire-format de-signaturing, a
standalone `keygen` verb, a cargo-building CLI verb, a `litmask run`
exec/key-wiring verb, and **build-emitted provider metadata** (a config field
naming the provider/var so the CLI could give provider-aware diagnostics and a
`run` verb could auto-wire any provider). The `run` verb was dropped because
provider-agnosticism (above) means it could only ever auto-wire the
default-env-var case — a one-line `just` recipe or the extractor already covers
that, and §1.7 removes the dev-loop need entirely — so the verb earned nothing
while leaking env semantics into a provider-agnostic CLI. **Build-emitted
provider metadata was rejected on red-team**: the provider is selected in the
consumer's *runtime* code (`init_with!` or the implicit default), which the build
(`build.rs` + proc-macro) never observes. The build could therefore only describe
the implicit-default case (already handled by the §2.1 `--var` default); covering
renamed/custom providers would force the consumer to declare the provider twice
(build.rs *and* main.rs), a consistency hazard, or move provider selection out of
runtime entirely (a large init-API redesign that still cannot express runtime
custom providers like vault/HSM). The runtime is the correct, sole owner of
provider identity — already realized by §1.4 / §1.4.1 (`source_hint`). The "CLI is
blind to the provider" property is correct by construction, not a defect to fix.
The first four alternatives chase a separate deployment-security product
(unique-per-instance, non-signatureable) that is not an original pain.

## Audience & Mode Model

- **Developer / operator loop** — iterate, run examples/tests, prove masking,
  ship per-customer builds. Coherence and loud diagnostics are wanted. Debug
  builds are *not* scrub-clean (DWARF), so they may freely carry identifying
  strings, helpful messages, **and an embedded `unlock_key` (§1.7)** so the dev
  loop needs no key wiring. Consequence: a **debug build is self-decrypting and
  must never be distributed** — this is documented loudly and is the price of
  zero-config `cargo run`. Release verification is driven by the CLI, which is
  never shipped to the attacker (it may run on a trusted deployment host, e.g.
  on-host `bind`).
- **Production** — CI builds release with a fresh unique seed and a generated
  per-build `unlock_key`, emitted to a secret config that is transported
  out-of-band into a runtime `KeyProvider`. The attacker holds **the shipped
  binary only**. The release binary stays mute and free of litmask-identifying
  strings.

Every loud, identifying, or config-aware behavior is gated to debug builds or the
CLI; the release binary's behavior is unchanged.

## Foundation (unchanged — the deployment-security guarantees we preserve)

- **F.1**: The build generates a fresh per-build `unlock_key`; independence
  across builds is enforced by construction. This spec does not change it.
- **F.2**: A 32-byte build seed (`LITMASK_RNG_SEED` env > debug-only persist file
  > fresh OS RNG) deterministically derives `mask_key` and build-time nonces:
  fresh release seed ⇒ per-build-unique blobs; pinned seed ⇒ reproducible build.
  The seed is the **master secret** for a build (it derives both `mask_key` and
  `unlock_key`); its handling is tightened in §4 (S1) but the derivation is
  unchanged.
- **F.3**: `unlock_key` is never embedded **in a release binary**; only the
  wrapper (mask_key sealed under unlock_key) is. The runtime obtains `unlock_key`
  from a `KeyProvider` (the default `EnvVarProvider` reads `LITMASK_UNLOCK_KEY`,
  but the provider and variable name are the consumer's compile-time choice).
  Release behavior unchanged; §1.7 adds a debug-only embedded key behind the §5.1
  PROFILE gate, which never reaches release.
- **F.4**: Release runtime failure paths use bare `panic!()` / `Err(Decryption)`
  with no identifying text. The `litmask.config` is secret. Unchanged.

## 1. Coherence & Failure Diagnostics (fixes F1, F2, F3, F6, F7)

- **1.1**: Plain `litmask inspect` keeps today's **locator-presence** check and
  stays **secret-free**: it never decodes `unlock_key` into its address space
  (preserving the existing `parse_locator_only` hardening). An opt-in
  `--check-decrypt` flag adds the authoritative **decrypt-success** check — it
  confirms the `unlock_key` (from config or derived per §1.6) actually decrypts
  the wrapper. It reports **three distinct outcomes via distinct exit codes**:
  *coherent* (decrypt succeeded), *incoherent* (locator absent, or present-but-key-
  fails-to-decrypt), and *indeterminate* (locator present but decrypt could not be
  checked — see §1.6). Indeterminate MUST NOT collapse into coherent: doing so
  would recreate the F7 false-pass. Decrypt-success is the source of truth —
  strictly stronger than locator presence, which a right-locator/wrong-key config
  silently passes (F7) — so it is opt-in precisely because it must read the secret.
- **1.2**: The two failure shapes are separately diagnosable so an operator can
  tell *wrong config* from *stale/rotated key* (F3): a config whose locator is
  absent reports "wrong config for this binary" (the existing guiding message,
  available secret-free); under `--check-decrypt`, a present locator whose key
  fails to decrypt reports "locator present but key does not decrypt".
- **1.3**: In **debug** builds only, an init/mask failure surfaces a build
  **fingerprint** (see Architecture) so a human can correlate "this binary"
  against "this config" without the CLI. Release failure paths emit no
  litmask-identifying text (bare `panic!()`, unchanged per F.4).
- **1.4**: In **debug** builds only, a key failure that is *not* resolved by the
  §1.7 auto-key fallback — i.e. a provider that returned a key which then fails to
  decrypt the wrapper (wrong/stale env value, an unbound `MachineIdProvider`); per
  §1.7.0 the "key absent" case is rescued, not diagnosed — names the
  **provider-specific source** the runtime actually tried (the configured env var
  via `EnvVarProvider::var_name()`, the file path, etc.) instead of aborting with a
  bare `explicit panic` (F1). This lives in the runtime because only the runtime
  knows the provider; the CLI never names a source it cannot know. Release keeps
  the mute abort.
- **1.4.1**: Custom (consumer-authored) `KeyProvider` implementations may
  participate in §1.4 naming via an **optional** trait method
  `fn source_hint(&self) -> Option<&str> { None }`. The default returns `None`
  (non-breaking — existing custom providers compile unchanged and simply produce
  no source name). Built-in providers implement it (`EnvVarProvider` returns its
  `var_name()`, `FileProvider` its path). The hint is consumed only on the
  debug diagnostic path; release never reads it.
- **1.5**: The fingerprint is derived **on demand** from the already-public
  wrapper bytes; it is not added as a new embedded field and not written into
  `litmask.config`. Its rendered string form is absent from a stripped release
  binary (scrub-clean).
- **1.6**: For a `MachineIdProvider`-bound binary, the §1.1 decrypt-success check
  requires the machine-derived key, which off-box (on Alice's build host) the CLI
  cannot reproduce. `inspect --check-decrypt` therefore accepts the same
  `--machine-id`/`--salt` flags `bind` already exposes: given them, it derives the
  machine key and performs the full decrypt-success check parallel to `bind`'s own
  derivation. Without them, the check returns the **indeterminate** outcome (§1.1)
  — locator present, decrypt not checkable — with its own exit code, *never* the
  coherent code; full decrypt-success is available only (a) on the bound host
  (where the provider self-derives), or (b) via the supplied `--machine-id`/`--salt`.
  The spec states this degradation rather than implying a universal decrypt-check.
- **1.7 (debug auto-key)**: In **debug** builds only, the configured provider is
  composed with a debug-only fallback holding the per-build `unlock_key`, so
  resolution becomes "try the real provider; if it reports the key **absent**, use
  the embedded key." Effect: `cargo run` and tests decrypt with **zero key wiring** —
  no env var, no `awk`, no extractor, no opaque missing-key panic (eliminates the
  dev-loop halves of F1/F2/F6). The fallback's key store is the **existing public
  `StaticProvider`** (today documented "tests only", carrying a "never wire into a
  release build" caution): no new public type is introduced, and that pre-existing
  contract is exactly the trust boundary §1.7.2 leans on. Only release-absence is
  enforced by §1.7.1's `emit` gate; `StaticProvider` itself stays as-is.
  - **1.7.0 (fallback trigger — structural, normative)**: The fallback fires
    **only** when the primary provider returns `KeyError::NotFound`. This is not a
    behavioral guard but a **structural** property: the fallback sits at the
    *key-retrieval* layer (a wrapping `KeyProvider`), which runs *before*
    decryption, so it can only ever see "key found / not found" — never a
    decrypt failure. A key that is present but wrong (stale env value, unbound
    `MachineIdProvider`) flows through unchanged and is surfaced by §1.4, not
    masked. "Explicit but wrong" stays diagnosable while "simply unset" Just Works,
    by construction.
  - **1.7.1 (single gate at emit, normative)**: The `unlock_key` is minted in the
    consumer's `build.rs` (`litmask_build::emit`) and reaches the binary only by
    macro-baking — the runtime crate cannot carry a consumer-build-time secret. The
    debug/release **gate is therefore one data-flow decision in `emit`**, driven by
    its `PROFILE`: in release `emit` emits **no** fallback key, so the macro bakes
    nothing and the composed fallback is `None` (no secret in the binary, F.3
    intact); in debug it emits the key and the fallback is `Some`. The macro and the
    provider composition are **unconditional relays** of whatever `emit` provided —
    no independently-maintained `cfg` has to agree across crates (note
    `cargo:rustc-cfg` from litmask's `build.rs` would not reach macro-expanded code
    in the consumer crate anyway). A single `DebugFallbackProvider<P>` wrapper is
    applied once at the internal "resolve provider" point so it uniformly covers the
    implicit-default path, `init_with!`, and custom providers. The wrapper is an
    **internal** type (users never name or construct it); only its `StaticProvider`
    key store is public, reused unchanged from existing surface. The runtime fallback
    branch MAY additionally be `cfg`-stripped in release as cheap defense-in-depth,
    but `emit` is the single source of truth.
  - **1.7.2 (security caveat, normative)**: A debug build carries both the key and
    the ciphertext, so it is **self-decrypting** and offers **no protection against
    extraction** — only release does. It therefore MUST NOT be distributed. This is
    documented loudly (§6.3) and recorded as an accepted trust boundary
    (THREAT_MODEL.md). It does not weaken *deployment* security: the masking promise
    a release ships is about *plaintext* absence under attacker analysis, release is
    untouched, and the debug binary still embeds no plaintext literal (the key +
    ciphertext is a dev-only convenience, not a shipped artifact).
  - **1.7.3**: The fallback rescues only `NotFound`, so a debug `cargo run` using
    `init_with!(MachineIdProvider::new())` is **not** auto-rescued (the provider
    returns a derived key that fails to decrypt until bound — §1.7.0). Documentation
    states the consequence: in the dev loop either use the default/env provider or
    `bind` to the dev's own machine first; machine-id is a deployment-binding
    concept, not a dev-loop one.

## 2. Key Extraction for release/verification (fixes F2, F6 outside the dev loop)

- **2.1**: A CLI helper prints a target's `unlock_key`, replacing the
  `awk`-on-config incantation (F2, F6). With §1.7 the **dev loop no longer needs
  it**; it serves the release/verification cases — running a *release* binary
  locally to verify it, or capturing the key for out-of-band deployment handoff.
  It emits the **key value**; printing to stdout is acceptable (the dev/build host
  is trusted, Q6). When the operator wants a ready-to-paste export line it accepts
  `--var NAME` and prints `NAME=<base64url>`, defaulting `NAME` to
  `LITMASK_UNLOCK_KEY` purely as the default-provider convenience — documented as
  "override if your app configures a custom variable name or a non-env provider."
  The helper never presumes the provider; it only knows bytes.
  - **2.1.1 (secret-egress hygiene, normative)**: The extractor is a **deliberate
    secret-egress point** — it prints the `unlock_key` in the clear. It carries the
    same warning as S1/§4.5: **never route its output into shared/CI logs** or an
    untrusted terminal. (Asymmetry by design: plain `inspect` is hardened to *avoid*
    loading the secret (§1.1); the extractor exists to emit it, so the burden moves
    to the operator not to capture it where it leaks.)
- **2.2**: For a **release** binary, the supported run path is to supply the key
  via the app's own provider mechanism (it has no embedded fallback); it benefits
  from the §1 coherence signal on mismatch rather than an opaque failure. The
  dev-loop `cargo run` path needs none of this (§1.7). Any build-and-run
  convenience for a release artifact is a `just` recipe composing §2.1 with the
  prebuilt binary — not a CLI verb.

## 3. Config Isolation (fixes F4)

- **3.1**: `bind <binary>` writes its re-keyed config to a per-binary **sidecar**
  path `<binary>.litmask.config` (or an explicit `--output`) and never overwrites
  the emit-time shared `litmask.config` (fixes F4b). The derivation is normative
  and testable: sidecar = the binary path with `.litmask.config` appended.
- **3.2**: Binding one binary leaves every other binary's config and runtime
  decryptability unchanged (the observed round-2 regression cannot recur).
- **3.3**: All config-consuming subcommands (`inspect`, the §2.1 extractor)
  resolve config by a documented, deterministic precedence: explicit `--config`
  > per-binary sidecar (`<binary>.litmask.config`) > emit-time `litmask.config`
  in the binary's directory. `--config` is required only to override.
- **3.4**: The build-time clobbering of the shared
  `target/<profile>/litmask.config` across successive builds (F4a) is addressed
  by documentation, §4 ergonomics, and the §7 ledger. **Observed downstream effect:**
  after building Carol over Bob, the shared config holds only Carol's locator, so
  `inspect <bob-binary>` reports **locator-absent** — Bob's already-built binary
  becomes un-inspectable against the live config until Bob's config is restored.
  This makes the clobber not merely a lost-file nuisance but an active loss of
  verifiability for every prior customer. A per-customer build pins
  its seed and files its config under a customer-specific name; the per-customer
  identity (seed reference + fingerprint) is recorded in the ledger (§7); the
  shared file is understood as the *latest* build's config, not a per-customer
  store. No build-script change to the shared path (that would alter the emit
  contract); the fix is workflow + tooling.
- **3.5**: The sidecar/config is a **build-host artifact and is never shipped
  alongside the binary.** For an `EnvVarProvider`/`FileProvider` build the config
  holds the secret `unlock_key`; shipping it next to the binary would hand the
  attacker the key and defeat masking. The only artifacts that legitimately reach
  the customer host are (a) a `bind`-ed binary needing no key, or (b) the
  `unlock_key` injected out-of-band into the app's provider mechanism — never as a
  file beside the binary. Documentation states this and the DEPLOYMENT.md `scp`
  recipe is corrected accordingly.

- **3.6**: For `MachineIdProvider` deployments the **documented default is
  vendor-side `bind --machine-id`**: Alice derives the customer host's machine key
  off-box from a supplied machine ID (+ optional `--salt`) and ships only the
  re-keyed binary, which needs no accompanying config or key. This keeps the
  secret config a build-host artifact (§3.5) — it **never ships**. On-host `bind`
  (transport the binary *and* its secret config to the customer host, then bind
  there) is demoted to a narrow residual case for when the machine ID cannot be
  obtained in advance; it requires a secure transport channel and deleting the
  shipped config immediately after binding. DEPLOYMENT.md leads with the
  vendor-side flow and frames on-host bind as the exception, not the default.

- **3.7 (bind/provider mismatch — observed)**: `bind` re-keys the wrapper to a
  machine-ID-derived `unlock_key` but cannot see the binary's *compiled-in*
  provider. Binding a binary whose runtime uses `EnvVarProvider` (not
  `MachineIdProvider`) reports success (exit 0) yet yields a **runtime-broken
  artifact**: the binary still reads its env var, finds nothing, and aborts
  `NotFound` — and plain `inspect` still passes because the locator is intact
  (compounding F7). `bind`'s rekey is only meaningful for a `MachineIdProvider`
  binary, which `bind` cannot verify. Mitigation lives in the §1.1
  `--check-decrypt` coherence path (a machine-id `--check-decrypt` of a rebound
  `EnvVarProvider` binary reports *incoherent*), and documentation must state that
  `bind` is for `MachineIdProvider` builds only — success from `bind` is not
  evidence the binary will decrypt.

> No `litmask keygen` verb. Plan A generates the `unlock_key` at build time;
> users **extract** it (§2.1), never mint it. A standalone `keygen` would invite
> the rejected "operator chooses the key" mental model and silently fail to
> decrypt. Revisit only if `bind` gains an explicit random-rekey mode, at which
> point key generation is a sub-need of that mode, not a standalone verb.

## 4. Seed & Per-Customer Ergonomics (fixes F5, S1)

- **4.1**: `litmask seed` prints a valid `LITMASK_RNG_SEED` value (correct
  base64url encoding, 32 bytes) suitable for direct export, replacing the
  hand-rolled `head -c32 /dev/urandom | basenc` ritual (F5).
- **4.2**: A malformed `LITMASK_RNG_SEED` at build time reports the required
  encoding (base64url), the required length (32 bytes), and points to
  `litmask seed`. (Build-time developer input — not subject to the runtime
  panic-message-hygiene rule.) **Observed (current `litmask-build/src/lib.rs:258`):**
  the malformed case already **hard-fails the build** via a build-script panic
  (exit 101) — the correct fail-direction — but the message
  (`"LITMASK_RNG_SEED must be base64url-encoded: Invalid"`) is partial: it omits the
  32-byte length and the `litmask seed` pointer this requirement mandates. Closing
  that gap is implementation work; the fail-hard behavior is already correct.
- **4.3**: Documentation describes the per-customer build recipe end-to-end: mint
  a seed (`litmask seed`), build with `LITMASK_RNG_SEED` pinned, capture the
  config under a customer name, and either inject the extracted key (§2.1) or
  `bind` to the customer's machine — so a fresh operator ships unique builds to
  Bob and Carol without losing either's config (F4a, F5).
- **4.4**: Documentation flags that the **seed is the master secret** — strictly
  more sensitive than the `unlock_key`, since it derives both `mask_key` and
  `unlock_key`. Pinning a seed is **optional**: the default fresh-seed path
  requires nothing stored; pinning is only for reproducibility/patching, and a
  pinned per-customer seed must be stored with at-least-`unlock_key` sensitivity
  (sealed CI secret / vault). Building the secret store that *holds* the seed is
  the operator's responsibility (out of scope); the §7 ledger records only a
  **reference** to that store (a vault path / secret name), never the seed bytes.
- **4.5 (S1 fix)**: The fresh-release seed-capture `cargo:warning=` MUST NOT echo
  the seed value — `cargo:warning` output is captured into shared CI logs, which
  would leak the master secret. This is sharpened by an observed cargo behavior:
  build-script warnings are **cached and replayed on every subsequent build** until
  `build.rs` reruns, so a seed-bearing warning leaks not once but on every build
  (including no-op rebuilds) that reads the cache. The warning instead states that
  a fresh seed was generated, points to the build-host-local seed artifact for
  recovery, and recommends pinning `LITMASK_RNG_SEED` up front for any build that
  must be reproducible. No secret material appears in build logs — and because the
  fixed warning carries no seed, the cached-replay path is harmless.

## 5. Diagnostics Gating (security-correctness)

- **5.1**: The debug-only **loud diagnostics** (§1.3/§1.4 identifying strings) are
  gated on the **actual build profile**, not on `debug_assertions`. Rationale:
  `debug_assertions` is user-tunable per profile (`[profile.release]
  debug-assertions = true` is legitimate), so keying the mute/loud boundary on it
  would compile identifying strings into a release binary and break the scrub
  invariant. **Mechanism (chosen): a `PROFILE`-derived `cfg`** plumbed from a
  runtime-crate `build.rs` (the `litmask` crate has none today; this adds one
  whose sole job is to emit `cargo:rustc-cfg` from `PROFILE`). Chosen over a
  default-off Cargo feature because the gate is **automatic and fail-safe** — a
  release build is mute without the developer remembering to disable a feature,
  the safer default for a security boundary.
  - **5.1.1**: The §1.7 **embedded key** is *not* gated by this runtime cfg — its
    gate is the single data-flow decision in `litmask_build::emit` (§1.7.1), since
    `cargo:rustc-cfg` from litmask's `build.rs` cannot reach the macro-expanded
    fallback that lands in the consumer crate. The §5.1 cfg MAY additionally strip
    the runtime fallback branch in release as defense-in-depth, but the
    authoritative key gate lives in `emit`, not here. Keep the two concerns
    distinct: this cfg governs *strings*; `emit` governs the *key*.

## 6. Examples, Fixtures & Documentation (fixes F1 framing, doc gaps)

- **6.1**: Each example declares its secret/masked fixtures in a single source of
  truth that the scrub test consumes; fixture strings are not duplicated across
  example source, doc comments, and the scrub test.
- **6.2**: Every example's header documents how to **run** it (not only how to
  `strings`-verify it): in debug, plain `cargo run` works with no key wiring
  (§1.7); for verifying the *release* artifact it points at the §2.1 extractor
  instead of the bare `awk` line. No example relies on the reader inferring an env
  var from a different file.
- **6.3**: Documentation states the dev-vs-release behavior split explicitly: why
  release runtime is mute, why debug is loud, how coherence is verified, that
  **debug builds embed a key and are self-decrypting (§1.7) and must never be
  distributed**, and that the default `mask!`-only path therefore *succeeds with
  no key wiring in debug* but a **release** binary with no key aborts mute (F1).
  It also documents that `init_with!` + `InitError` handling yields the `sysexits`
  codes.
- **6.4**: `machine_id_provider` and `EnvVarProvider` docs match observed output —
  the failure a reader actually sees is documented (no claim of a message the
  binary cannot emit), and the configurable-variable-name / non-env-provider cases
  are shown so readers do not assume `LITMASK_UNLOCK_KEY` is fixed.

## 7. Build Identity & Audit (fixes F3 reproducibility, F4a/F5 identity)

The release-side residual after S1/§3/§4: a per-customer build has no managed
**identity** — nothing makes "rebuild Bob's exact binary to ship a patch"
reproducible, and nothing records "which key/fingerprint shipped to whom, when."
This is addressed by a **ledger**, a record-keeping artifact only. litmask
**records** identities; cargo/`just` still builds (no build-driver verb).

- **7.1**: A `litmask` record command appends a per-build **ledger entry** for a
  customer binary capturing: customer label, the §1.5 build **fingerprint**
  (derived on demand from the freshly built binary's wrapper bytes), the build
  date, the **litmask wire-format version** (so §7.3 fingerprint reproducibility is
  interpretable), and a **reference** to where the build's seed is stored (e.g. a
  vault path or CI secret name). The entry is appended; the ledger is not a build
  step.
- **7.2 (security, normative)**: The ledger **never contains secret material** —
  not the seed, not the `unlock_key`. It holds the non-secret fingerprint
  (derived from the already-public wrapper), labels, dates, and *pointers* to the
  operator's secret store. The secret store itself remains the operator's
  responsibility (§4.4). This keeps litmask out of secret custody: the ledger may
  live in the repo or on the build host at low sensitivity.
- **7.3**: Reproducible patch rebuild: given a ledger entry, the operator
  resolves the referenced seed from their secret store, pins it as
  `LITMASK_RNG_SEED`, and rebuilds — yielding the same `mask_key`/`unlock_key`
  (keys derive from the seed alone, deterministically) and, **for the same litmask
  wire-format version and the same masked source**, a matching fingerprint
  (verifiable with §1.1 `--check-decrypt`). The *key* reproducibility holds
  unconditionally from the seed; the *fingerprint* match additionally assumes the
  wrapper bytes are unchanged — a litmask version that alters the wire format will
  change the fingerprint even with the same seed, so the ledger SHOULD record the
  litmask version alongside the entry. This makes F3's "silent rotation" a
  deliberate, reproducible choice rather than an accident.
- **7.4**: The ledger is **optional** — the default fresh-seed, ship-once flow
  needs no ledger. It earns its keep only for operators who ship reproducible,
  auditable per-customer builds. No build-script change; no new embedded field.

## Architecture notes

**Coherence** = "the `unlock_key` a consumer will use actually decrypts the
wrapper in a given binary." It cannot be guaranteed by construction (per-build
uniqueness) and is instead **checkable** via decrypt-success. The CLI holds
binary + candidate key and is authoritative *for keys it can reproduce*; for
machine-id-bound binaries off-box it degrades to locator-presence (§1.6). The
release runtime has only the binary and its sole signal is decrypt
success/failure (debug adds the fingerprint + provider-named source for human
correlation).

**Provider-agnostic CLI / runtime-owned diagnostics.** The key-retrieval
mechanism is compile-time consumer source, invisible to the CLI. The CLI deals in
key bytes and the wrapper only; it never assumes a variable name or provider type.
Provider-aware "missing/wrong key" messaging lives in the debug runtime, which
holds the provider instance (`EnvVarProvider::var_name()`, a file path, etc.).
The CLI has no `run` verb and never compiles — building is cargo's, run-loop
convenience is `just`'s.

**Debug auto-key (§1.7)** = the configured provider is wrapped by a single
`DebugFallbackProvider<P>` that composes a `StaticProvider` fallback holding the
per-build `unlock_key`. Resolution is `primary.unlock_key().or_else(|| fallback)`,
so the fallback can fire *only* on `NotFound` (it lives at the key-retrieval layer,
before decryption — §1.7.0 is therefore structural, not a guard). The key value is
minted in the consumer's `build.rs` (`emit`) and baked by the macro; the **single
gate** is `emit`'s `PROFILE` decision to emit the fallback key or not (§1.7.1) —
release emits none, so the fallback composes to `None` and no secret reaches the
binary (F.3 intact). This deliberately avoids a cross-crate `cfg` that would have
to agree in three places (`cargo:rustc-cfg` from litmask's `build.rs` never reaches
consumer-crate macro expansion). Embedding the *key* (not the plaintext) keeps the
masking promise — `strings` on a debug binary still finds no masked literal —
though the debug binary is self-decrypting and must not be distributed (§1.7.2).
Chosen over reading a config file beside the binary at runtime, which is
cwd-/relocation-fragile; embedding is robust and self-contained. Embedding also
sidesteps the observed `emit`/recompile desync (F3 root cause): because the key is
baked into the binary at the same macro-expansion that bakes the wrapper, the
debug binary is internally self-consistent and immune to `litmask.config` drift on
disk — the on-disk config can rotate without breaking the binary's own decrypt.

**Build-identity ledger (§7)** = an append-only record of `(customer, fingerprint,
date, seed-reference)`. It is deliberately *not* a secret store and *not* a build
driver: it holds non-secret pointers + the public-derived fingerprint, and is
written by an explicit record step, never by the build. It exists to make
per-customer rebuilds reproducible (resolve seed-ref → pin → rebuild) and
shipments auditable, the release-side residual that §3/§4 left as "name your files
carefully."

**Build fingerprint** = short truncated-BLAKE3 of the (already public) wrapper,
base32, **derived on demand** — never stored in config, never a new embedded
field. Reveals nothing new and is scrub-clean. Its only job is human correlation
in debug diagnostics (§1.3); the authoritative machine check is decrypt-success
(§1.1), so the fingerprint earns its keep purely as a readable label, not a
coherence oracle.

**Secret hygiene.** The seed is the master secret; it must never reach a shared
log (§4.5) and is stored, when pinned, with at-least-`unlock_key` sensitivity
(§4.4). The config/sidecar holds the `unlock_key` and is a build-host artifact,
never shipped beside the binary (§3.5). The debug binary embeds the `unlock_key`
(§1.7) and is therefore self-decrypting — never distribute a debug build. The
ledger (§7) holds **no** secret material, only non-secret references and the
public-derived fingerprint. The build host accumulating all customers' keys (and
seed references) is an accepted, documented trust boundary (see THREAT_MODEL.md),
not solved here.

**Diagnostics policy (invariant-preserving)** = release runtime keeps the
message-free paths verbatim. All human-readable explanation lives in
debug-profile runtime and the CLI, gated per §5.1.

**Testing strategy** = build two examples with distinct pinned seeds; assert
`inspect` reports coherent for the matching key and incoherent for the other,
covering both the locator-absent and key-mismatch branches (§1.1/§1.2); assert the
three outcomes carry **three distinct exit codes** and that *indeterminate* never
equals *coherent* (§1.1); assert the machine-id off-box path returns the
**indeterminate** code without flags and full decrypt-success when
`--machine-id`/`--salt` are supplied (§1.6);
assert a custom provider's `source_hint()` (and its `None` default) drives the
debug source-naming (§1.4.1); assert `bind` of
one writes only its `<binary>.litmask.config` sidecar and leaves the other's
config and decryptability intact (§3.1/§3.2); assert config resolution follows
the §3.3 precedence; assert `bind` of an `EnvVarProvider` binary followed by
`inspect --check-decrypt --machine-id` reports *incoherent*, not coherent (§3.7); assert the debug-profile init/mask failure names the
provider source (§1.4) while the release build stays mute and scrub-clean (§5.1);
assert the fingerprint string form is absent from the release binary (§1.5);
assert the fresh-release warning contains no seed bytes (§4.5); assert a **debug**
build decrypts with the env var **unset** (§1.7 auto-key rescues `NotFound`) but a
**wrong** explicit env value is *not* rescued and instead hits the §1.4 diagnostic
(§1.7.0 trigger), and that a **release** build composes the fallback to `None`,
embeds no key, does not self-decrypt (§1.7.1), and stays scrub-clean of both the
key bytes and plaintext (§1.7.2); assert a ledger entry round-trips and that resolving its seed-reference,
pinning it, and rebuilding reproduces the recorded fingerprint (§7.1/§7.3) while
the ledger file contains no seed/`unlock_key` bytes (§7.2). Reuse the
`example_scrub` harness; one fixtures source per example feeds the scrub test
(§6.1).

## Out of Scope

- A CLI verb that compiles a target, and a `litmask run` exec/key-wiring verb
  (run-loop convenience is a `just` recipe; building is cargo's).
- Changing the build-time shared-config path or emit contract (F4a is fixed by
  workflow + tooling, not by relocating the emitted file).
- A managed seed/key **secret store**, or solving the
  build-host-holds-all-customers'-keys trust boundary — documented in
  THREAT_MODEL.md, accepted here. (The §7 ledger records non-secret *references*
  to such a store, not the secrets themselves — it is in scope; the store is not.)
- Build-emitted provider metadata / build-declared provider selection (rejected
  on red-team — see Summary; the runtime owns provider identity via §1.4/§1.4.1).
- Any change to key minting, the wrapper wire format, or the release-runtime
  failure paths. (§1.7 adds a *debug*-only embedded key; the release embed set is
  unchanged.)
- Any new identifying strings — or the embedded key — in **shipped/release**
  binaries.
