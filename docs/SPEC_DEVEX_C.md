# litmask Developer-Experience — Specification (Variant C: Declarative + Layered)

> **Status:** design variant, refine phase. Fourth option beside
> `docs/SPEC_DEVEX.md` (build-generated key), `docs/SPEC_DEVEX_A.md`
> (operator-owned key), and `docs/SPEC_DEVEX_B.md` (clean slate). **C adopts B's
> foundation verbatim** — operator-owned `unlock_key`, derived locator, opaque
> wrapper, reseal-default deployment, `K_dev` zero-wiring, no-argv secret
> channels, the four-outcome `verify` — and adds three orthogonal moves on top:
> (1) a **single declarative provider site** that lets tooling *recover* the
> runtime's key-acquisition intent from the binary; (2) an explicit **two-layer
> crate split** (masking core vs distribution tool); (3) a **workflow guard** that
> turns "never ship a debug build" from documentation into a check. Drafted for a
> deliberate side-by-side decision. If adopted, C replaces B (and the other two).
> The project is **pre-release**, so C lands as a direct edit with no migration
> burden.

## Summary

B removed the last sidecar file and the per-customer-build assumption, leaving a
clean core. Walking B in use surfaced one residual seam and two ergonomic gaps
that B inherits rather than closes:

1. **Provider intent is invisible to tooling (B §4.4.1).** B states, correctly,
   that the compiled-in `KeyProvider` is chosen in *runtime* code and **no offline
   check can observe it** — so `reseal --to-machine-id` on an `EnvVarProvider`
   binary produces a well-formed artifact that silently never self-decrypts, and
   `verify` cannot catch it. B's honest answer is "validate by executing the
   binary" (B §4.4.2). That works but is heavyweight (needs a runner, a throwaway
   reseal, a cleared env) and is the single largest sharp edge left in B. **C's
   first move makes provider *intent* a recoverable property of the binary** for
   the built-in providers, turning B's "fundamentally invisible" into "invisible
   *unless the binary declares it*, which the built-ins now do."

2. **Two provider-setup sites invite divergence.** B has the provider chosen at a
   runtime macro (`init_with!` / implicit default) **and** key bytes supplied at
   build (`emit()`), and for machine-id deployments a *third* decision at reseal
   (`--to-machine-id`). Three places, three chances to disagree (RT-2: build seals
   under env-key, runtime asks machine-id, reseal targets a *different*
   machine-id). **C's second move collapses provider declaration to exactly one
   site** — a single source-level `init!` — and removes `init_with!`. `build.rs`
   goes back to **key-bytes-only**. One site cannot diverge from itself.

3. **The crate boundary is implicit.** litmask today is one runtime crate plus a
   build helper plus a CLI, but the *contract* between "the masking core a
   consumer compiles against" and "the distribution tool an operator runs" is not
   stated, so the CLI and the runtime drift on what a wrapper/locator/decl means.
   **C's third move names the two layers** and pins the wire contract between them
   (the decl_blob, §3), so the CLI reads exactly what the macro wrote.

C is therefore **B + declarative key-acquisition + one provider site + a named
layer contract + a debug-never-ship workflow guard.** Everything B collapsed stays
collapsed; C adds machinery only where B left a sharp edge.

**What C does *not* claim.** C does **not** make `verify` authoritative for
provider alignment in general. For **built-in** providers (env / file / machine-id)
the declaration is precise and the alignment check is authoritative; for a
**custom** provider the declaration is necessarily `custom` and the check returns
*indeterminate* — B's execute-locally proof (B §4.4.2) remains the only authority
there. The honest framing (§4.4): the alignment check is an **opt-in early-warning
axis that complements, never replaces, executing the binary**, and its value is
**proportional to built-in-provider usage**. A pure-vault shop gains nothing from
C's static machinery and degrades cleanly to B-parity.

## Audience & Mode Model

Unchanged from B, plus one consequence of the layer split (§2):

- **Developer / operator loop** — iterate, run examples/tests, ship to
  customers. Debug builds seal under a per-crate **non-secret** dev constant
  `K_dev` (B §3 / §6 here), so `cargo run` / `cargo test` decrypt with zero
  wiring. A **debug build is self-decrypting and must never be distributed**; C
  promotes that from prose to a **checkable guard** (§7).
- **Production** — CI builds release supplying the operator's key from a secret
  store; the same value reaches the runtime provider out-of-band. The attacker
  holds **the shipped binary only**; the release binary is mute and free of
  litmask-identifying strings.
- **Layer consequence** — a consumer crate depends only on the **masking core**
  (`litmask` + `litmask-build`); the **distribution tool** (`litmask-cli`) is an
  operator-side binary the consumer never links. The decl_blob (§3) is the *only*
  channel by which the tool learns anything the consumer's source said — there is
  no other back-door from runtime types into the offline tool (the Rust
  compilation-unit wall, §2.3).

## Foundation (inherited from B, stated for portability)

C inherits **all** of B's Foundation (B.1–B.4) unchanged. Restated so this spec is
implementable without B open:

- **C.1 (inverted key, = B.1):** the `unlock_key` is an **operator-supplied
  input**, never a build output. The build seals `mask_key` under the supplied
  key.
- **C.2 (derived locator, = B.2):** the locator is `KDF(unlock_key,
  "litmask-locator-v1")`, recomputed by build / runtime / CLI; **no metadata file
  exists.**
- **C.3 (opaque wrapper, = B.3 / B §2.5):** `nonce(12) ‖ AEAD(version_byte ‖
  mask_key)(33) ‖ tag(16)` = **61 bytes**, no plaintext header; cipher recovered by
  trial-decrypt (AEAD tag = discriminator).
- **C.4 (mute release failure paths, = B.4):** release runtime failures stay bare
  (`panic!()` / `Err(Decryption)`), no identifying text.
- **C.5 (reseal-default deployment, = B §4):** one universal build under a
  `build_key`, resealed per customer under each `unlock_key`; per-customer *builds*
  reserved for differing content or leak attribution.
- **C.6 (no-argv secrets + four-outcome verify, = B §8 / §5.2):** secret key input
  only via env/file/stdin, never `--key <value>`; `verify` reports
  coherent / locator-absent / key-fails / indeterminate over four exit codes.

**C adds one wire-format element** to B's binary layout: the **decl_blob**, an
AEAD-sealed declaration of the runtime's key-acquisition intent (§3). Layout
becomes `locator(12) ‖ wrapper(61) ‖ decl_blob`. The decl_blob is sealed under
**`mask_key`** (not `unlock_key`), so it is **invariant across reseal** (reseal
re-keys only the wrapper, B §6.2) and an attacker without the key sees it as more
high-entropy bytes — the scrub invariant (B §2.2) is preserved.

## 1. Layer Model (the two-layer split)

- **1.1 (masking core vs distribution tool — normative)**: litmask is specified as
  **two layers with one wire contract between them**:
  - **Masking core** — what a *consumer crate* compiles against: the `litmask`
    runtime (providers, `init!`, `mask!*`), `litmask-build::emit()`, and the
    `litmask-macros` proc-macro. Its job: turn source literals into an opaque
    embedded region and decrypt them at runtime under an operator-owned key.
  - **Distribution tool** — what an *operator* runs: `litmask-cli` (`verify`,
    `reseal`, `keygen`, `derive`, `show-machine-id`). Its job: re-key and
    validate **already-built** binaries. It never compiles, never links the
    consumer crate, and learns about a binary **only** by reading the wire format.
  - **Shared contract** — `litmask-internal` is **neither layer**; it is the wire
    contract **both** layers depend on (the layout, KDF/AEAD schemes, locator
    `info` strings, and decl_blob schema, §1.2 / §3.2). Filing it under either layer
    misstates the dependency (C-I): the masking core *writes* what the contract
    defines and the distribution tool *reads* it, so the contract sits between them
    and is the single point where drift becomes a `litmask-internal` test failure.
- **1.2 (the wire contract is the only coupling — normative)**: The sole interface
  between the layers is the embedded region `locator ‖ wrapper ‖ decl_blob` and the
  KDF/AEAD schemes that produce it, all defined in `litmask-internal`. The CLI MUST
  derive everything it reports from that region plus the supplied key — never from
  consumer source, build metadata, or runtime type information (none of which it
  can see, §2.3). `litmask-internal` is the single source of truth for the layout,
  the locator-derivation `info` strings, the cipher set, and the decl_blob schema
  (§3.2); both layers depend on it so they cannot drift.
- **1.3 (why name it)**: B's friction walk showed the CLI and runtime silently
  disagreeing about what a wrapper means (e.g. whether a locator-only match
  "counts"). Naming the layers and pinning the contract in one crate makes such
  drift a compile/test failure in `litmask-internal`, not a field bug. This is a
  **framing/organizational** requirement; it introduces no new runtime mechanism
  beyond the decl_blob (§3).

## 2. Single Provider Site (declarative `init!`, `init_with!` removed)

- **2.1 (one provider-declaration site — normative)**: A consumer declares its
  key-acquisition intent at **exactly one** place: a single source-level `init!`
  invocation. `build.rs` supplies **key bytes only** (`emit()` reads
  `LITMASK_UNLOCK_KEY`, C.1) and declares **no** provider. The legacy `init_with!`
  (runtime-constructed provider passed in by value) is **removed**. There is no
  second site to diverge from (closes RT-2 / B §4.4.1's three-site hazard at the
  source).
- **2.1.1 (multiplicity — normative, C-E)**: "Exactly one" is specified, not merely
  recommended:
  - **one `init!`** → the decl_blob records that single declaration (the intended
    path).
  - **zero `init!`** (a consumer that calls `mask!` but relies on the lazy/implicit
    default) → **no decl_blob is emitted** (§3.6); the binary is B-valid and C-valid,
    but alignment is permanently *indeterminate* for it (§4.2.2). This is the
    **lazy-default residual** (§8.6): a consumer who never writes `init!` silently
    gets B-parity tooling, not C's offline alignment. Documented, not an error.
  - **more than one `init!`** → the macro emits **at most one** decl_blob and the
    build MUST hard-error on a second `init!` expansion (a per-build flag in the
    proc-macro / `litmask-internal`), because two declarations could disagree and
    there is exactly one embedded decl slot. Multiple sites are a build failure, not
    a last-writer-wins race.
- **2.2 (the three declaration forms — normative)**: `init!` takes one of three
  forms, in increasing escape-hatch order:

  ```rust
  litmask::init!()?;                                   // (a) default
  litmask::init!(source: machine_id("cryptio-v1"))?;   // (b) built-in, named
  litmask::init!(custom: VaultProvider::new("…"))?;    // (c) custom, opaque
  ```

  - **(a) `init!()`** — the default: read `LITMASK_UNLOCK_KEY` via the built-in
    `EnvVarProvider`. **Precise declaration:** decl = `env:LITMASK_UNLOCK_KEY`.
  - **(b) `init!(source: <built-in>)`** — a built-in selector litmask itself
    constructs: `env("NAME")`, `file("path")`, `machine_id("salt")`. **Precise
    declaration:** decl names the exact source (`env:NAME`, `file:path`,
    `machine_id:salt`). Because litmask constructs the provider from a
    *macro-visible literal*, the macro can record the source faithfully (§3.3). **The
    argument MUST be a string literal (C-F):** the macro records the source only if it
    can read the bytes at expansion time. A non-literal (a `const`, an expression, an
    interpolation) is a **compile error** directing the author to a literal or to form
    (c) — the macro MUST NOT silently emit a `custom` decl for a `source:` form, which
    would make the precise/imprecise boundary depend on invisible const-ness.
  - **(c) `init!(custom: <expr>)`** — an arbitrary runtime expression evaluating to
    a `KeyProvider`. **Imprecise declaration:** decl = `custom` (no parameters; the
    expression is runtime data the macro cannot evaluate). Alignment for custom
    decls is *indeterminate* (§4.4) — this is the documented escape hatch, not a
    regression.
- **2.3 (why the declaration cannot live in `build.rs` — normative rationale)**:
  `build.rs` is a **separate compilation unit** that runs *before and apart from*
  the consumer crate; it cannot name the consumer's provider types and any value it
  constructs cannot cross into the runtime binary. A custom provider's *fetch code*
  (vault round-trip, HSM call) must be compiled **into the deployed binary** to run
  at startup, so it must originate in consumer **source**, not the build script.
  This is why **all** provider declaration is anchored at the source `init!` and
  `build.rs` stays bytes-only: it is the only site that can express built-in *and*
  custom uniformly. (Stated because the constraint is the design's load-bearing
  reason, not an incidental choice.)
- **2.4 (default-name coherence, = B.1.1 — normative)**: Form (a) and the
  build-time default and `verify`'s default MUST all read `LITMASK_UNLOCK_KEY`. A
  custom env name is set on **both** the build (`emit().key_var("X")`) and the
  source (`init!(source: env("X"))`); the decl records `env:X` so the CLI reads the
  same name (§4.2).
- **2.5 (init exit-code accuracy, = B §5.6 — normative)**: `init!(…)?` with a bare
  `?` yields Rust's default `Err` termination (exit 1, `Debug`-printed variant), not
  a sysexit. At least one example MUST map `InitError` to `sysexit_code()`
  (returning `ExitCode`); docs distinguish the `?`→exit-1 path from the
  explicit-mapping→`sysexits` path. (Carried from B; the macro rename
  `init_with!`→`init!` does not change this.)
- **2.6 (debug zero-wiring interaction, = B §3.8 — normative)**: A debug `cargo
  run` whose declared source is `machine_id(…)` is **not** rescued by `K_dev` (the
  provider returns a derived key that fails to decrypt until resealed, B §3.2). The
  zero-wiring rescue fires only on `KeyError::NotFound` (B §3.2 / §6.2 here). Docs
  state: in the dev loop use form (a)/`env` or reseal under the machine key. A
  **custom** provider that errors with anything *other than* `NotFound` on a
  missing source likewise breaks dev zero-wiring — an accepted, documented papercut
  of the escape hatch (§8 residuals).

## 3. The Declaration Blob (decl_blob)

- **3.1 (purpose)**: The decl_blob is the **recoverable record of the §2
  declaration**, embedded so the offline distribution tool can read the runtime's
  *intended* key source without executing the binary — the property B proved
  impossible without such a record (B §4.4.1). It powers `verify --check-alignment`
  (§4.4) and `reseal --to-machine-id`'s mismatch refusal (§5).
- **3.2 (layout & schema — normative, fixed-size)**: The embedded region becomes
  `locator(12) ‖ wrapper(61) ‖ decl_blob`, where the decl_blob is a **constant total
  size** `nonce(12) ‖ AEAD_mask_key(decl_plain[L_decl]) ‖ tag(16)` = `12 + L_decl +
  16` bytes for a fixed `L_decl` pinned in `litmask-internal`. **Fixed size is
  load-bearing** (C-B): the wrapper carries no stored length and is delimited as "the
  next 61 bytes" (B §2.5.5); a *variable-length* trailing decl_blob would reintroduce
  a length boundary the reader must store or guess, breaking that opacity discipline
  and the scrub invariant. Instead the decl is **padded inside the AEAD** to `L_decl`
  and the padding is **authenticated** (it is part of the sealed plaintext), so the
  reader takes a constant-width tail and the pad is indistinguishable from the payload
  to anyone without `mask_key`.
- **3.2.1 (canonical, length-prefixed plaintext — normative)**: `decl_plain` is
  `version_byte ‖ canonical_encoding ‖ zero_pad` to `L_decl`. `canonical_encoding`
  is a **length-prefixed** encoding (each variable field carried as `len ‖ bytes`,
  C-G) of one of: `{kind: machine_id, salt}`, `{kind: env, name}`, `{kind: file,
  path}`, `{kind: custom}`. Length-prefixing (not delimiter-joined concatenation)
  is required so distinct fields can never alias into the same byte string — the
  same domain-separation hazard §3.4 fixes for the nonce. The `version_byte` is the
  decl-schema version, authenticated inside the AEAD exactly like the wrapper's
  version byte (B §2.5.3); it is **never in the clear** (§3.7). The schema and
  `L_decl` live in `litmask-internal` (§1.2). The decl_blob carries **no plaintext
  header** and its cipher matches the wrapper's (no independent cipher selection).
- **3.2.2 (minimal schema first — normative scope, C-C)**: The decl payload ships
  **minimal**: the discriminating fields §5.2 (reseal refusal) and §4.2 (alignment
  with `--expect-source`) actually consume — **`kind` plus the `machine_id` salt**.
  `env` name and `file` path are recorded when present (they make `--expect-source`
  exact), but the schema is deliberately **not** a general key-value bag; fields are
  added only when a verb consumes them. This keeps `L_decl` small and the decl from
  over-building beyond what the two reader verbs need.
- **3.3 (sealed under `mask_key`, not `unlock_key` — normative, load-bearing)**:
  The decl_blob is encrypted under **`mask_key`** (the per-build content key), not
  the `unlock_key`. Two consequences this choice is *for*:
  - **Reseal-invariant.** Reseal re-keys only the wrapper (`unlock_key`→new
    `unlock_key`, B §6.2); `mask_key` is unchanged by reseal. So the decl_blob
    **survives every reseal untouched** — the declaration is a property of the
    *build*, not of any customer's key, which is correct (the runtime asks the same
    source regardless of which customer's key opens the wrapper).
  - **Reader path.** A reader recovers the declaration via
    `unlock_key → decrypt wrapper → mask_key → decrypt decl_blob → declared source`.
    Holding the `unlock_key` is therefore required to read the decl — the same
    key-holder gate as everything else (an attacker without the key sees only
    entropy, B §2.2). The proc-macro, which **already holds `mask_key`** to seal the
    per-site blobs, emits the decl_blob in the same pass — no new secret crosses any
    boundary.
- **3.4 (nonce domain separation — normative)**: The decl_blob nonce is derived
  with a **reserved site-id** distinct from every real call site: `nonce =
  KDF(len(seed)‖seed ‖ len("decl")‖"decl" ‖ len(decl_plain)‖decl_plain)` truncated to
  nonce width — the B §7.2-style derivation with a reserved `"decl"` site-id and the
  fixed-size `decl_plain` (§3.2.1) standing in for "plaintext", **length-prefixed at
  every field** (C-G) so no concatenation can alias another input. The same
  length-prefixing MUST be applied to the per-site masked-literal derivation
  `KDF(seed ‖ site-id ‖ plaintext)` (B §7.2 / §6.3) for the identical reason. This
  guarantees the decl_blob nonce can never collide with a masked-literal nonce,
  preserving the structural nonce-reuse safety of B §7.2.
- **3.5 (the macro writes, the CLI reads — single producer/consumer — normative)**:
  The decl_blob is **written only by `litmask-macros`** (at the `init!` site, where
  the declaration is syntactically present) and **read only by `litmask-cli`** (and
  optionally `verify` self-checks). The runtime does **not** read its own decl_blob
  to choose a provider — the provider is already compiled in from §2; the decl_blob
  is purely an *out-of-band record for tooling*. (Avoids a circular "runtime reads
  decl to pick provider" design, which would re-introduce build-emitted provider
  selection — explicitly out of scope, B Out-of-Scope.)
- **3.6 (absence is a valid state — normative)**: A binary built by a consumer that
  calls `mask!` but never `init!` (relying on lazy/implicit default) has **no
  decl_blob**. Tooling MUST treat a missing decl_blob as decl = *unknown* (not an
  error), and `--check-alignment` returns *indeterminate* for it (§4.4), exactly as
  for a `custom` decl. This keeps the decl_blob **additive**: every B-valid binary
  remains C-valid.
- **3.7 (scrub invariant — MUST)**: A release binary's decl_blob region MUST be
  indistinguishable from random (no plaintext schema tag, no litmask constant), on
  the same footing as the wrapper (B §2.2 / §3.5). The decl-schema version byte
  lives **inside** the AEAD payload (§3.2), never in the clear.

## 4. Coherence, Alignment & Failure Diagnostics

C keeps B §5 verbatim — `verify` is keyed decrypt-success by default, four
outcomes, four exit codes, debug provider-source naming, verify-against-runtime-key,
machine-id off-box handling, `--deny` lock-out — and **adds one opt-in axis**.

- **4.1 (default `verify` unchanged, = B §5.1/§5.2)**: `litmask verify <binary>`
  defaults to the authoritative **decrypt-success** check (coherent / locator-absent
  / key-fails / indeterminate). The decl_blob is **not** consulted by default.
- **4.2 (`--check-alignment` — opt-in additive axis, normative)**: `litmask verify
  <binary> --key-… --check-alignment` additionally reads the decl_blob (§3.3) and
  **reports the declared key source**. It is a **separate, additive verdict** layered
  on top of the decrypt-success verdict — it does **not** change the default verdict
  (a dry-walk correction: baking alignment into the default either breaks vault
  shops, always-indeterminate and thus can't gate, **or** gives false confidence by
  marking a custom-coherent binary "coherent" when the runtime may ask a different
  source — the F7 trap).
- **4.2.1 (the tool compares source-KIND, never key-VALUE — normative, C-A)**: The
  alignment axis can **only** establish *which source-kind the runtime will request*
  (from the decl); it can **never** establish that the key *bytes* the operator holds
  equal the production source's value — the tool holds 32 opaque key bytes and cannot
  know their provenance. Critically, alignment MUST NOT be **inferred from the
  `--key-…` channel** the operator used to supply those bytes. The off-box verify
  flow (B §5.5) feeds a machine-id binary's key over whatever channel is convenient
  on the operator's *trusted* host (e.g. deriving it with `--machine-id`/`--salt`);
  the channel is an offline operator-side convenience and reveals nothing about the
  deployed binary's *runtime* source. Inferring "supplied via env ⟹ runtime reads
  env" would false-positive *misaligned* whenever an operator legitimately
  pre-derives a machine key and pipes it in. (This is the corrected scope: an earlier
  draft over-claimed that `--check-alignment` validated the supplied key against the
  channel — it cannot, and machine-binding remains a **runtime** property the tool
  never weakens.)
- **4.2.2 (hard-check only against explicit `--expect-source` — normative)**: To get
  a *pass/fail* alignment verdict (not just a report), the operator states the
  expectation **explicitly**: `--check-alignment --expect-source <kind[:param]>`
  (e.g. `--expect-source machine_id:cryptio-v1`). The tool then compares the **decl**
  to the **declared expectation** — both sides independent of whatever `--key-…`
  channel supplied the bytes. Behavior by decl kind:
  - **built-in (`env`/`file`/`machine_id`)** → comparison is **authoritative**: decl
    vs `--expect-source` is *aligned* / *misaligned* with certainty (e.g. decl
    `machine_id:cryptio-v1` vs `--expect-source env:LITMASK_UNLOCK_KEY` →
    **misaligned**), catching B's silent footgun **offline** without touching the
    supplied key.
  - **custom or absent** → **indeterminate** (§3.6): the decl carries no source the
    tool can compare; it reports *indeterminate*, never *aligned*, and points at
    execute-locally (B §4.4.2). It MUST NOT pose as having validated a custom
    provider.
  Without `--expect-source`, `--check-alignment` is **report-only** (prints the decl,
  contributes no pass/fail), so it can never false-positive off the key channel.
- **4.3 (alignment outcome encoding — normative)**: `--check-alignment` contributes
  its own outcome on a distinct axis (e.g. an additional summary line and a
  documented exit-code policy when combined with `--deny`/decrypt-success).
  **Report-only** alignment (no `--expect-source`, §4.2.2) prints the decl and
  contributes **no** pass/fail — it can never fail a run. Only `--expect-source`
  makes the axis gateable: the run fails (non-zero) if a built-in decl **mismatches**
  the stated expectation; an *indeterminate* alignment axis (custom/absent, or
  report-only) does **not** by itself fail the run. Documentation states the exact
  combined exit-code table so a custom-provider shop can still gate on
  decrypt-success + `--deny` while ignoring an always-indeterminate alignment axis.
- **4.4 (alignment complements, never replaces, execution — normative honesty)**:
  `--check-alignment` is a **cheap offline early-warning**, authoritative only for
  built-in decls. For custom providers and for the final word on *any* deployment,
  **executing the binary** (B §4.4.2) remains the authority. Documentation MUST
  state: (a) alignment's value is proportional to built-in-provider usage; (b) a
  vault/HSM shop sees only *indeterminate* and loses nothing relative to B; (c)
  *aligned* on a built-in decl proves the runtime will **request** the right source,
  which `verify` decrypt-success alone never proved (B §5.5) — this is the concrete
  win C adds over B, scoped honestly.
- **4.5 (debug provider-source naming, = B §5.3)**: In debug only, a key failure
  not rescued by `K_dev` names the provider-specific source — sourced from the
  provider's own `source_hint()` (default `None`, non-breaking), **not** from the
  decl_blob. **The runtime cannot read its own decl_blob on the failure path** (C-H):
  the decl_blob is sealed under `mask_key`, and recovering `mask_key` requires first
  opening the wrapper with the key that just failed (or `K_dev`, which also failed in
  this branch) — so at the moment diagnostics are needed, `mask_key` is unavailable.
  Decl-enriched diagnostics are therefore **CLI-only**: the key-holding CLI (which
  *can* open the wrapper) may name the declared source when reporting
  `locator-absent`. The **release runtime** abort stays mute regardless (C.4).

## 5. Reseal With Declaration Awareness

C keeps B §6.2's `reseal` verb and adds decl-driven safety to the machine-id path.

- **5.1 (`reseal` core, = B §6.2)**: `litmask reseal <binary> --from <keysrc> --to
  <keysrc> [-o <out>]` re-keys the wrapper and its derived locator; `mask_key`,
  blobs, **and the decl_blob (§3.3)** are unchanged. Machine-id target:
  `reseal … --to-machine-id <id> --salt <s>` (subsumes legacy `bind`).
- **5.2 (`--to-machine-id` mismatch handling — decl-driven, normative)**: When the
  target is a machine key (`--to-machine-id`), `reseal` reads the decl_blob (§3.3)
  and acts on the **declared** source:
  - **declared `machine_id:<salt>`** and the reseal salt **matches** → proceed
    silently (the runtime will request the machine key; the reseal is coherent).
  - **declared a *different* built-in (`env`/`file`, or `machine_id` with a
    different salt)** → **refuse by default** (non-zero exit, clear message): the
    runtime will not request a machine key, so the resealed artifact would never
    self-decrypt on the bound host — exactly B's silent footgun, now caught **at
    reseal time**. An explicit `--force` override proceeds with a loud warning for
    the operator who knows better (e.g. is about to rebuild with a matching decl).
  - **declared `custom` or decl absent (§3.6)** → **warn, do not refuse**: the tool
    cannot know what a custom provider will request; it emits the B §6.2 non-secret
    notice ("self-decrypts on the bound host only if built with a machine-id-aware
    provider") and points at execute-locally (B §4.4.2). (Dry-walk correction:
    refusal is **automatic for built-in mismatches, warn-only for custom** — refusing
    custom would block legitimate vault-then-machine-id hybrids the tool can't reason
    about.)
- **5.3 (reseal never weakens B's guarantees)**: The decl-driven refusal is an
  **added** guard; everything B §6.2 promised (re-key correctness, `--deny`
  lock-out validation per B §5.7) is unchanged. `--force` recovers exactly B's
  prior unconditional behavior for the operator who opts out.

## 6. Inherited Mechanisms (carried from B; §6.7 is a C addition)

These sections are inherited **verbatim** from B; they are listed so an
implementer sees the complete surface. Where C touches one, the delta is noted.
**§6.7 is a genuine C refinement** of B's seed handling (per-customer seed model),
not an inheritance.

- **6.1 (Debug zero-wiring `K_dev`, = B §3)**: per-crate non-secret `K_dev` rescues
  `KeyError::NotFound` in debug; release absence is a **hard build error** gated on
  `PROFILE` (fail toward Release); zero `K_dev` bytes in release (scrub). **C
  delta:** none to the mechanism; §2.6/§7 add the decl/workflow interactions.
- **6.2 (Deployment shape, = B §4)**: reseal-default; `build_key` is a
  plaintext-equivalent dedicated key (never ships, opens no shipped binary);
  per-customer builds opt-in for differing content / attribution; machine-id
  deployment via `derive machine-key` (§6.8) + `reseal --to-machine-id`. **C delta:**
  §5.2 adds decl-driven `--to-machine-id` safety; §4.4 adds the alignment
  early-warning.
- **6.3 (Seed & reproducibility, = B §7)**: decrypt-repro is free (owned key);
  per-site nonces `KDF(seed ‖ site-id ‖ plaintext)` (structural nonce-reuse safety,
  extended to the decl_blob by §3.4); seed never persisted/logged (S1 fix); bit-repro
  is opt-in `LITMASK_RNG_SEED`. **Observed (current
  `litmask-build/src/lib.rs:258`):** a malformed pinned seed already hard-fails the
  build (panic, exit 101) — correct direction — but the message omits the 32-byte
  length and a `seed`/`keygen` pointer; closing that is implementation work. **C
  delta:** §6.7 refines the *per-customer* seed story (derive-from-master) — the
  base decrypt-repro / nonce / S1 mechanics here are unchanged.
- **6.4 (Secret input channels, = B §8)**: secret key input only via env / `--key-file`
  / `--key-stdin` (per-role `--from-…`/`--to-…`/`--deny-…`/`--key-…`), **never
  `--key <value>`**; secret-emitting verbs print only the value; build-time
  injection from a secret store. **C delta:** none.
- **6.5 (Diagnostics gating, = B §9)**: loud debug strings + `K_dev` value/branch
  gated on `PROFILE`-derived `cfg`, absent from release. **C delta:** the decl_blob
  is present in **both** profiles (it is not a debug-only diagnostic — it is the
  tool's contract), but it is opaque in release (§3.7), so it adds no
  release-distinguishing string.
- **6.6 (CLI surface, = B §6 header + C consolidation)**: the distributable CLI is
  **{`verify`, `reseal`, `keygen`, `derive`, `show-machine-id`}**, configless, no
  `run`/no compile. **C delta:** `verify` gains `--check-alignment` (§4.2); `reseal`
  gains decl-driven `--to-machine-id` refusal + `--force` (§5.2); and all KDF-output
  derivations consolidate under **one `derive` verb** (§6.8) — which **subsumes B's
  `machine-key` verb** (now `derive machine-key`), provides B's named-but-absent seed
  deriver (`derive seed`, §6.7.3), and adds content-key derivation
  (`derive mask-key`). `keygen` still **mints** random roots (`unlock_key`,
  `build_key`, `master_seed`); `derive` only **computes** KDF outputs. There is
  deliberately **no `derive unlock-key`** (§6.8.3).

## 6.7 Per-Customer Seed Model (derive-from-master) — C addition

Scope: this section governs **per-customer-*build* mode only** (§6.2 / B §4.3 —
the opt-in path for differing content or leak attribution). Reseal-default (B §4.2)
**shares** `mask_key` across customers by design and needs none of this.

- **6.7.1 (`mask_key` uniqueness is governed by the seed — normative restatement)**:
  `mask_key` derives from the build `seed` and is **independent of `unlock_key`**
  (proven by the reseal invariant, B §4.2: reseal swaps `unlock_key` yet leaves
  blobs unchanged, so the blobs — and thus `mask_key` — cannot depend on
  `unlock_key`). Therefore: **unique blobs per customer ⟺ unique `mask_key` ⟺ unique
  `seed`**, and **reproducing** a customer's exact binary (patch rebuild, or
  attribution-matching a leaked binary) ⟺ **pinning that customer's `seed`** via
  `LITMASK_RNG_SEED` (B §7.4 — the build already respects this; no build change).
- **6.7.2 (derive per-customer seeds from one master — normative)**: C derives each
  per-customer seed as `customer_seed = KDF(ikm = master_seed, info = "litmask-seed-v1"
  ‖ customer-id)` rather than minting and storing N independent seeds. The operator
  stores **one** `master_seed` (`unlock_key`-grade) plus a list of **non-secret**
  `customer-id` labels. Any customer's seed is recomputed on demand, yielding a
  **deterministic, unique `mask_key` per customer**, reproducible for attribution,
  **without custody of N master secrets**.
- **6.7.3 (one derive verb, no mint verb — normative; reconciles B's latent gap)**:
  A seed is 32 random base64url bytes — identical to a `keygen` value; a seed is "a
  `keygen` value in the seed role," exactly as `build_key` is "a `keygen` value in
  the build-key role" (B §4.1.1). So C adds **no seed-*mint* verb** — a `master_seed`
  is minted with `keygen`. The per-customer seed is a target of the consolidated
  `derive` verb (§6.8): `litmask derive seed --from-master <keysrc> --label
  <customer-id>` prints the derived per-customer seed (per §6.4 / B §8.3 secret-emit
  discipline), a sibling of `derive machine-key` deriving a machine key from a
  machine-id. This **resolves B's inconsistency** (B §7.4 named a `seed` verb absent
  from the §6 CLI surface): the operation exists as a `derive` target, and it
  **derives**, it does not mint.
- **6.7.4 (`master_seed` is the one secret; `customer-id` is not — normative)**:
  `master_seed` derives every per-customer `mask_key`, so it is stored
  `unlock_key`-grade and travels only via §6.4 channels (env/file/stdin, never
  argv). `customer-id` is a **non-secret** label (e.g. `"bob"`, an order id) and may
  be recorded in the clear. Leaking a `customer-id` reveals nothing; leaking
  `master_seed` exposes every per-customer build's plaintext (which the operator
  authored anyway) — so derive-from-master reduces the secret-custody surface from
  **N seeds to one**, the central reason to prefer it over store-N.
- **6.7.5 (attribution record is labels, not secrets — normative; the lightweight
  ledger)**: Per-customer-build attribution (B §4.3(b)) needs a customer→build
  record. Under derive-from-master that record is the `(customer-id, fingerprint,
  date)` tuple plus a **single `master_seed` reference** — **no per-customer secret
  material**. To attribution-match a leaked binary: recompute each candidate's seed
  (`derive seed --from-master MASTER --label <c>`), re-derive its fingerprint, and
  compare.
  This is the **lightweight form** of the build-identity ledger the prior specs left
  out of scope; C states the record *shape* but does not build a managed store (Out
  of Scope).
- **6.7.6 (pinned-seed nonce-reuse safety preserved — normative)**: A derived seed
  feeds the same per-site nonce derivation as any seed (B §7.2:
  `nonce = KDF(seed ‖ site-id ‖ plaintext)`), so the structural nonce-reuse safety
  holds per customer; two customers' identical literals get **different** nonces
  because their derived seeds differ, and the §3.4 decl_blob nonce stays
  domain-separated within each.

## 6.8 The `derive` Verb (consolidated KDF outputs) — C addition

- **6.8.1 (one verb for every derivation — normative)**: All deterministic
  KDF-output derivations live under a single `litmask derive <target>` verb, so the
  surface separates by role: `keygen` **mints** random roots, `derive` **computes**
  KDF outputs from them, `reseal`/`verify` operate on **binaries**, and
  `show-machine-id` reads a **non-secret identity**. Targets:
  - `derive mask-key --seed <keysrc>` — the per-build **content key**,
    `mask_key = KDF(seed)` (§6.8.2).
  - `derive seed --from-master <keysrc> --label <id>` — a **per-customer seed**,
    `KDF(master_seed, customer-id)` (§6.7).
  - `derive machine-key --machine-id <id> --salt <s>` — a **machine key**, the same
    KDF the runtime `MachineIdProvider` uses. This **subsumes B's `machine-key`
    verb**; together with `bind` → `reseal --to-machine-id`, these are the two B-verb
    renames C makes.
- **6.8.2 (`derive mask-key` — content-key derivation, normative)**:
  `mask_key = KDF(seed)` is the **existing build derivation** (B §7.2 derives
  `mask_key` and per-site nonces from the seed); `derive mask-key` merely **exposes**
  it for inspection, test vectors, and tooling. It grants **no capability a
  seed-holder lacks** — anyone with the seed can already recompute `mask_key` and
  decrypt the blobs — so it is a convenience, not a new attack surface. It is
  secret-emitting (the value opens every blob) and obeys §6.4/B §8.3 egress (stdout
  only, never argv, never shared/CI logs).
- **6.8.3 (no `derive unlock-key` — normative, model invariant)**: There is
  deliberately **no `unlock-key` target**, and in particular no `--seed` path to one.
  Under the inversion (C.1) `unlock_key` is an **operator-supplied input**,
  independent of the seed by construction — and that independence is exactly what
  delivers free rebuild (B §7.1), reseal (B §4), and the property that **leaking the
  seed does not open a shipped binary** (the seed reveals plaintext, but cannot
  derive the `unlock_key` that seals and locates the wrapper). Deriving
  `unlock_key = KDF(seed)` would **fuse the content-root and access-root**, revert C
  to the build-generated model, and re-introduce the per-customer cascade that
  `keygen`-per-customer (B §6.1) and build_key-distinctness (§4.1.2) exist to
  prevent. An operator who wants **deterministic** per-customer `unlock_key`s derives
  them from a **separate access-master** (`KDF(unlock_master, customer-id)`), **never
  from the content seed**, keeping the two roots independent — a provisioning policy
  outside the binary that `keygen` + an off-box KDF already cover. (Were such a verb
  ever added it would be `derive unlock-key --from-master`, never `--seed`.)
- **6.8.4 (secret egress — normative)**: Every `derive` target emits a **secret**
  (`mask_key`, a per-customer `seed`, a machine key) and prints **only** the value to
  stdout (§6.4/B §8.3); none accept a secret over argv. `show-machine-id` remains the
  one non-secret reader and is exempt.

## 7. Debug-Never-Ship Workflow Guard

- **7.1 (the hazard B documents but does not check)**: B §3.6 states a debug build
  is self-decrypting (carries `K_dev` + ciphertext) and **must not be
  distributed**, but leaves that to documentation. The single worst operator
  mistake in the reseal-default flow is shipping the wrong artifact; "debug build
  reached a customer" is its most dangerous instance (the customer gets a
  self-decrypting binary, defeating the whole point). C makes it **checkable**.
- **7.2 (the primary gate: a debug build cannot be resealed — normative, C-D)**: The
  **reliable** catch needs no new mechanism and no `CARGO_PKG_*`: a debug build is
  `K_dev`-sealed (B §3.1), not `build_key`-sealed, so the mandatory pipeline step
  `reseal --from-env BUILD_KEY` (§9.4) **fails to open it** — the wrapper does not
  decrypt under `build_key`. The reseal-default flow already runs this on every
  artifact, so a debug build entering the pipeline is caught **by construction**,
  with the key the operator already holds. This, plus the B §5.7 `--deny BUILD_KEY`
  lock-out, is the gate the workflow leans on.
- **7.3 (`verify` may *additionally* flag a debug build — normative, best-effort)**:
  As a secondary, best-effort signal, `litmask verify` MAY attempt the `K_dev`
  locator for the crate and, on a match, report a distinct *debug-build
  (self-decrypting, do not distribute)* outcome. **This is advisory, not the gate**
  (C-D): `K_dev` is recomputed from `CARGO_PKG_*` (B §3.3), which a release/stripped
  binary may not expose to the tool, so the check can silently **no-fire** when crate
  identity is unavailable. It MUST therefore never be the *only* thing standing
  between a debug build and a customer — §7.2's reseal-open failure is. When crate
  identity *is* supplied/discoverable the extra keyed locator scan is a cheap early
  warning; when it is not, the pipeline still catches the build at §7.2.
- **7.4 (guard is detection, not prevention)**: C does **not** prevent a developer
  from copying a debug binary by hand; it makes the mistake **loudly detectable** —
  primarily at the reseal step (§7.2), secondarily at verify (§7.3) — which is where
  the reseal-default pipeline already pauses. This is proportionate (reuse of an
  existing pipeline step), not heavyweight (no new build machinery, no signing).
  Documented as such.

## 8. Honest Residuals (documented, not solved)

C narrows B's sharpest edge but does not erase the underlying constraints. These
MUST be documented so the spec does not over-promise:

- **8.1 (custom providers degrade to B-parity)**: A `custom` decl (§2.2c) yields
  *indeterminate* alignment (§4.4) and warn-only reseal (§5.2); B's execute-locally
  proof (B §4.4.2) remains the sole authority. A pure-vault/HSM shop gains **nothing**
  from C's declarative machinery and loses nothing relative to B. C's value is
  **proportional to built-in (env / file / machine-id) provider usage** — stated
  plainly, not buried.
- **8.2 (`K_dev` rescues only `NotFound`)**: §2.6 / B §3.2. A custom provider that
  errors with anything other than `KeyError::NotFound` on a missing source breaks
  debug zero-wiring (the rescue can't fire). The escape hatch's papercut, accepted.
- **8.3 (decl is intent, not a runtime contract)**: The decl_blob records what the
  source `init!` *declared* (§3.5); it does not *bind* the runtime (the runtime's
  provider is the compiled-in code, not the decl). A consumer who hand-rolls a
  provider that ignores its own declared source can still diverge — but C makes the
  honest path (declare via `init!`) the only ergonomic one and removes `init_with!`
  (§2.1), so divergence now requires going out of one's way. Alignment is therefore
  *strong evidence*, not *proof*, for built-ins; *no evidence* for custom.
- **8.4 (debug self-decrypting, never distribute)**: §7 detects but does not prevent
  (§7.4). The caveat from B §3.6 stands and is recorded in THREAT_MODEL.md.
- **8.5 (build host trust boundary)**: unchanged from B — the host holding all
  customers' keys and `build_key` is an accepted, documented trust boundary
  (THREAT_MODEL.md). `build_key` remains plaintext-equivalent (B §4.2.1).
- **8.6 (lazy-default consumers get B-parity tooling)**: A consumer that calls
  `mask!` but never writes `init!` (relying on the implicit default, §2.1.1) emits
  **no decl_blob**, so alignment (§4.2.2) and decl-driven reseal refusal (§5.2) are
  permanently *indeterminate* for that binary — it degrades cleanly to B. C's offline
  alignment win is **opt-in via writing `init!`**; the lazy path is not penalized, but
  it is not upgraded either. Documented so the win is not over-claimed as automatic.

## 9. Examples, Fixtures & Documentation

Inherits B §10 and adds the C-specific surfaces:

- **9.1 (single fixtures source, = B §10.1)**: each example declares its masked
  fixtures in one source of truth the scrub test consumes.
- **9.2 (run docs, = B §10.2)**: debug = plain `cargo run`, zero wiring; release
  verification supplies the owned key over a §6.4 channel — no awk, no metadata
  file.
- **9.3 (declarative `init!` shown, C-new)**: at least one example uses each of the
  three §2.2 forms — `init!()` (default env), `init!(source: machine_id(…))`
  (built-in named), and `init!(custom: …)` (escape hatch) — and documents the
  alignment consequence of each (`env`/`machine_id` → authoritative; `custom` →
  indeterminate). Documentation shows that `init_with!` **no longer exists** and how
  to port each old call to the new form.
- **9.4 (reseal-default pipeline end-to-end, = B §10.5 + C guards)**: `keygen` per
  customer into the secret store → one universal `cargo build --release` under
  `build_key` → `reseal` per customer (a debug build fails to open here — the
  primary debug-build gate, §7.2) → `verify` each with **`--deny-env BUILD_KEY`
  (lock-out, B §5.7) and the best-effort §7.3 debug flag**, plus **`--check-alignment
  --expect-source <kind>` where the decl is built-in** (§4.2.2) → inject each customer
  key into its runtime provider. The pipeline gates on decrypt-success + lock-out +
  reseal-open for every shop, and additionally on alignment for built-in-provider
  shops.
- **9.5 (dev-vs-release split, = B §10.3)**: why release is mute, why debug is loud
  and self-decrypting under `K_dev` (and §7 detects it), how coherence + alignment
  are verified (§4), that a keyless release build fails at build time (B §3.4), and
  the §2.5 init exit-code accuracy.

## Architecture notes

**The decl_blob is the whole of C's new mechanism.** Everything else in C is B
plus framing (the layer split, §1) plus reuse of existing machinery (the reseal-open
failure as the debug-build gate, §7.2; the existing reseal verb for §5.2; a
best-effort `K_dev` locator flag at verify, §7.3). The one genuinely new wire element
is a single fixed-size AEAD-sealed record of the §2 declaration, sealed under
`mask_key` so it survives reseal and rides the same
key-holder gate as everything else. Read path: `unlock_key → wrapper → mask_key →
decl_blob`. It is written once (the macro, which already holds `mask_key`) and read
by one consumer (the CLI). No new secret crosses any boundary; no plaintext tell is
added (§3.7).

**One provider site dissolves B's three-site divergence.** B chose the provider at
runtime (`init_with!`), keyed at build (`emit`), and targeted at reseal
(`--to-machine-id`) — three places that could disagree (RT-2). C anchors the
*declaration* at one source `init!`, makes `build.rs` bytes-only, removes
`init_with!`, and lets reseal *read* the declaration rather than guess (§5.2). The
Rust compilation-unit wall (§2.3) is the reason the single site must be source, not
build: a custom provider's fetch code has to compile into the deployed binary.

**Alignment is an additive axis, deliberately not the default verdict.** The
sharpest design decision in C (and the one the dry-walk corrected twice): the static
alignment check must *complement* B's execute-locally proof, never *replace* it.
Baking it into `verify`'s default verdict breaks vault shops (always indeterminate →
can't gate) or gives false confidence on custom-coherent binaries (the F7 trap). So
`--check-alignment` is opt-in, authoritative only for built-in decls, *indeterminate*
for custom/absent, and its honest value is "early offline warning, proportional to
built-in usage." This is the line between C being a real improvement on B and C
overstating itself — held explicitly.

**Reseal refusal: automatic for built-ins, warn-only for custom.** Symmetric reason:
for a built-in decl the tool *knows* the runtime's request and can safely refuse a
machine-id reseal that contradicts it; for a custom decl it cannot reason and must
not block a legitimate hybrid. `--force` recovers B's unconditional behavior.

**Layer split is organizational, not mechanical.** Naming "masking core" vs
"distribution tool" and pinning their contract in `litmask-internal` prevents the
CLI/runtime drift the friction walk exposed, without adding a runtime component. The
decl_blob is the only new thing crossing the boundary, and it crosses one-way
(macro→CLI).

**Per-customer seeds derive from one master.** `mask_key` uniqueness is a function
of the `seed`, not the `unlock_key` (the reseal invariant), so the only mode that
needs unique seeds is per-customer-*build* (B §4.3). Rather than mint and store N
master secrets, C derives `customer_seed = KDF(master_seed, customer-id)` (§6.7.2):
one stored secret + N non-secret labels, deterministic and reproducible for
attribution. These derivations live under a single `derive` verb
(`derive seed --from-master --label`, alongside `derive mask-key --seed` and the
renamed `derive machine-key`), not a minter — a seed is a `keygen` value in a role,
so the master is minted with `keygen`; this also closes B's named-but-absent `seed`
verb. The attribution record collapses to labels + one master reference (§6.7.5) —
the lightweight form of the ledger the earlier specs deferred. Reseal-default (the
common case) is untouched: it shares `mask_key` deliberately and needs no
per-customer seed.

**`derive` exposes the content key, never the access key.** `mask_key = KDF(seed)`
is a genuine seed derivation, so `derive mask-key --seed` simply surfaces it
(inspection / test vectors), granting nothing a seed-holder lacks. `unlock_key` is
the opposite: under the inversion it is an operator *input*, kept independent of the
seed on purpose, so there is **no `derive unlock-key`** and no `--seed` path to one
(§6.8.3). Fusing the two roots would revert C to the build-generated model and
re-introduce the cascade; a shop wanting deterministic access keys derives them from
a *separate* access-master, never the content seed.

**Testing strategy.** Inherit B's entire test matrix (reseal compartmentalization;
four `verify` outcomes/exit codes; no-metadata-file decrypt; opaque-wrapper
trial-decrypt + scrub-clean of the `0x01,0x01` tell; `K_dev` `NotFound`-rescue and
no-rescue-of-wrong-key; release no-key build failure + zero-`K_dev`-bytes scrub;
seed never persisted/logged incl. cached rebuild; pinned-seed byte-identical blobs +
edit-changes-nonce; machine-id off-box indeterminate/with-flags; `keygen` encoding +
`derive` derivation reproduction; `--deny` pass/fail; execute-locally provider
proof). **Add for C:**
- assert the decl_blob is **sealed under `mask_key`** and therefore **byte-identical
  before and after reseal** (the wrapper+locator change, the decl_blob does not,
  §3.3);
- assert the decl_blob is **constant-size** (`12 + L_decl + 16`) regardless of decl
  kind/parameter length, so the embedded region is delimited as fixed-width tails
  with no stored length (§3.2, C-B); assert the authenticated padding round-trips and
  a flipped pad byte fails AEAD;
- assert the decl plaintext uses **length-prefixed canonical encoding** so two
  distinct decls (e.g. `env:"ab"` vs `file:"ab"`, or salts that would alias under
  delimiter-join) never produce the same `decl_plain` or nonce input (§3.2.1/§3.4,
  C-G);
- assert the read path `unlock_key→wrapper→mask_key→decl_blob` recovers the declared
  source for each of the three §2.2 forms (`env:NAME`, `machine_id:salt`, `custom`),
  and that a binary with **no `init!`** has **no decl_blob** and is treated as
  *unknown*/indeterminate (§3.6);
- assert the decl_blob region is **scrub-clean** in release (no plaintext schema
  tag; high-entropy; decl-schema version recovered only post-decrypt, §3.7);
- assert the decl_blob nonce uses the reserved `"decl"` site-id and **cannot collide**
  with any masked-literal nonce (§3.4);
- assert `verify --check-alignment --expect-source` returns **authoritative**
  *aligned*/*misaligned* for a built-in decl (e.g. decl `machine_id:cryptio-v1` vs
  `--expect-source env:NAME` → *misaligned*) and **indeterminate** for a `custom` or
  absent decl (§4.2.2/§4.4); assert that **without** `--expect-source` the axis is
  **report-only** and contributes no pass/fail (§4.2.2/§4.3); assert alignment is
  **never inferred from the `--key-…` channel** — a `machine_id` binary whose key is
  supplied via raw env does **not** report *misaligned* (§4.2.1, C-A); and that the
  alignment axis does **not** change the default decrypt-success verdict (§4.1);
- assert the combined exit-code policy (§4.3): a custom-provider run gating on
  decrypt-success + `--deny` **passes** despite an *indeterminate*/report-only
  alignment axis;
- assert `reseal --to-machine-id` **refuses** (non-zero) when the decl is a built-in
  that contradicts the machine-id target, **proceeds** when the decl is matching
  `machine_id`, **warns-but-proceeds** when the decl is `custom`/absent, and that
  `--force` overrides the refusal with a warning (§5.2);
- assert `reseal --from-env BUILD_KEY` **fails** on a debug build (wrong seal — the
  primary debug-build gate, §7.2), and that `verify` *additionally*, best-effort,
  flags a debug build via the `K_dev` locator **when crate identity is available**
  and **no-fires without erroring** when it is not (§7.3);
- assert **`init_with!` is removed** — the macro no longer compiles — and that each
  §2.2 form expands to a decl_blob the CLI reads back; assert `build.rs` declares no
  provider (bytes-only, §2.1);
- assert `derive seed --from-master M --label bob` is **deterministic** (same
  `(M, label)` → byte-identical seed) and **unique per label** (two labels → two
  distinct seeds); assert a per-customer build under a derived seed yields a **unique
  `mask_key`** — two customers built from the same source under `seed(M,bob)` vs
  `seed(M,carol)` have **byte-differing blobs** (§6.7.1/§6.7.2), while a rebuild under
  the *same* derived seed reproduces **byte-identical blobs** (attribution
  reproducibility);
- assert `derive mask-key --seed S` reproduces that build's `mask_key` (it decrypts
  that build's blobs) and emits stdout-only (§6.8.2); assert **no `derive unlock-key`
  target exists** (§6.8.3); assert `derive machine-key` reproduces the runtime
  `MachineIdProvider` derivation (§6.8.1, the renamed B `machine-key`);
- assert there is **no seed-*mint* verb** (the master is a `keygen` value, §6.7.3)
  and that every `derive` target emits over §6.4 channels only (never argv, §6.8.4);
- assert two customers' **identical literals get different nonces** under their
  distinct derived seeds (no cross-customer nonce reuse, §6.7.6), and that
  reseal-default (shared `mask_key`, no per-customer seed) still produces
  byte-identical blobs across customers (B §4.2 — the contrast case).
Reuse the `example_scrub` harness; one fixtures source per example (§9.1).

## Out of Scope

Inherits B's Out-of-Scope set, plus:

- A CLI verb that compiles a target, and a `litmask run` exec/key-wiring verb (B).
- A managed seed/key secret store, or solving the build-host-holds-all-keys trust
  boundary (B; THREAT_MODEL.md). C states the per-customer attribution *record shape*
  (§6.7.5) but builds **no managed seed/label ledger** — the operator keeps the
  `(customer-id, fingerprint, date)` list and the single `master_seed`.
- **Build-emitted provider *selection*** — the decl_blob is a *record of* a
  source-declared provider for tooling (§3.5), **not** a build-side choice of which
  provider the runtime uses. The runtime's provider is the compiled-in `init!` code,
  full stop. (C explicitly does not let the build or the decl pick the runtime
  provider — that would re-introduce the rejected build-emitted-provider design.)
- **Making alignment authoritative for custom providers** — fundamentally impossible
  offline (§4.4 / B §4.4.1); execute-locally (B §4.4.2) remains the authority.
- **Preventing** (vs detecting) debug-build distribution (§7.4) — C detects loudly at
  the reseal step (§7.2) and, best-effort, at verify (§7.3); it does not block a
  manual copy.
- Changing the wrapper crypto, `mask_key` derivation, or release-runtime failure paths
  (C adds the decl_blob element and the layer framing; it does not touch the wrapper
  seal, B).
- Enforcing cross-customer key distinctness in the binary (provisioning, B §6.1).

## Open Questions (all resolved)

- **OQ-C1 — RESOLVED (decl sealed under `mask_key`, §3.3).** Concern: under which
  key should the declaration ride so it survives reseal yet stays key-gated?
  Resolution: `mask_key`, which reseal never touches, so the decl is a build-property
  invariant across customer re-keying; the macro already holds `mask_key`, so no new
  secret crosses a boundary; the reader gate is the same `unlock_key`-holding gate as
  the wrapper.
- **OQ-C2 — RESOLVED (one source site, `init_with!` removed, §2.1/§2.3).** Concern:
  can the single provider site live in `build.rs` so build is the only setup point?
  Resolution: **no** — the Rust compilation-unit wall means a custom provider's fetch
  code must compile into the deployed binary, so the one site must be source `init!`;
  `build.rs` stays bytes-only. This still achieves *one* declaration site (the goal),
  just in source rather than build.
- **OQ-C3 — RESOLVED (alignment is an opt-in additive axis, §4.2/§4.4).** Concern:
  does the decl make `verify` authoritative and dissolve B's OQ-3? Resolution: **no,
  and saying so would over-claim.** Alignment is authoritative only for built-in
  decls and *indeterminate* for custom; it is an **opt-in early-warning** that
  complements, never replaces, execute-locally (B §4.4.2). Baking it into the default
  verdict was rejected (breaks vault shops / F7 false-confidence). C's honest win:
  built-in-provider shops catch the machine-id-vs-env footgun **offline**; custom
  shops are exactly at B-parity. **Scope correction (C-A):** alignment compares
  source-**KIND** (decl vs explicit `--expect-source`), never key-**VALUE** and never
  the `--key-…` channel the operator used — inferring "supplied via env ⟹ runtime
  reads env" would false-positive the legitimate off-box machine-id verify flow
  (B §5.5), and machine-binding remains a **runtime** property the offline tool never
  weakens (§4.2.1/§4.2.2).
- **OQ-C4 — RESOLVED (reseal refusal automatic for built-ins, warn-only for custom,
  §5.2).** Concern: should `reseal --to-machine-id` refuse on a declared-source
  mismatch? Resolution: refuse **automatically** when the decl is a built-in that
  contradicts the target (the tool *knows* the runtime won't ask for a machine key);
  **warn-only** when the decl is custom/absent (the tool can't reason about a hybrid);
  `--force` overrides. This catches B's silent footgun for the common case without
  blocking legitimate custom flows.
- **OQ-C5 — RESOLVED (per-customer seeds derive from one master, §6.7).** Concern:
  per-customer-build mode wants unique-and-reproducible `mask_key`, which (since
  `mask_key` derives from the seed, not the `unlock_key`) means building from a
  stored unique seed. Store N independent seeds, or derive? Resolution: **derive** —
  `customer_seed = KDF(master_seed, customer-id)`. One stored master secret + N
  non-secret labels gives deterministic per-customer uniqueness and attribution
  reproducibility while shrinking secret custody from N seeds to one. The derivation
  is a target of the consolidated **`derive`** verb (`derive seed --from-master
  --label`, §6.8), not a minter (a seed is a `keygen` value in a role; the master is
  minted with `keygen`) — which also closes B's named-but-absent `seed` verb. The
  build already respects `LITMASK_RNG_SEED`, so no build change is needed. Applies to
  per-customer-build mode only; reseal-default shares `mask_key` and is untouched.
- **OQ-C6 — RESOLVED (derive `mask_key` from seed, never `unlock_key`, §6.8).**
  Concern: should the CLI derive both `mask_key` and `unlock_key` from the seed?
  Resolution: **`mask_key` yes, `unlock_key` no.** `mask_key = KDF(seed)` is already
  the build derivation, so `derive mask-key --seed` just exposes it (inspection / test
  vectors, no new capability, §6.8.2). `unlock_key` is an operator **input** under the
  inversion (C.1), independent of the seed *by design* — deriving it from the seed
  would fuse the content-root and access-root, revert C to the build-generated model,
  and re-introduce the per-customer cascade (§6.8.3). So there is no `derive
  unlock-key`; a shop wanting deterministic access keys derives them from a *separate*
  access-master off-box, never the content seed. All derivations consolidate under one
  `derive` verb that also subsumes B's `machine-key` (§6.8.1).

## Decision delta vs `SPEC_DEVEX_B.md` (C inherits B; this is the C-only delta)

| Axis | **B (clean slate)** | **C (declarative + layered)** |
|---|---|---|
| `unlock_key` / locator / wrapper | operator input / derived / opaque | **inherited unchanged** |
| Deployment shape | one build + per-customer reseal | **inherited unchanged** |
| `K_dev` zero-wiring / seed hygiene / no-argv secrets | as B | **inherited unchanged** |
| Provider setup sites | runtime `init_with!` + build `emit` + reseal target (3) | **one source `init!`; `init_with!` removed; build bytes-only (1)** |
| Provider intent offline | **invisible by construction** (B §4.4.1) | **recoverable for built-ins via decl_blob (§3); custom = opaque** |
| Binary layout | `locator ‖ wrapper` | **`locator ‖ wrapper ‖ decl_blob`** (fixed-size, decl under `mask_key`, reseal-invariant) |
| `verify` provider alignment | not possible (execute-locally only) | **opt-in `--check-alignment`: report-only, or pass/fail vs explicit `--expect-source`; authoritative for built-ins, indeterminate for custom; never inferred from key channel** |
| `reseal --to-machine-id` mismatch | silent footgun (warns, B §6.2) | **auto-refuse on built-in mismatch; warn-only on custom; `--force` override** |
| Debug-never-ship | documented caveat (B §3.6) | **primary gate: reseal-open fails on a `K_dev`-sealed build (§7.2); best-effort `K_dev`-locator flag at `verify` (§7.3) — a gate, not prose** |
| Layer contract | implicit (one crate set) | **named: masking core vs distribution tool; contract pinned in `litmask-internal` (§1)** |
| Per-customer `mask_key` (build mode) | unique via per-customer build under a fresh seed; `seed` verb named but absent | **derive `seed = KDF(master_seed, customer-id)`** — one stored master, N non-secret labels (§6.7) |
| Attribution record | per-customer-build operator's problem (ledger out of scope) | **labels + one master ref** (§6.7.5) — lightweight, no per-customer secret |
| CLI surface | verify, reseal, keygen, machine-key, show-machine-id | **verify, reseal, keygen, `derive`, show-machine-id** — one `derive` verb (mask-key / seed / machine-key); `verify +--check-alignment`, `reseal +decl-refuse/--force` |
| Honest residual | bigger break from current code | **custom providers gain nothing (B-parity); value ∝ built-in usage (§8.1)** |
