# litmask Developer-Experience — Specification (Variant E: Pass-Through Dev + Honest Topology)

> **Status:** design variant, refine phase. Sixth option beside
> `docs/SPEC_DEVEX.md` (build-generated key), `_A` (operator-owned key),
> `_B` (clean slate), `_C` (declarative + layered), `_D` (B minus `K_dev`).
> **E adopts D's foundation** — operator-owned `unlock_key`, derived locator,
> opaque wrapper, reseal-default deployment, single `init!` site, no-argv secret
> channels — and makes **three** changes, two of which are net **deletions** and
> one of which is a **doc-first reframing**:
> (1) it **does not seal in the dev loop at all** — debug builds compile literals
> in the clear (pass-through), deleting D's developer-key channel, its
> secret-hygiene burden, and its ambient-key footgun, on top of D's already-deleted
> `K_dev`;
> (2) it **demotes `MachineIdProvider` from core machinery to one provider among
> several** and **cuts the `verify` ceremony** (four-outcome exit-code namespace,
> `--deny` lock-out) down to a single decrypt-success question, on YAGNI grounds;
> (3) it makes the **deployment-topology decision** — the thing a real adopter
> actually cannot answer today — the **first page of the documentation**, with an
> honest statement of when litmask is protection and when it is obfuscation.
> Drafted for a deliberate side-by-side decision. If adopted, E replaces the other
> five. The project is **pre-release**, so E lands as a direct edit with no
> migration burden.

## Summary

The variant chain converged on a small set of correct moves and then accreted
machinery around them. E keeps the convergence and removes the accretion.

**What the chain got right (E keeps, mostly verbatim from B/D):**

- **Invert the key (A).** Operator owns `unlock_key`; the build *seals* under it
  and never generates it. This single move dissolves F1/F2/F3/F6/S1 by *removal* —
  they were all symptoms of a build-minted secret a human had to chase.
- **Derive the locator (B §2).** Deletes the entire config-file subsystem, F4, and
  the F7 false-pass.
- **Opaque wrapper (B §2.5).** Removes the `0x01,0x01` format/cipher tell. For a
  tool whose whole job is to hide from static analysis, a self-identifying wrapper
  is a defect; E treats fixing it as table stakes.
- **Single `init!` site (C §2 / D §2bis).** Zero wire-format cost; closes the
  build-vs-runtime provider divergence (B §4.4.1).
- **`reseal` as the one multi-tenant primitive (B §4).** One universal build,
  re-keyed per customer without rebuilding.
- **Delete `K_dev` (D).** The baked debug constant was a vestige of the
  build-generated model; once the key is inverted it earns nothing. D's deletion
  cascade (no self-decrypting binary → no per-crate derivation, no scrub-MUST for
  the constant, no §7 workflow guard) is correct.

**What E changes over D — three moves:**

1. **Pass-through dev (E §3, replaces D §3 entirely).** Every prior variant spends
   effort making `cargo run` *decrypt* — `SPEC_DEVEX`'s baked key, A/B/C's `K_dev`,
   D's developer-key-in-a-channel. All of it exists to **unseal in dev**. But
   masking is a **release** property: debug builds are already not scrub-clean
   (DWARF, identifying strings) and already "must never ship." So E **does not seal
   in debug** — `mask!` compiles the literal in the clear and `init!` is a no-op.
   The dev loop needs **no key, no dev-key file, no `K_dev`, no wiring at all** —
   strictly less than D. The self-decrypting-binary hazard does not arise (a debug
   binary embeds *plaintext*, exactly the non-shippable artifact everyone already
   understands; it adds **no new key-extraction surface**). D's dev-key
   secret-hygiene burden (D §3.7) and ambient-dev-key release footgun (D §3.6)
   **both disappear**, because there is no dev key.

2. **Demote `MachineIdProvider`; cut the `verify` ceremony (E §5, §6).**
   Machine-id binding drives a disproportionate share of every prior variant's CLI
   surface (off-box derivation, `bind`, `reseal --to-machine-id`, host-lock,
   execute-locally proof, alignment checks) **and delivers weak security** — a
   local attacker who holds the binary also holds the machine-id and can re-derive
   the key (E §1.3). E keeps machine-id as **one `KeyProvider` among several**, not
   as a load-bearing core concept, and shrinks `verify` to the one question it
   exists to answer: *does this binary decrypt under this key?* (E §5.1). The
   four-outcome exit-code namespace and the `--deny` lock-out are deferred under
   YAGNI (E §5.4) — added when a concrete CI need lands, not before. E does re-add
   **one** thing a red-team (R3) showed the chain cut too early: a **minimal
   provider-descriptor blob** (E §2 E.6), AEAD-sealed (no static tell), so
   `verify`/`reseal` catch a provider/seal-target *identity* mismatch offline rather
   than letting it die silently on the deployed host.

3. **Topology-first documentation + honest crypto framing (E §1).** Every prior
   variant optimizes *mechanics* and never states **when litmask provides security
   at all** — the question a real adopter (Alice) genuinely cannot answer from the
   current docs. E makes a **deployment-topology decision tree** the first page
   (E §1.1) and states plainly that the security value is a function of *who the
   attacker is*, not of the crypto strength (E §1.2/§1.3).

What E is, in one line: **D, with sealing removed from the dev loop, machine-id
demoted out of the core, the `verify` surface cut to its essential question, and
the honest threat-topology promoted to the front of the docs.** Smallest surface
of any variant; two more hazard/burden classes deleted than D (the one addition over
D's wire format is the small AEAD provider-descriptor blob, E.6, which earns its
keep by closing R3's silent-misconfig).

## 1. Threat Topology — Documentation Leads Here (the missing UX piece)

> This section is **doc-normative**: it governs what the documentation must say
> *before* any key mechanics, and it shapes which mechanisms E keeps. It is the
> one thing no prior variant states, and it is the thing an adopter most needs.

- **1.1 (topology decision tree — doc-normative, must lead the README)**: The
  documentation MUST open with a decision tree that tells an adopter whether
  litmask protects them, **before** explaining keys, providers, or `reseal`. The
  determining question is **who holds the runtime key relative to the attacker**:
  - **Server-side topology** — the masked binary runs on infrastructure the
    operator controls (Alice's cloud); the end user (Bob) is *remote* and never
    receives the binary. The plausible attacker obtains the **binary artifact**
    (leaked image, repo, backup) but **not** the runtime key (held in the
    operator's env/vault). **litmask is real protection here** — the masking
    promise (plaintext absent from the binary) directly defeats the attacker's
    access. This is the topology litmask is *for*.
  - **Distributed topology** — the masked binary runs on a host the *user/attacker*
    controls (Bob runs Cryptio on Bob's machine, a desktop app, an on-prem
    appliance). The attacker has the binary **and** the environment the key must
    live in. **litmask here is obfuscation, not a wall**: a local attacker can run
    the binary and read decrypted strings from memory, or replay the (small,
    known-algorithm) decrypt path with the provisioned key. `MachineIdProvider`
    (E §6.3) raises the bar for *lateral* theft (binary copied to another host) but
    does **not** stop the *local* attacker, who can re-derive the machine key.
  - **The honest rule (doc-normative)**: litmask's strong-masking guarantee is
    **"a stolen binary is inert without a key the attacker does not have."** It is
    only a guarantee when the key is genuinely outside the attacker's reach
    (server-side; or a vault/HSM the attacker cannot read). For the distributed
    case the docs MUST say so in these words and frame litmask as
    raise-the-cost obfuscation, not confidentiality.
- **1.2 (crypto strength is not the security boundary — doc-normative)**: The
  documentation MUST state that AEAD strength buys little over `weak_mask!`-grade
  XOR **once the key is in the attacker's reach** — the boundary is *key custody*
  (§1.1), not cipher choice. Strong masking earns its keep specifically in the
  server-side topology and the vault/HSM provider; the existing strong/weak split
  is explained in these terms rather than as a generic "more secure" dial.
- **1.3 (machine-id is lateral-theft mitigation, not local-attacker defense —
  doc-normative)**: Documentation for `MachineIdProvider` MUST state its actual
  guarantee — a binary bound to host A will not self-decrypt on host B — and its
  actual non-guarantee: on host A, an attacker with the binary can obtain the same
  machine-id the runtime uses and re-derive the key. It is a deployment-binding
  convenience, **not** a confidentiality control against a local adversary. This
  framing is why E demotes it from core machinery to one provider (§6.3).

## 2. Foundation (inherited from B/D, stated for portability)

E inherits **all** of B's Foundation (B.1–B.4) unchanged, exactly as D does, **plus
one change**: the seal is **release-only** (§2.5 / §3). Restated so this spec is
implementable without B/D open:

- **E.1 (inverted key, = B.1/D.1):** the `unlock_key` is an **operator-supplied
  input**, never a build output. The **release** build seals `mask_key` under the
  supplied key. (Debug does not seal — §3.)
- **E.2 (derived locator, = B.2/D.2):** the locator is
  `KDF(unlock_key, "litmask-locator-v1")`, recomputed by build / runtime / CLI;
  **no metadata file exists.** Applies to release builds (the only sealed builds).
- **E.3 (opaque wrapper, = B.3 / B §2.5 / D.3):** `nonce(12) ‖ AEAD(version_byte ‖
  mask_key)(33) ‖ tag(16)` = **61 bytes**, no plaintext header; cipher recovered by
  trial-decrypt (AEAD tag = discriminator). Carried verbatim from B §2.5. Present
  only in release builds.
- **E.4 (mute release failure paths, = B.4/D.4):** release runtime failures stay
  bare (`panic!()` / `Err(Decryption)`), no identifying text.
- **E.5 (release-only seal — the E foundation change, normative):** Masking is a
  **release-profile transformation**. In `PROFILE != "release"` builds, literals
  are compiled **in the clear** and `init!`/`mask!` are pass-through (§3). The
  wire format, locator, and seal of E.1–E.3 exist **only** in release artifacts.
  The masking promise (plaintext absent from the binary) is, and has always been, a
  property of the **shipped release binary** — debug builds are not scrub-clean
  regardless (THREAT_MODEL.md), so withholding the seal in debug weakens nothing
  that was ever promised.
- **E.6 (provider descriptor blob — normative, re-adds a *minimal* decl_blob):** the
  release binary carries one additional sealed region: an AEAD blob, sealed under
  `mask_key` (therefore **reseal-invariant** — `mask_key` is unchanged across
  reseal), encoding the **compiled provider family** (`env(NAME)` / `file` /
  `machine_id` / `custom`). It is emitted by the **`init!` macro** (the side that
  knows the provider — build.rs stays bytes-only, §4bis), **not** by `emit()`. It is
  AEAD ciphertext, so it is **indistinguishable from random and adds no
  static-analysis tell** (the opaque-wrapper invariant, E.3, is preserved). Tooling
  that opens the wrapper (`verify`/`reseal`, which recover `mask_key` from the
  `unlock_key`) decrypts it to catch provider/seal **identity** mismatch offline
  (§5.3, §6.2). This deliberately **reverses E's earlier "no decl_blob" stance for
  the provider descriptor only** — the red-team (R3) showed the cut left a real
  misconfig (resealing `--to-machine-id` onto an `env`-provider binary) undetectable
  offline and producing a misleading `verify` pass. It does **not** re-add C's
  broader decl_blob (per-blob offline alignment), which stays declined.

**E adds exactly one wire-format element to B/D's layout: the E.6 provider blob.** A
release binary is `locator(12) ‖ wrapper(61) ‖ provider_blob` (the blob being
`nonce(12) ‖ AEAD(descriptor) ‖ tag(16)`). A debug binary embeds the plaintext
literal directly and carries **no wrapper, locator, blob, or key**.

## 3. Dev-Loop Pass-Through (no seal in debug — replaces D §3 and B §3 `K_dev`)

This section **replaces** D §3 (developer-supplied key) and B §3 (`K_dev`) in full.
There is **no dev key** in E: no baked constant, no per-crate derivation, no
gitignored keyfile, no env var, no `direnv`/`just` assumption, no `cfg`-stripping of
a key. The dev loop needs **nothing**.

- **3.1 (debug is pass-through — normative)**: In `PROFILE != "release"`, the
  `litmask-macros` expansion of `mask!`/`mask_secret!`/`weak_mask!` embeds the
  **plaintext literal directly** and performs **no encryption**; `litmask_build::emit()`
  generates **no seed, no wrapper, no locator, and reads no key**. `init!` expands
  to a **no-op success** (`Ok(())`) because there is nothing to unseal. Therefore
  `cargo run` / `cargo test` work with **zero wiring, zero key, and zero setup** —
  strictly less ceremony than D's one-time keyfile.
- **3.2 (type-identity across profiles — normative, the skew guard)**: `mask!` MUST
  return the **identical type** in debug and release (the existing secure buffer
  type, e.g. a zeroizing `SecretString`/`Masked<…>`), differing only in **how it is
  filled**: in debug from the embedded plaintext, in release from decryption. The
  *only* behavioral difference between profiles is "did the decrypt path run." This
  bounds dev/release skew to the key path itself, which is validated by
  execute-locally on the release artifact (§5.5) — the same authority B/C/D already
  rely on. No API, signature, or downstream-type difference is permitted between
  profiles (a `mask!` returning `&'static str` in debug but an owned secret in
  release is a spec violation — it would let dev compile code that breaks release).
- **3.2.1 (narrow the profile `cfg` to the crypto *operation*, not the whole branch
  — normative, the R1 skew guard)**: pass-through MUST be implemented so that the
  consumer's dev loop still **type-checks the release code path**. Naïvely
  `#[cfg]`-stripping the entire sealed branch leaves the `init!(custom: <expr>)`
  expression, the `InitError`→`sysexit_code` mapping, and the unseal call
  **unparsed/untype-checked** in debug — so a consumer's `cargo check` is green while
  `cargo check --release` fails (an Alice-facing skew). Therefore: provider
  **construction**, the provider trait objects, and the error types MUST compile in
  **both** profiles (type-checked everywhere; dead-code-eliminated in debug — they
  embed no secret and pull in no wrapper bytes, since wrapper/locator/blob come from
  release-only `emit()`/macro paths). Only the **crypto operation** (the actual
  unseal, the embedded wrapper/locator/blob bytes) is profile-gated. This keeps
  E.6/§9.2 intact (no debug wrapper/locator/blob) while restoring type-checking of
  the release path in the ordinary debug `cargo check`. Consumer guidance (§10.4) and
  litmask's own CI MUST additionally run `cargo check --release` + clippy on release,
  since type-identity alone cannot prove the gated operation compiles.
- **3.3 (no self-decrypting binary, no key hazard — normative)**: A debug binary
  embeds **plaintext**, not a key + ciphertext. It is therefore exactly the
  artifact every prior variant already classified non-shippable, and it adds **no
  new key-extraction surface** — there is no embedded key to extract, and the
  plaintext being present is the *defined* debug behavior (E.5), not a leak of a
  protected secret. Consequences, all deletions vs D:
  - **No dev-key secret-hygiene burden** (D §3.7 deleted): there is no dev key to
    keep out of `/proc`, crash dumps, or CI logs.
  - **No ambient-dev-key release footgun** (D §3.6 deleted): there is no dev key
    that a local release build could accidentally seal under. A release build seals
    under exactly the key its `LITMASK_UNLOCK_KEY` channel supplies, and a clean CI
    build with `build_key` is unambiguous. (`verify --deny`'s vacuous-pass risk,
    D §5.7, does not arise because no dev key competes with `build_key`.)
  - **No "debug success ≠ wired" caveat** in the `K_dev` sense (B §3.7): debug does
    not exercise *any* provider, so it never gives false confidence that a provider
    is wired — there is nothing to mistake. The authoritative provider check is
    execute-locally on the **release** artifact (§5.5), stated plainly so a green
    `cargo run` is understood as "the app logic runs," never "the deployment is
    wired."
- **3.4 (litmask's own examples and tests — normative)**: The repository's
  `examples/` and `just test` run in debug and therefore pass-through with no key —
  a fresh clone runs `just test` and `cargo run --example …` with **no setup of any
  kind**. The masking/roundtrip and scrub assertions that require a real seal build
  **release** (§3.5), which they already must, since the scrub test exists to
  inspect the *shippable* artifact.
- **3.5 (testing the seal is a release-build concern — normative)**: Any test that
  must exercise encryption/decryption, the wrapper, the locator, or the scrub
  invariant MUST build the example under `--release` (or a release-derived test
  profile) with an explicit `LITMASK_UNLOCK_KEY`, exactly as a real release build
  does. The `example_scrub` harness already builds release; E formalizes that the
  *crypto* path is tested there, and the *dev-loop ergonomics* are tested in debug
  (pass-through). This split mirrors the real-world contract: dev iterates on logic,
  release proves masking.
- **3.6 (opt-in: seal in debug too — normative, niche)**: A developer who wants
  their *local debug* binary to also not carry plaintext (shared dev box, demoing on
  an untrusted laptop) opts in explicitly via a single
  `litmask_build::Emit::new().seal_in_debug()` builder flag (or the documented
  `LITMASK_SEAL=1` env), which makes a debug build seal exactly like release and
  therefore require a runtime key like release. This is **opt-in**, so the default
  pays nothing for a niche want; when enabled it reuses the release seal path
  verbatim (no new mechanism) and the resulting debug binary is treated as
  release-grade for distribution purposes (still unoptimized; still carries §9
  diagnostic strings, so still not a *shippable* artifact, but no longer carries
  plaintext). Documentation states this is the single escape hatch for "I don't want
  plaintext in my dev build," replacing D's always-on dev-key machinery with an
  opt-in.
- **3.7 (default debug carries plaintext — the honest cost, normative doc claim, R2)**:
  pass-through means a debug binary **defeats `strings`/static analysis on the
  masked literals — the exact threat litmask exists to counter.** Prior variants
  (`K_dev`, D's dev key) sealed even in debug, so an accidentally-shipped debug
  binary still resisted a casual `strings | grep`; E's does not. Documentation MUST
  state this plainly: (a) masking is **off by default in debug**, so an accidental
  ship of `target/debug` leaks plaintext secrets, not merely DWARF/symbols; (b) a
  consumer whose literals are genuinely sensitive (not public test fixtures) and who
  fears accidental debug distribution SHOULD enable §3.6 `seal_in_debug()`; (c) CI
  that produces shippable artifacts SHOULD guard against shipping `target/debug` at
  all. This is a deliberate default — most debug builds never leave the dev host —
  but it is a **regression in defense-in-depth for the accidental-ship case** versus
  the always-seal variants, and the docs own it rather than implying debug is
  protected. See Honest Residuals §8.2.
- **3.8 (`LITMASK_SEAL` is build-explicit, not ambient — normative, R5)**: the §3.6
  opt-in MUST NOT silently flip behavior from a developer's ambient shell.
  `LITMASK_SEAL` is honored only as a per-invocation build input (the
  `seal_in_debug()` builder is the primary, unambiguous form); when it *is* read from
  the environment, a debug build that seals because of it MUST emit a one-line
  non-secret notice (`litmask: sealing debug build (LITMASK_SEAL set) — runtime key
  required`), so a stray `LITMASK_SEAL=1` in a shell/`direnv` cannot silently make
  `cargo test` require a key or change artifact contents without a visible signal.
  (E deleted D's ambient *dev-key* footgun; this clause prevents introducing a
  symmetric ambient *seal-mode* footgun in its place.)

## 4. Key Ownership Model (inversion, = B §1 / D §1)

Carried from D §1, with the seal scoped to release (E.5). In brief:

- **4.1**: For a **release** build, `litmask_build::emit()` obtains the
  `unlock_key` from a build-time environment variable (default
  `LITMASK_UNLOCK_KEY`) or a keyfile (`Emit::new().key_file(path)`), validates it
  (base64url, exactly 32 bytes, ASCII-whitespace-trimmed), and seals the
  freshly-derived `mask_key` into the wrapper under it. The key is **never
  generated** by the build and **never written to any artifact**. In a debug build
  `emit()` reads **no key** (§3.1).
- **4.1.1 (default name matches the runtime — normative)**: The build default,
  `verify` (§5), and the runtime `EnvVarProvider` default MUST all read
  `LITMASK_UNLOCK_KEY`. A divergence silently yields runtime `NotFound` for every
  default user and is a spec violation. (Carried from B §1.1.1.)
- **4.2 (custom name, = B §1.2)**: configurable on both sides —
  `emit().key_var("CRYPTIO_KEY")` paired with `init!(source: env("CRYPTIO_KEY"))`.
- **4.3 (input normalization, = B §1.3)**: every key channel trims surrounding
  ASCII whitespace before base64url-decoding.
- **4.4 (malformed build-time key, = B §1.4)**: reports required encoding
  (base64url), length (32 bytes), and points at `litmask keygen` (§6.1).
- **4.5 (the build var seals; the provider unseals — normative, = D §1.1.2)**: the
  build-time variable is consumed at compile time by `emit()` to **seal**; the
  runtime provider supplies the **unseal** key independently. For `env`/`file` they
  coincide; for `machine_id`/`custom` they are two independent computations that
  MUST yield the identical value or the wrapper will not open. (Relevant only to
  release / opt-in-sealed-debug builds, §3.6.)

## 4bis. Single Provider Site (declarative `init!`, `init_with!` removed)

Carried **verbatim** from D §2bis / C §2: one source-level `init!` site;
`build.rs` is bytes-only; `init_with!` is removed; three forms — `init!()` (default
env), `init!(source: <built-in literal>)` (env/file/machine_id), `init!(custom:
<expr>)` (escape hatch); a non-literal `source:` argument is a compile error; the
`?` path yields exit 1 (not a sysexit) and at least one example maps `InitError` to
`sysexit_code()`. **Provider-descriptor blob only** (E.6): the `init!` macro emits
the sealed provider-identity blob in release so `verify`/`reseal` can catch
identity mismatch offline (§5.3, §6.2). It does **not** re-add C's broader decl_blob
(per-blob offline alignment, D §2bis.5) — *runtime* provider success is still proven
only by execute-locally (§5.5).

**E note (pass-through interaction)**: in a debug pass-through build (§3.1) `init!`
in *all three* forms expands to a no-op success and emits **no blob** — the provider
is **constructed-and-type-checked but not executed** (the constructing code compiles
in both profiles per §3.2.1, so a `custom:` expr or `InitError` mapping that fails to
type-check is caught by the ordinary debug `cargo check`; it is simply
dead-code-eliminated / unreached at runtime in debug, because there is nothing to
unseal). The provider's *unseal* runs only in release (or opt-in-sealed debug, §3.6).
This is the one respect in which E's dev loop differs from D's: D runs the real
provider in dev (D §3.1.1); E does not *execute* it in dev. The trade is deliberate
and the cost is small — see §5.5 and the Honest Residuals (§8.1).

## 5. Coherence & Failure Diagnostics (cut to the essential question)

E keeps B/D's `verify` **purpose** and **deletes its ceremony**. `verify` exists to
answer one operator question; everything beyond that is deferred under YAGNI until a
concrete need lands.

- **5.1 (`verify` — one question, three answers — normative)**: `litmask verify
  <binary>` reads the owned key per §7 and reports **decrypt-success**:
  - **decrypts** (`EX_OK`) — the binary's wrapper opens under the supplied key;
  - **does not decrypt** (`EX_DATAERR`) — the keyed locator is absent **or** the
    wrapper fails to open (these are *not* split — see §5.2);
  - **cannot check** (`EX_UNAVAILABLE`) — the key cannot be supplied offline (a
    `MachineIdProvider` binary verified off-box without `--machine-id`/`--salt`,
    §5.3).
  The F7 false-pass is **unreachable by construction** (the locator is keyed, so
  there is no keyless mode to pass weakly), exactly as in B/D.
- **5.2 (why not split "wrong binary" from "wrong key" — normative rationale,
  deletes B/D's four-outcome namespace)**: Under a **derived** locator (E.2), a key
  that cannot *find* the wrapper and a key that cannot *open* it are the same
  failure to the operator: "this binary does not decrypt under this key." B §5.2
  itself observes that with a keyed locator "wrong key" and "wrong binary" usually
  both surface as locator-absent. E concludes that a four-code namespace
  (coherent/locator-absent/key-fails/indeterminate) prices a distinction the
  operator's actual question does not need. The two codes of §5.1 (plus
  *cannot-check*) suffice; a finer split is added **only** when a real CI script
  demonstrates a need to branch on it (§5.4).
- **5.3 (machine-id off-box + provider-identity check, R3a)**: For a
  `MachineIdProvider` binary, off-box decrypt-success needs the machine key the CLI
  cannot reproduce; `verify` accepts `--machine-id`/`--salt` and derives it. Without
  them it returns *cannot-check* (`EX_UNAVAILABLE`), never *decrypts*. Once the
  wrapper opens, `verify` decrypts the E.6 provider blob and checks it against the
  key source the operator supplied: if they **contradict** — e.g. the wrapper opens
  under a machine key (operator passed `--machine-id`) but the blob says the
  *compiled* provider is `env` — `verify` reports **does-not-decrypt-as-deployed**
  (`EX_DATAERR`, §5.2's failure code, with a distinct message: "wrapper opens under
  <key source>, but this binary's compiled provider is <blob provider> and will
  request a different key at runtime"). This closes the R3 misleading-green: the old
  *decrypts* result proved only that the wrapper opens under the supplied key, not
  that the runtime would request that key; the blob now lets `verify` catch the
  mismatch **offline**. The residual limit (§8.1): the blob proves compiled-provider
  **identity**, still not *host runtime success* (machine-id actually matches the
  target, salt correct) — that remains an execute-locally / consumer-smoke-test
  concern (§5.5).
- **5.4 (deferred under YAGNI — normative scope boundary)**: E deliberately does
  **not** ship B/D's `--deny` lock-out check, the four-distinct-exit-code table, or
  the *key-fails* vs *locator-absent* split. Rationale: these solve CI-scripting
  problems no current consumer has (the project is pre-release with no external CI
  yet). They are **clean additions** when a need lands — `verify` gaining a fourth
  code or a `--deny` flag is backward-compatible — so deferring costs nothing and
  keeps the surface honest. Documentation states this so the omission reads as
  *deferred*, not *overlooked*. (Contrast: B/C/D specified the full namespace
  up-front; E treats that as speculative surface — see [[feedback_yagni_over_speculative]].)
- **5.5 (provider *runtime success* is validated by execution, = B §4.4.2 / D §4.4)**:
  the E.6 blob lets an offline check observe the compiled provider's **identity**
  (§5.3), but not whether the host actually yields a working key. The authoritative
  proof of *runtime success* is
  **executing the release binary** with the key env cleared: reseal a throwaway copy
  to the local machine-id (for the machine-id case) or supply the production key
  (for env/file), run it, and confirm self-decrypt / correct behavior. The provider
  is compile-time fixed, so one such run proves alignment for every subsequent
  reseal of the same binary. **E note:** because E's dev loop is pass-through
  (§3.1), execute-locally is *also* the first point at which the provider path runs
  at all — so the docs frame "run the release artifact once" as a required
  smoke-test step, not an optional one.
- **5.6 (debug provider-source naming — does not apply in pass-through)**: B/D's
  debug-only provider-source naming (`source_hint()`) assumes the provider runs in
  debug and can fail. In E's pass-through debug build the provider does not run
  (§4bis note), so there is no debug key-failure to name. The diagnostic instead
  applies to **opt-in-sealed debug** (§3.6) and to running the **release** artifact
  under the §9 string gate: a key failure names the provider-specific source
  (`source_hint()`, default `None`, non-breaking) where strings are permitted, and
  stays mute in a true release build (E.4). This is a simplification, not a loss:
  the common dev loop never reaches a key-failure path because it never seals.
- **5.7 (runtime self-check hook — deferred, optional future feature, R3b)**: E.6's
  blob proves provider *identity* offline, but not that the host actually yields a
  working key at runtime (machine-id matches, salt correct, env populated).
  *Generically* proving that is impossible from the CLI — "successful execution" is
  app-defined (a server never exits; a CLI may error-exit on missing args, not on
  crypto), so a `verify --exec` flag is explicitly **rejected** (it would conflate
  app exit semantics with crypto success). The only litmask-defined way to automate
  runtime proof is an **opt-in self-check entry point** baked into the consumer
  binary: a `LITMASK_SELFCHECK`-triggered path that runs *only* the provider→unseal
  step before the app's `main` logic and exits with a litmask-owned deterministic
  code (unsealed → 0, key-fail → nonzero). This is **deferred under YAGNI** — it adds
  a runtime branch and a faint behavioral tell, and the default answer to "did it
  work on the host" stays the consumer's own smoke test (execute-locally, §5.5).
  Listed in Out of Scope as a clean future addition, not shipped now.

## 6. Tooling / CLI Surface (machine-id demoted, surface trimmed)

The distributable CLI is **{`verify`, `reseal`, `keygen`, `show-machine-id`}**.
The CLI never compiles and has no `run` verb; every subcommand is configless
(`(binary, key)` only).

- **6.1 (`keygen`, = B §6.1 / D §6.1)**: mints a fresh 32-byte `unlock_key`
  (CSPRNG, base64url no-padding), prints **only** the key to stdout (§7). Pure
  generator. Provisioning is one pipe per customer
  (`litmask keygen | gh secret set CRYPTIO_KEY_BOB`); distinct keys per run by
  default. There is **no `just dev-key`** equivalent — pass-through (§3) means the
  dev loop has no key to mint.
- **6.2 (`reseal`, = B §6.2 / D §6.2)**: `litmask reseal <binary> --from <keysrc>
  --to <keysrc> [-o <out>]` re-keys the wrapper and its derived locator;
  `mask_key`/blobs unchanged — **including the E.6 provider blob**, which is sealed
  under the unchanged `mask_key` and so survives reseal verbatim. The machine-id
  target is the same verb with a derived destination:
  `reseal … --to-machine-id <id> --salt <s>` (subsumes the legacy `bind` verb).
  Because `reseal` opens the wrapper with `--from`, it recovers `mask_key` and can
  read the provider blob (§5.3); `--to-machine-id` against a binary whose compiled
  provider is **not** machine-id-aware is the R3 misconfig, so `reseal` **refuses by
  default** with a clear message ("compiled provider is `env`; resealing
  `--to-machine-id` produces an artifact that will not self-decrypt — rebuild with a
  machine-id provider, or pass `--force` to reseal anyway"), overridable with
  `--force` for deliberate cases. It still points at execute-locally (§5.5) for the
  runtime-success check the blob cannot give (§8.1). Operates on release artifacts
  (debug builds have no wrapper to reseal — resealing a debug binary is a usage error
  with a clear message).
- **6.3 (`MachineIdProvider` is a provider, `show-machine-id` is its only verb —
  normative, the E demotion)**: machine-id is **one `KeyProvider`**, on equal
  footing with `EnvVarProvider`, `FileProvider`, and custom providers — **not** a
  core concept the CLI is organized around. Concretely:
  - `show-machine-id` is retained (prints this host's machine ID, a non-secret
    identifier, exempt from §7) because deriving a machine key off-box needs the
    target host's id.
  - The machine-key **derivation** is reached through `reseal --to-machine-id`
    (§6.2), which is the only operation that needs it. E does **not** ship a
    standalone `machine-key` verb (B/D §6.3) or C's `derive` consolidation: a
    bare "print a machine key" verb served the now-cut alignment/`--deny` ceremony;
    without that ceremony, the only consumer of a derived machine key is `reseal`,
    so the derivation lives there.
  - Documentation places machine-id **under "providers,"** beside env/file/custom,
    with its honest guarantee/non-guarantee (§1.3) — not in a top-level
    "deployment" chapter that implies it is the default or the strong path.
- **6.4 (no `derive`, no `bind`, no `machine-key`, no `record` — normative)**: E
  ships none of C's `derive` verb family, the legacy `bind` (folded into `reseal`),
  a standalone `machine-key`, or `SPEC_DEVEX`'s `record`/ledger. Each existed to
  serve machinery E cut (per-customer seed derivation, the alignment axis, the
  build-identity ledger). Key *management* (provisioning, derivation-from-master,
  attribution) is the operator's existing infrastructure (vault, gh secrets, KMS),
  composed with litmask's minimal seam (seal / unseal / re-key / verify).

## 7. Secret Input Channels (= B §8 / D §8)

Carried verbatim: any subcommand consuming a secret key (`verify`,
`reseal --from/--to`) accepts it **only** via non-argv channels — the default
`LITMASK_UNLOCK_KEY` env, `--key-env <NAME>` (per role `--from-env`/`--to-env`),
`--key-file <path>`, or `--key-stdin`. **There is no `--key <value>` flag** (argv
lands in the process table, readable by every user via `ps`, and is unreliably
masked in CI logs). Secret-emitting verbs (`keygen`) print **only** the value to
stdout. Build-time injection reads `LITMASK_UNLOCK_KEY` (or a keyfile, §4.1) at the
cargo boundary, which litmask facilitates but cannot enforce; documentation states
the discipline. (No `--deny-env` role, since §5.4 defers `--deny`.)

## 8. Reseal-Default Deployment (= B §4 / D §4)

Carried verbatim from B §4 / D §4: §4.1 universal-build-plus-per-customer-reseal;
§4.1.1/§4.1.2 the dedicated long-lived `build_key`; §4.2/§4.2.1 the reseal security
property and `build_key` plaintext-equivalence; §4.3 per-customer builds as the
opt-in for differing content / leak attribution; §4.4 machine-id deployment;
§4.4.1 provider-alignment is unverifiable offline; §4.4.2 validate-by-execution. E
changes only the framing emphasis:

- **8.1 (provider *identity* checkable offline; *runtime success* is not, = B §4.4.1
  refined by R3a)**: the E.6 blob lets `reseal`/`verify` catch a provider/seal
  **identity** mismatch offline (§5.3, §6.2) — closing R3's misleading-green and
  hard `--to-machine-id` misconfig. It does **not** prove the host yields a working
  key (machine-id matches, salt correct, env populated); for that, execute-locally
  (§5.5) remains the authority, with the §5.7 self-check hook as a deferred opt-in.
- **8.2 (reseal-default framed by topology — E emphasis)**: per §1.1, the
  reseal-default flow's compartmentalization (Bob's binary inert without Bob's key)
  is **real value in the server-side topology** and **weak in the distributed
  topology** (a local attacker has both binary and key). Documentation frames
  per-customer reseal as **operator compartmentalization** (limit blast radius of a
  *key* leak across tenants), not as protection against the end user who runs the
  binary — that follows directly from §1.1 and prevents the most likely
  over-claim.
- **8.3 (clean-env release is still required — but for the ordinary reason)**: the
  shippable universal build is produced in CI from a fresh clone with `build_key`
  supplied explicitly. In E this is **standard release discipline** (debug is
  pass-through and unshippable for the ordinary reasons), **not** a defense against
  an ambient dev key — there is no dev key (§3.3). D's normative clean-env rule
  (D §3.6) downgrades in E to "build releases in CI like any other project."

## 9. Diagnostics Gating (security-correctness — strings only, = D §9)

- **9.1 (strings only — normative)**: Debug-only loud diagnostics (§5.6 identifying
  strings, applicable to opt-in-sealed debug and to running release under the gate)
  are gated on the **actual build profile** via a `PROFILE`-derived `cfg` plumbed
  from a runtime-crate `build.rs` — not on `debug_assertions`. The gate is automatic
  and fail-safe.
- **9.2 (nothing else to gate — the E simplification)**: As in D, there is **no
  `K_dev` value/derivation/branch** for this `cfg` to strip. E goes one step
  further than D: because debug is pass-through (§3), there is also **no debug
  seal, no debug wrapper, and no debug locator** — the *only* litmask-specific thing
  the profile distinguishes is (a) whether literals are sealed at all and (b) the
  human-readable diagnostic strings. The release binary contains the wrapper and the
  E.6 provider blob (both AEAD ciphertext, scrub-clean, indistinguishable from
  random); the debug binary contains plaintext and (gated) strings. No litmask-specific
  *constant* survives into release that could become a distinguishing signature — the
  provider blob in particular is sealed, never a plaintext provider name.

## 10. Examples, Fixtures & Documentation

- **10.1 (single fixtures source, = B §10.1)**: each example declares its masked
  fixtures in one source of truth the scrub test consumes. The fixtures are public
  test strings.
- **10.2 (topology decision tree leads — E-new, doc-normative)**: the README opens
  with §1.1's decision tree (server-side = protection; distributed = obfuscation)
  and §1.2's crypto-is-not-the-boundary statement, **before** any key/provider
  mechanics. This is the single most important doc change in E.
- **10.3 (run docs — pass-through)**: every example header documents that in debug,
  `cargo run` / `cargo test` work with **no key, no setup, no wiring** (§3) — there
  is nothing to unseal. For verifying the *release* artifact, supply the owned key
  over a §7 channel and run it once (§5.5). No awk, no metadata file, no baked
  constant, no dev-key file, and no "this binary is self-decrypting" warning (a
  debug binary carries plaintext, the ordinary non-shippable state).
- **10.4 (dev-vs-release split — E framing)**: documentation states that **masking
  is a release transformation** (E.5): debug compiles literals in the clear and is
  unshippable for the ordinary reasons; release seals under the operator key; the
  *only* cross-profile behavioral difference is whether the decrypt path runs
  (§3.2), validated by execute-locally (§5.5). It documents the §3.6 opt-in for
  developers who want a plaintext-free debug build, framed as the single escape
  hatch.
- **10.5 (declarative `init!` shown, = D §10.4)**: at least one example uses each
  §4bis form; documentation notes that offline checking covers provider **identity
  only** (E.6 blob, §5.3) — *runtime* alignment is execute-locally (§5.5) — and that
  `init_with!` no longer exists, with porting guidance. Examples note that in debug
  pass-through `init!` is a no-op and emits no blob (the provider's unseal runs in
  release/§3.6 only).
- **10.6 (per-customer pipeline end-to-end, = B §10.5 minus `--deny`)**: `keygen`
  per customer into the secret store → one universal `cargo build --release` under
  `build_key` (in CI) → `reseal` per customer → `verify` each (decrypt-success,
  §5.1) → run each once to prove the provider path (§5.5) → inject each customer key
  into its runtime provider. No metadata file travels; no `--deny` step (deferred,
  §5.4).
- **10.7 (machine-id under providers, = §6.3 framing)**: `MachineIdProvider` is
  documented in the providers chapter beside env/file/custom, with its §1.3
  guarantee/non-guarantee, not as the deployment default.

## Architecture notes

**Not sealing in dev is the whole of E's first novelty, and it is a deletion.** Every
prior variant treated "make `cargo run` decrypt" as a requirement and built
machinery to satisfy it — a baked key (`SPEC_DEVEX`), `K_dev` (A/B/C), a developer
key channel (D). E observes the requirement is spurious: masking is a *release*
property (the scrub invariant has always been about the shipped binary; debug is
never scrub-clean), so the dev loop should not seal at all. Pass-through deletes the
unseal-in-dev problem class entirely — no key, no file, no constant, no hygiene
burden, no ambient-key footgun. D removed the *baked* key; E removes the *need for
any dev key*.

**The deletion cascades further than D's.** D's `K_dev` deletion removed per-crate
derivation, the scrub-MUST for a constant, a PROFILE-fused seal gate, and C's
workflow guard. E's pass-through additionally removes D's dev-key secret hygiene
(§3.7), D's ambient-key clean-env *security* rule (downgraded to ordinary release
discipline, §8.3), and the debug provider-run path (§5.6 simplifies). The profile
`cfg` narrows to its cleanest possible job: distinguish "seal or not" and gate
diagnostic strings.

**The one thing E gives up vs D, stated honestly.** D's dev loop runs the *real*
provider for every family (D §3.1.1), so a wiring bug can surface in development. E's
pass-through dev loop does not *unseal* in dev. The red-team (R3) split this into two
halves: provider **identity** mismatch — the high-frequency misconfig (resealing
`--to-machine-id` onto an `env`-provider binary) — is now caught **offline** by the
E.6 provider blob (§5.3, §6.2), so E gives that up to *no one*; only provider
**runtime success** (host machine-id matches, salt correct, env populated) is first
exercised at execute-locally on the release artifact (§5.5). This residual is small:
D's "real provider in dev" already ran against the *dev* key, not the production
key/provider config (D §3.5 admits machine_id/custom need per-family dev setup), and
the authoritative runtime check is execute-locally regardless. E trades "runtime
provider bug *might* surface a step earlier in dev" for "no dev key, no dev-key
hygiene, no ambient-key footgun, no per-family dev setup" — and makes execute-locally
a documented required smoke test (§5.5), with the §5.7 self-check hook as a deferred
opt-in to automate it.

**Machine-id demotion is the second novelty, also a deletion.** Across A/B/C/D,
machine-id drives off-box derivation, `bind`, `reseal --to-machine-id`, host-lock,
the execute-locally proof, and (in C) alignment — a large share of the CLI and the
prose. Yet its security is weak in the exact topology where it is reached for (the
distributed case, where the local attacker re-derives the key — §1.3). E keeps the
*capability* (it is one `KeyProvider`, and `reseal --to-machine-id` still works) but
strips it of its structural prominence: no standalone verb, documented under
providers with an honest non-guarantee. This shrinks the CLI to four verbs and stops
the weakest security primitive from shaping the strongest-looking surface.

**Cutting the `verify` ceremony is the third, on YAGNI.** A derived locator collapses
"wrong key" and "wrong binary" into one operator-visible failure (§5.2); the
four-code namespace and `--deny` priced distinctions the operator's actual question
("does this decrypt under this key?") does not need, for CI that does not yet exist.
E ships the essential question and defers the rest as backward-compatible additions
(§5.4).

**Topology-first docs are the fourth, and the most important for adoption.** Every
prior variant is a *mechanism* spec; none answers the adopter's first question —
*does this tool protect me?* E makes the topology decision tree (§1.1) and the
crypto-is-not-the-boundary statement (§1.2) the front page. This is not a code change;
it is the difference between a tool an adopter can correctly apply and one they
might deploy as false comfort in the distributed topology.

**Secret hygiene.** The owned `unlock_key` and `build_key` travel via env/file/stdin
only (§7), never argv or logs. **No binary embeds the `unlock_key`** — release embeds
only the operator-sealed wrapper; **debug embeds plaintext** (the defined,
non-shippable dev state, §3.3) and embeds no key. There is no dev key, no metadata
file, and the seed is never persisted or logged (B §7.3, inherited). The build host
holding all customers' keys (and `build_key`) is an accepted, documented trust
boundary (THREAT_MODEL.md); `build_key` is plaintext-equivalent (B §4.2.1).

**Testing strategy.** Inherit B/D's *crypto* matrix at the **release** profile
(reseal compartmentalization; `verify` decrypt-success; no-metadata-file decrypt;
opaque-wrapper trial-decrypt + scrub-clean of the `0x01,0x01` tell; release no-key
build failure; seed never persisted/logged incl. cached rebuild; pinned-seed
byte-identical blobs + edit-changes-nonce; machine-id off-box *cannot-check* vs
with-flags; `keygen` encoding; execute-locally provider proof). **Change/add for E:**
- **assert pass-through in debug** — a debug build of an example embeds the
  **plaintext** literal (it is findable by `strings`), carries **no wrapper, no
  locator, and no key**, and `cargo run` / `cargo test` succeed with
  `LITMASK_UNLOCK_KEY` **unset** and no other setup (E's central dev-loop claim);
- **assert type-identity across profiles (§3.2)** — `mask!` returns the identical
  type in debug and release; a test compiled against the debug expansion links and
  runs unchanged against the release expansion (no `&'static str`-vs-owned skew);
- **assert release seals normally** — the same example built `--release` with an
  explicit key produces the `locator ‖ wrapper ‖ provider_blob` layout, is
  scrub-clean of plaintext and of any litmask constant, and `verify` reports
  *decrypts* under the matching key and *does-not-decrypt* under another (§5.1/§5.2);
- **assert the provider blob (E.6 / R3a)** — the release region carries the sealed
  provider blob; it is AEAD ciphertext (scrub-clean, no `strings`-findable provider
  name, no static tell); it is **reseal-invariant** (byte-identical descriptor
  plaintext recovered after `reseal --from/--to`); `verify` of a binary whose
  compiled provider is `env` but checked with `--machine-id` reports
  *does-not-decrypt-as-deployed* (`EX_DATAERR`, distinct message), and
  `reseal --to-machine-id` on that binary **refuses** without `--force` (§5.3, §6.2);
- **assert the R1 type-check guard (§3.2.1)** — `cargo check` (debug) of an example
  whose `init!(custom: <expr>)` or `InitError` mapping is **ill-typed FAILS** (the
  release path is type-checked in debug, not cfg-stripped unparsed); and a
  well-typed example passes `cargo check` in **both** debug and `--release`;
- **assert the init! error path runs in release (R4)** — a release integration test
  drives `init!` with a wrong/absent key and asserts the `InitError` → `sysexit_code`
  mapping (the path a debug pass-through build never exercises);
- **assert the opt-in seal (§3.6)** — `Emit::new().seal_in_debug()` (or
  `LITMASK_SEAL=1`) makes a debug build seal like release and require a runtime key,
  reusing the release path (no plaintext literal in that debug binary);
- **assert `LITMASK_SEAL` ambient-env notice (§3.8 / R5)** — a debug build that
  seals because `LITMASK_SEAL` was read from the environment emits the one-line
  non-secret notice; the `seal_in_debug()` builder form is silent (explicit);
- **assert `verify` is two-code + cannot-check** — *decrypts* (`EX_OK`) /
  *does-not-decrypt* (`EX_DATAERR`) / *cannot-check* (`EX_UNAVAILABLE`); assert there
  is **no** `--deny` flag and **no** separate *key-fails* vs *locator-absent* code
  (§5.4 deferral is intentional, regression-guarded so it is not silently
  re-expanded);
- **assert the CLI surface is exactly {`verify`, `reseal`, `keygen`,
  `show-machine-id`}** — no `bind`, no standalone `machine-key`, no `derive`, no
  `record` (§6.4); `reseal --to-machine-id` derives the machine key internally;
- **assert `init_with!` is removed** and each §4bis form constructs the right
  provider in release while expanding to a no-op in debug pass-through; assert
  `build.rs` declares no provider (bytes-only);
- **assert no *broad* decl_blob** — the release embedded region is exactly
  `locator ‖ wrapper ‖ provider_blob` (the E.6 provider descriptor *only*); there is
  no per-blob offline-alignment data (C's decl_blob stays declined), and *runtime*
  alignment remains execute-locally (§5.5);
- **assert no dev-key artifacts exist** — there is no `K_dev` constant in any
  profile (D's test) **and** no dev keyfile / dev env var is read by `emit()` in
  debug (E's stronger claim): a debug build with no key set anywhere still builds and
  runs (contrast D, where a missing dev key in debug is a usage problem);
- **assert execute-locally is exercised** — the per-customer pipeline test runs the
  resealed **release** artifact once with the env cleared (machine-id) or with the
  production key (env/file) and asserts self-decrypt, standing in for the absent
  dev-loop provider run (§5.5).
Reuse the `example_scrub` harness (already release-building) for the crypto
assertions; one fixtures source per example (§10.1).

**Maintainer-CI note (R6 — litmask's own workbench, not Alice's loop).** Because the
default fast loop (`just test`, debug) is pass-through, it **exercises no crypto** —
a contributor can get green without touching the seal/wrapper/blob paths. So
litmask's own `just ci` MUST release-build the crypto matrix above (the
`example_scrub`/release harness), and `just ci` MUST run `cargo check --release` +
clippy on release to cover the §3.2.1-gated code that debug `cargo check` type-checks
but does not monomorphize for release. Document that the fast `just test` loop is
deliberately crypto-blind and `just ci` is the gate that proves masking. (This is a
maintainer concern; Alice's consumer loop is covered by §10.4's `cargo check
--release` guidance.)

## Honest Residuals (documented, not solved)

- **8.1 (provider *runtime success* not exercised in dev; *identity* now is)**:
  pass-through (§3) means the compiled-in provider's unseal does **not** run in the
  dev loop. R3a's E.6 blob recovers the cheaper half — provider **identity** mismatch
  is now caught offline by `verify`/`reseal` (§5.3, §6.2) — but a *runtime* wiring bug
  (host machine-id differs, salt wrong, env unpopulated) still first surfaces at
  execute-locally on the release artifact (§5.5). Accepted: the residual cost is small
  (D's dev provider-run was against a dev key anyway) and execute-locally is the
  authoritative runtime check regardless. Documentation makes the release smoke-test a
  required step; the §5.7 self-check hook is the deferred opt-in to automate it.
- **8.2 (default debug leaks plaintext to `strings` — the sharpest residual, R2)**:
  the default debug build carries plaintext, so it provides **zero** protection
  against the very static-analysis threat litmask exists to counter, and an
  accidental ship of `target/debug` exposes the masked secrets outright (worse than
  the always-seal variants, whose debug builds still resisted a casual `strings`).
  Accepted as a deliberate default (most debug builds never leave the host; debug is
  unshippable for many other reasons too), but **owned loudly** (§3.7): consumers with
  genuinely sensitive literals SHOULD enable §3.6 `seal_in_debug()`, and shippable-CI
  SHOULD refuse to package `target/debug`. The single escape hatch is one flag — far
  less than D's always-on dev-key machinery — but the default trade is real and stated.
- **8.3 (distributed-topology weakness)**: per §1.1/§1.3, litmask is obfuscation,
  not confidentiality, when the attacker controls the runtime host. machine-id
  raises the lateral-theft bar only. This is a *property of the problem*, not of E —
  E's contribution is to **state it loudly** rather than let the mechanics imply
  otherwise.
- **8.4 (deferred `verify` surface)**: the `--deny` lock-out and the
  four-code namespace are not shipped (§5.4); a consumer who later needs to branch
  CI on "wrong binary vs wrong key" must add the code (a clean, backward-compatible
  extension). Accepted under YAGNI for a pre-release tool with no external CI.
- **8.5 (build host trust boundary)**: unchanged from B/D — the host holding all
  customers' keys and `build_key` is an accepted, documented trust boundary
  (THREAT_MODEL.md). `build_key` is plaintext-equivalent (B §4.2.1).
- **8.6 (`init!` error path + call-ordering unexercised in dev, R4)**: because `init!`
  is a no-op success in debug (§3.1) and `mask!` needs no key, the `InitError` →
  `sysexit_code` mapping, the `?`-path, and the "`mask!` before `init!`" ordering
  contract are **never exercised by the pass-through dev loop**; they first run in
  release. Mitigated by the §3.2.1 type-check guard (the error-mapping code still
  type-checks in debug) and a required release integration test driving the error
  path (testing strategy); accepted that *behavioral* coverage of these paths lives
  at the release profile, not the fast loop.
- **8.7 (ambient `LITMASK_SEAL` is a residual seal-mode switch, R5)**: a stray
  `LITMASK_SEAL=1` in a developer's environment changes debug build behavior (seals,
  requires a key). E neutralizes the *silent* failure with the §3.8 notice and by
  making `seal_in_debug()` the primary explicit form, but the env channel remains a
  behavior switch. Accepted: it only ever *fails closed* (a debug build that wants a
  key it lacks fails to build — it can never wrong-key-seal), strictly milder than
  D's ambient *dev-key* footgun that E deleted.
- **8.8 (dev↔release context-switch; sensitive literals on dev hosts, R7/R8)**: a
  consumer iterating in pass-through must switch to `--release` + an `unlock_key`
  (+ a throwaway reseal for the machine-id case) to exercise the *real* sealed
  behavior locally — a heavier context-switch than D, where dev already had a key
  wired. And a sensitive literal is present in plaintext across every dev machine and
  every debug CI artifact by default (§3.7/§8.2). Both accepted as the cost of the
  pass-through default; the §3.6 opt-in covers the consumer who cannot accept the
  second.

## Out of Scope

Inherits D's Out-of-Scope set, plus E's additional declines:

- A CLI verb that compiles a target, and a `litmask run` exec/key-wiring verb
  (building is cargo's; the dev loop needs no run-wiring — it is pass-through).
- **A `verify --exec` flag** that runs the target to prove crypto worked — rejected,
  not merely deferred: "successful execution" is app-defined (servers never exit;
  CLIs error-exit on missing args), so exit-code/liveness cannot be read as crypto
  success without conflating the two (R3b).
- **The §5.7 runtime self-check hook** (`LITMASK_SELFCHECK` entry point) — a clean
  *deferred* future addition, not shipped now: it is the only litmask-defined way to
  automate the runtime-success check the E.6 blob cannot give, but it adds a runtime
  branch and a faint behavioral tell, so it waits for a concrete need (YAGNI).
- A managed seed/key **secret store**, or solving the build-host-holds-all-keys
  trust boundary (THREAT_MODEL.md, accepted).
- **A dev-time key of any kind** — no baked `K_dev` (D removed it) and no
  developer-supplied dev key/channel (E removes the *need*): the dev loop is
  pass-through (§3). The single escape hatch is the opt-in §3.6 seal-in-debug.
- **C's *broad* decl_blob (per-blob offline alignment), `derive`-verb consolidation,
  per-customer seed model, and workflow guard** (declined by D, still declined). E
  re-adds only the **minimal provider-descriptor blob** (E.6) for offline
  provider-identity checking — not C's per-blob alignment data.
- **A standalone `machine-key` verb, the legacy `bind` verb, B/D's `--deny`
  lock-out, and the four-outcome `verify` namespace** — machine-id is demoted to a
  provider (§6.3); `verify` is cut to decrypt-success (§5.1); the rest are deferred
  under YAGNI (§5.4) as backward-compatible future additions.
- Changing the wrapper crypto, `mask_key` derivation, or release-runtime failure
  paths (E inherits B/D's wrapper unchanged; its only release-layout addition is the
  E.6 provider-descriptor blob, and its only profile change is *withholding* the seal
  in debug, §3).
- Enforcing cross-customer key distinctness in the binary (provisioning, B §6.1).

## Decision delta vs `SPEC_DEVEX_D.md` (E inherits D's foundation; this is the E-only delta)

| Axis | **D (B minus `K_dev`)** | **E (pass-through dev + honest topology)** |
|---|---|---|
| `unlock_key` / locator / wrapper / `init!` / reseal | operator input / derived / opaque / single site / reseal-default | **inherited unchanged** |
| Dev-loop key | developer-supplied via a §8 channel (gitignored keyfile baseline), one-time setup | **none — debug is pass-through; no key, no file, no setup** |
| Dev-loop seals? | yes (under the dev key) | **no — literals compiled in the clear (§3.1)** |
| Debug binary | inert without the dev key | **carries plaintext (the ordinary non-shippable state); no key embedded** |
| Dev-key secret hygiene | required (§3.7: `/proc`, dumps, CI logs) | **none — no dev key exists** |
| Ambient-key release footgun | normative clean-env rule (§3.6) to prevent dev-key-sealed releases | **does not arise; clean-env release is ordinary CI discipline (§8.3)** |
| Dev exercises real provider | yes, for every family (against the dev key) | **no unseal in dev; provider *identity* checked offline via E.6 blob, *runtime* success via execute-locally (§5.5)** |
| Plaintext-free debug build | always (dev key seals) | **opt-in via `seal_in_debug()` / `LITMASK_SEAL=1` (§3.6)** |
| Release embedded region | `locator ‖ wrapper` | **`locator ‖ wrapper ‖ provider_blob` — minimal AEAD provider descriptor re-added (E.6) to catch identity mismatch offline (R3a)** |
| `verify` outcomes | four codes (coherent/locator-absent/key-fails/indeterminate) + `--deny` | **decrypts / does-not-decrypt / cannot-check, + provider-identity mismatch via E.6 blob (§5.3); `--deny` and the split deferred (§5.4)** |
| machine-id | core deployment concept; `machine-key` verb + `reseal --to-machine-id` | **one provider among several; no `machine-key` verb; derivation folded into `reseal` (§6.3)** |
| CLI surface | verify, reseal, keygen, machine-key, show-machine-id | **verify, reseal, keygen, show-machine-id (four verbs)** |
| Documentation order | mechanics first | **topology decision tree + crypto-is-not-the-boundary first (§1, §10.2)** |
| Threat honesty | machine-id framed as deployment binding | **server-side = protection, distributed = obfuscation, stated up front (§1.1/§1.3)** |
| Spec size / surface | smallest of A/B/C/D | **smallest overall — two more deletions than D (dev key + machine-id prominence) plus a `verify` cut** |
| Biggest risk | ambient dev key can seal a local release build; one-time dev setup | **debug carries plaintext by default — defeats static-analysis hiding if shipped (§8.2/R2); provider *runtime* success unexercised until execute-locally (§8.1)** |
