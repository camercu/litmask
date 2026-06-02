# litmask Developer-Experience — Specification (Variant F: Composable Providers, Distributed-Default)

> **Status:** design variant, refine phase. Seventh option beside
> `docs/SPEC_DEVEX.md` (build-generated key), `_A` (operator-owned key),
> `_B` (clean slate), `_C` (declarative + layered), `_D` (B minus `K_dev`),
> `_E` (pass-through dev + honest topology).
> **F adopts E's foundation** — operator-owned `unlock_key`, derived locator,
> opaque wrapper, reseal-default deployment, pass-through dev, single `init!`
> site, no-argv secret channels, topology-first docs — and makes **four**
> changes:
> (1) it **reframes the primary market**: the distributed / multi-tenant
> *obfuscation* topology is the ~80% case litmask serves, and the design optimizes
> that path as the **default road** rather than treating it as the weak edge E
> demoted — while keeping E's honesty that it *is* obfuscation;
> (2) it makes the key derivation a **three-layer model** (`material → unlock_key →
> mask_key`) so providers become **composable**;
> (3) it replaces E's `init!(source: …)` with a **flat provider grammar**
> (`init!(env: …)`, `init!(machine_id)`, `init!(custom: …)`) and adds a
> **`multi:` combinator** for two-factor unlock;
> (4) it **deletes user-configured salt entirely** — domain separation is a
> litmask-derived salt recomputed from the wrapper nonce, never embedded.
> Drafted for a deliberate side-by-side decision. If adopted, F replaces the other
> six. The project is **pre-release**, so F lands as a direct edit with no
> migration burden.

## Summary

E got the honesty right (state when litmask protects vs obfuscates) but drew the
wrong conclusion from it — it **demoted** machine-id and the per-customer
machinery as "serves the weak topology." The weak topology *is the market*. Most
consuming apps ship binaries to hosts the user/attacker controls, **knowingly
accept that this is obfuscation**, and choose litmask because they want to beat
the existing Rust string-obfuscation crates (`litcrypt`, `obfstr`). F keeps E's
honest framing and **re-centers the design on that majority path**, then adds the
one capability that makes the obfuscation case meaningfully stronger than the
competitors: **composable, multi-factor unlock**.

**What F keeps from E (mostly verbatim):**

- **Inverted key (A/B/E.1).** Operator owns `unlock_key`; the build seals under
  it and never generates it.
- **Derived locator (B/E.2).** No metadata file.
- **Opaque wrapper (B §2.5 / E.3).** No plaintext header bytes; cipher by
  trial-decrypt.
- **Pass-through dev (E §3).** Debug compiles literals in the clear; `init!` is a
  no-op; no dev key, no setup. Masking is a release property.
- **Reseal-default deployment (B §4 / E §8).** One universal build, re-keyed per
  customer; `reseal --to-machine-id` subsumes the legacy `bind`.
- **Single `init!` site (C/D/E §4bis).** One source-level provider declaration;
  `init_with!` removed; `build.rs` stays bytes-only.
- **Topology-first, honest docs (E §1).** Server-side = real protection;
  distributed = obfuscation. The crypto strength is not the security boundary; key
  custody is.
- **No-argv secret channels; smallest `verify` surface (E §5/§7).**

**What F changes over E — four moves:**

1. **Distributed-default reframing (F §1, replaces E's demotion).** machine-id and
   the per-customer path are the **main road**, not an afterthought under
   "providers." The docs lead with the distributed/multi-tenant case (the 80%),
   state plainly it is obfuscation, and frame litmask's value as a concrete
   improvement over `litcrypt`/`obfstr` (F §1.2). E's machine-id *demotion* (E §6.3)
   is reverted; E's machine-id *honesty* (E §1.3) is kept.

2. **Three-layer key model (F §2).** A provider no longer yields a finished
   `unlock_key`; it yields **material**. `unlock_key` is derived from material;
   `mask_key` is recovered from the wrapper under `unlock_key`. This single
   indirection is what makes composition possible without disturbing the
   wrapper/reseal invariants.

3. **Flat provider grammar + `multi` combinator (F §3, §4).** Drop E's `source:`
   prefix; name the provider directly. Add `multi: [..]` for **two-factor unlock**
   (`machine_id` + an external secret) — the capability that lets the distributed
   case resist a *local* attacker, which neither competitor nor single-factor
   machine-id can do (F §4.3).

4. **Delete user-configured salt (F §5).** No `init!(machine_id: "salt")`, no
   `--salt` ergonomics in the routine path. Domain separation is a
   **litmask-derived `machine_salt`** (`KDF(wrapper_nonce, "litmask-machine-id-salt-v1")`)
   recomputed on demand by runtime and CLI from the wrapper nonce — **never embedded**,
   so it adds no static tell (F §5.3, closes F-R8) and stays byte-reproducible
   transitively through the seed-derived nonce. The honest reason: a salt is non-secret
   and cannot stop a local attacker; only an external factor (F §4.3) can.

What F is, in one line: **E, re-centered on the distributed-obfuscation majority,
with composable multi-factor providers, a flat `init!` grammar, and salt reduced to
an internal `machine_salt` derived on demand from the wrapper nonce.**

## 1. Threat Topology & Competitive Frame (docs lead here)

> Doc-normative, as in E §1. F keeps E's two topologies verbatim and adds the
> competitive frame and the majority-market emphasis E lacked.

- **1.1 (the two topologies — = E §1.1, kept)**: documentation MUST open with the
  decision: *who holds the runtime key relative to the attacker?*
  - **Server-side** — binary runs on operator infrastructure; attacker gets the
    artifact, not the key. **litmask is real protection.**
  - **Distributed / multi-tenant** — binary runs on a host the user/attacker
    controls (desktop app, on-prem appliance, per-customer deployment). The
    attacker has the binary **and** the host the key must reach. **litmask is
    obfuscation.** A local attacker who runs the binary can read decrypted strings
    from memory or replay the decrypt path.
- **1.2 (the distributed case is the primary market — F-new, doc-normative)**: the
  documentation MUST state, and the design MUST assume, that the **distributed
  topology is the common case** for consumers: they ship to hosts they do not
  control, they **knowingly accept obfuscation**, and they adopt litmask to be
  **stronger than the existing Rust options**. The README frames litmask's
  improvement over those options concretely, not as a vague "more secure":
  - **`obfstr`** — XOR against a random per-build constant **baked into the
    binary**. Pure obfuscation; deobfuscated by running or emulating. No key
    management.
  - **`litcrypt`** — XOR against a compile-time env key **baked into the binary**
    (recoverable from the artifact). Reversible.
  - **litmask** — AEAD (not XOR) + the key lives **outside** the binary
    (env / file / machine-id / vault) + optional **machine-id binding** + optional
    **multi-factor unlock** (F §4). Three concrete wins even in the obfuscation
    topology:
    1. **AEAD vs XOR** — no frequency / known-plaintext shortcut; the attacker
       must execute the decrypt path, not statically analyze it.
    2. **Key out of the binary** — `strings`/disasm on the artifact yields nothing;
       the attacker additionally needs the *runtime environment*. The floor rises
       from "run `strings`" to "obtain a host secret." **Scope (normative, F-R4)**:
       this win is real only for providers whose material is **not derivable from the
       host or the artifact** — `env`/`file`/`custom` and any `multi` containing one.
       For **single `machine_id`** there is *no* external secret: the machine-id is
       read from the host and the salt is recomputed from the artifact (§5.2), so an
       attacker *on the authorized host* reconstructs the key. Single `machine_id`'s win
       is **#3 (per-host binding)**, not #2 — state it as such, do not claim "key out of
       the binary" for it.
    3. **Per-host binding / multi-factor** — a stolen binary is inert on another
       host (machine-id, F §4.2), and with a second factor (F §4.3) it is inert
       even on the authorized host without the external secret. Neither competitor
       has any equivalent.
  - The honest floor (doc-normative): a determined attacker **on the authorized
    host with all factors** still wins — the binary must run, so it must decrypt.
    litmask beats the competitors on every axis they compete on and adds one they
    do not; it does not turn obfuscation into confidentiality. State this plainly.
- **1.3 (crypto strength is not the boundary — = E §1.2, kept)**: key custody is
  the boundary, not cipher choice. AEAD earns its keep in the server-side topology
  and, in the distributed topology, by making the decrypt path non-trivial and the
  key external — not by being "unbreakable" on a host the attacker owns.
- **1.4 (machine-id honesty — = E §1.3, kept; demotion reverted)**: machine-id's
  guarantee is "a binary bound to host A will not self-decrypt on host B"; its
  non-guarantee is "on host A, a local attacker re-derives the machine key from the
  same machine-id the runtime reads." F keeps this statement **and** keeps
  machine-id structurally central (it is the default distributed path), because the
  honest non-guarantee is exactly *why* F offers the second factor (F §4.3) rather
  than pretending machine-id alone is a wall.

## 2. Three-Layer Key Model (the enabling indirection)

> Normative. This is the structural change that makes composition possible. The
> wrapper, `mask_key`, and reseal invariants of B/E are **unchanged**; F only
> inserts a derivation step *above* `unlock_key`.

The key chain has three layers, each with one job:

```
material        →   unlock_key       →   mask_key        →   plaintext
(from provider)     (per F §2.2)         (in the wrapper)     (the literal)
```

- **2.1 (material — normative)**: a provider yields **material**: raw bytes from
  its source — the decoded env/file key, the machine-id derivation, custom bytes.
  Material is **not** itself a finished key contract; it is the input to §2.2, which
  normalizes it. The provider trait is:
  ```rust
  trait KeyMaterial {
      fn material(&self) -> Result<Zeroizing<Vec<u8>>, KeyError>;
  }
  ```
  All built-ins (`env`, `file`, `machine_id`) and `custom:` providers implement
  this one method. (This **renames/refocuses** B/E's `KeyProvider`: the old trait
  returned a key to unseal with; the new one returns material to derive from.)
  **Material may be any length** — §2.2 always runs it through a KDF, so there is no
  32-byte requirement on a provider's output and the same provider behaves
  identically standalone and inside `multi` (closes the single-vs-composite length
  hazard, red-team F-R3).
- **2.2 (unlock_key derivation — always normalized, normative)**: there is **no**
  verbatim path; **every** provider configuration derives the `unlock_key` through
  the workspace BLAKE3 KDF, so material of any length and any provider mix collapses
  to a uniform 32-byte key:
  ```
  unlock_key = KDF(info = "litmask-unlock-v1",  ikm = Σ len_prefixed(material_i))
  ```
  with materials in **declared order** (one element for a bare provider, ≥2 for
  `multi`, §4). Length-prefixing + the fixed `info` make the mixing canonical and
  order-significant (§4.4). Consequence vs E: the operator's `keygen`-minted key set
  in `env`/`file` is now the **material**, not the `unlock_key` itself — the build
  seals under `KDF(…material…)`, and both sides recompute the same normalization
  (F §6.1), so the operator-facing workflow (`keygen` → set env → build) is
  unchanged even though the byte fed to AEAD is now the KDF output.
- **2.3 (mask_key — unchanged, = B/E)**: `mask_key` is build-minted, sealed in the
  wrapper under `unlock_key`, and **never** supplied by an operator or a provider.
  The wrapper indirection is what makes reseal cheap: re-keying a customer changes
  the wrapper (sealed under a new `unlock_key`) while `mask_key` and every blob stay
  byte-identical (F §6.2). An operator-supplied `mask_key` would delete reseal and
  force a rebuild per customer; this is explicitly rejected.
- **2.4 (why material ≠ unlock_key ≠ mask_key — normative rationale)**: material
  sits one layer below `unlock_key` for two reasons — to **normalize** arbitrary
  provider output to a fixed key (§2.2) and to enable **composition** (several
  materials mixed into one key, §4). `unlock_key` sits one layer below `mask_key`
  solely to enable reseal. Neither material nor `unlock_key` ever touches a data
  blob; only `mask_key` does. The operator never sees `mask_key`.

## 3. Provider Grammar (flat; `source:` removed)

> Normative. Replaces E §4bis's `init!(source: <literal>)` form with a flat
> grammar that names the provider directly. `init_with!` stays removed;
> `build.rs` stays bytes-only; pass-through-debug behavior (E §3, §4bis note) is
> unchanged (all forms expand to a no-op success in debug, constructed-and-
> type-checked but not executed).

- **3.1 (forms)**:
  ```rust
  init!()                                       // = env provider, LITMASK_UNLOCK_KEY (§3.2)
  init!(env: "MY_KEY")                          // env var named MY_KEY
  init!(file: "/run/keys/cryptio")              // key read from a file path
  init!(machine_id)                             // per-host derivation (§5)
  init!(custom: VaultProvider::new("vault/cryptio"))  // any expr: impl KeyMaterial
  init!(multi: [machine_id, env: "MY_KEY"])     // two-factor (§4)
  ```
- **3.2 (empty default — = E, kept)**: `init!()` constructs the env provider reading
  the default `LITMASK_UNLOCK_KEY`. The build default (F §6.1), `verify`, and this
  runtime default MUST all read `LITMASK_UNLOCK_KEY`; divergence is a spec
  violation (B §1.1.1).
- **3.3 (argument rules — normative)**: `env:` and `file:` take a **string
  literal** (a non-literal is a compile error, = E). `machine_id` takes **no
  argument** (the salt is internal, §5 — `init!(machine_id: "…")` is a compile
  error with a message pointing at the generated-salt rationale). `custom:` takes
  any expression implementing `KeyMaterial` (§2.1).
- **3.4 (the `init!` macro emits the provider descriptor — = E.6, kept and
  extended)**: in **release**, the `init!` macro emits the AEAD-sealed provider
  descriptor blob (sealed under `mask_key`, reseal-invariant, no static tell) so
  `verify`/`reseal` catch a provider/seal **identity** mismatch offline (E §5.3,
  §6.2). F extends the descriptor to encode the **full factor set** of a `multi`
  declaration (e.g. `[machine_id, env(MY_KEY)]`), so `reseal` can validate that a
  `--to-machine-id` reseal targets a binary whose factor set actually includes
  `machine_id` (F §6.2). The descriptor remains identity-only; **runtime success**
  is still execute-locally (E §5.5).

## 4. Composition — `multi` (two-factor unlock)

> Normative. F's headline capability for the distributed market: combine a host
> factor with an external secret so a *local* attacker cannot unlock the binary.

- **4.1 (grammar)**: `init!(multi: [<provider>, <provider>, ...])`. The list reuses
  the exact provider tokens of §3.1; they nest with identical syntax:
  ```rust
  init!(multi: [machine_id, env: "CRYPTIO_KEY"])
  init!(multi: [machine_id, custom: VaultProvider::new("vault/cryptio")])
  ```
- **4.2 (machine-id factor — the distributed default)**: `machine_id` contributes
  per-host material (§5.2). Used **alone** (`init!(machine_id)`) it gives lateral-
  theft resistance only (binary inert on another host) and is honest obfuscation
  on the authorized host (§1.4) — already better than `obfstr`/`litcrypt`, which
  bake their key in the artifact.
- **4.3 (the second factor raises the local bar — against a *different-UID* attacker
  — normative, doc-normative)**: an external factor (`env`/`file`/`custom`) contributes
  material the binary does **not** carry. A **different-UID** co-resident process can
  read the victim's binary file (and any value embedded in it) but **not** the victim's
  runtime environment or memory (process/UID isolation). Therefore:
  - `multi: [machine_id, env: "…"]` is inert on another host (machine-id mismatch)
    **and** inert on the authorized host for a different-UID attacker without the
    external secret. This is the strongest position the distributed topology admits,
    and the concrete answer to "stop a *different-UID* second app on the host from
    deriving the key."
  - **Honest limit (normative, F-R1)**: a **same-UID** attacker (the victim's own
    UID, or root) is **not** stopped by any factor. Same-UID can read
    `/proc/<pid>/environ` and read `--key-file` paths of the running victim, and can
    `ptrace` the process to lift the decrypted plaintext directly from memory — so it
    obtains the env/file factor *and* can bypass the whole decrypt path. The external
    factor defends the **different-UID / off-host / no-live-process** boundary, not the
    same-UID one (= §5.1). Documentation MUST state this scoping, MUST state that
    **machine-id alone does not stop even a different-UID local attacker** (it only
    blocks lateral theft to another host), and MUST present `multi` as the recommended
    posture for sensitive literals while naming the same-UID residual (R-1).
- **4.4 (derivation — the same universal rule as §2.2, normative)**: composition is
  not a special case; it is §2.2 with ≥2 materials. `unlock_key = KDF(info =
  "litmask-unlock-v1", ikm = Σ len_prefixed(material_i))` in **declared order**.
  Order is significant; reordering the list yields a different `unlock_key` and
  therefore a different wrapper/locator — `reseal` of a composite binary MUST use
  the same factor order (the descriptor blob, §3.4, records it). A missing or wrong
  **any** factor yields the wrong `unlock_key` and the wrapper does not open: there
  is **no partial success**.
- **4.5 (cardinality — normative)**: a `multi` list with **fewer than two**
  elements is a compile error (use the bare form); an empty list is a compile
  error.

## 5. Domain Separation by Derived Machine-ID Salt (no user salt)

> Normative. F **deletes** B/E's user-facing salt concept (`--salt`,
> `init!(machine_id: "salt")`). Domain separation is provided by a
> litmask-derived salt, computed on demand from the wrapper nonce — no separate
> embedded region, no extra static tell.

- **5.1 (the salt is non-secret and cannot defend — normative rationale)**: a salt
  in the machine-id derivation is **non-secret by definition**. Whatever its value,
  it must be available to the runtime on the host and is therefore readable by a
  local attacker who reads the binary. A salt — random, app-named, or user-chosen —
  **cannot** stop a co-resident attacker from re-deriving the machine key. The only
  thing that raises the bar against a *different-UID / off-host* attacker is an
  external factor (§4.3); against a *same-UID* attacker nothing does (F-R1). The
  salt's *real* job is narrower: **domain separation** — preventing two litmask apps
  on the same host from deriving the same machine key (which would let one app's
  binary unwrap the other's wrapper). Because that job needs uniqueness, not
  secrecy, a generated salt serves it with **zero configuration**.
- **5.2 (machine-id material — derived salt, normative)**: `machine_id` material is
  `KDF(ikm = machine_id_value, salt = machine_salt, info = "litmask-machine-id-v1")`,
  where `machine_salt = KDF(ikm = wrapper_nonce, info = "litmask-machine-id-salt-v1")`.
  The salt is **not stored**; the runtime and the CLI **recompute** it on demand from
  the wrapper nonce — the same plaintext `nonce(12)` at the front of the 61-byte
  wrapper that `derive_weak_xor_key` already keys on (B OQ-1). The salt is the
  security-critical value of this derivation, hence its own versioned KDF domain tag
  `"litmask-machine-id-salt-v1"` (versioned so the derivation scheme can rev without a
  silent reinterpretation, as for the locator KDF info string).
  - **The salt MUST derive from the wrapper nonce, NOT the locator (normative
    constraint)**: the locator is `KDF(unlock_key, …)`, and `unlock_key` depends on the
    machine material, which depends on the salt — deriving the salt from the locator is
    circular. The wrapper nonce is chosen at seal time independently of `unlock_key`, so
    it breaks the cycle.
- **5.3 (no embedded salt region — normative, replaces the former weak-masked embed;
  closes red-team F-R8)**: because §5.2 recomputes `machine_salt` from the wrapper
  nonce, the release binary embeds **no** machine-id-specific bytes. A `machine_id`
  binary is therefore **byte-structurally identical** to a non-`machine_id` binary
  (both = `locator(12) ‖ wrapper(61) ‖ provider_blob`); there is no extra region whose
  presence fingerprints "machine-id compiled in." This is strictly stronger than
  weak-masking a distinct region — the static tell is **removed**, not obfuscated.
- **5.4 (the reseal invariant — pure function of the wrapper nonce — normative;
  subsumes the former F-R2 carried-in-artifact rule)**: the governing rule is
  **`reseal` reads everything it needs from `(operator-supplied factors) ∪ (the
  artifact)`; the seed is the one thing it must never require.** `machine_salt`
  satisfies this trivially: it is a **pure function of the wrapper nonce**, which is
  present in every artifact, so `reseal` recomputes it without the seed. The
  derivation is **self-consistent across reseal even if reseal regenerates the wrapper
  nonce** — `reseal` derives the salt from the *same* nonce it seals the new wrapper
  under, and the runtime later recomputes the identical salt from that nonce. There is
  nothing to "preserve across reseal" (the former embed had to survive verbatim;
  recomputation makes that obligation disappear). Bit-reproducibility is preserved
  transitively: the wrapper nonce is seed-derived on the original pinned-seed build (B
  §7.2), so the salt is deterministic there (B §7.4 supply-chain attestation).
- **5.5 (no user salt surface — normative)**: there is **no** `init!(machine_id:
  …)` form, **no** `--salt` flag on `reseal`/`verify` in the routine path, and no
  documented user salt concept. An operator who needs a *secret* per-tenant
  divergence uses a **second factor** (§4.3, e.g. a per-tenant `env` value), which
  is the honest mechanism; a non-secret divergence is already provided by the
  generated `machine_salt`. If a concrete need for an explicit, pinned namespace across
  independent builds ever lands, it is a clean future addition (Out of Scope) —
  YAGNI until then ([[feedback_yagni_over_speculative]]).

## 6. Tooling / CLI Surface (machine-id re-centered, surface unchanged)

The distributable CLI is **{`verify`, `reseal`, `keygen`, `show-machine-id`}** —
the same four verbs as E, configless (`(binary, key)` only), never compiling, no
`run` verb. F changes **emphasis and reseal validation**, not the verb set.

- **6.1 (`keygen` / build-time seal — = E §6.1 / §4)**: `keygen` mints a 32-byte
  `unlock_key` (CSPRNG, base64url, no padding), prints only the key (F §7). For a
  release build, `emit()` reads the build-time material, validates it, derives the
  `unlock_key` (§2.2), and seals `mask_key` under it. No salt is embedded:
  `machine_salt` is recomputed on demand from the wrapper nonce (§5.2/§5.3). The
  material is never generated by the build and never written to any artifact. Debug
  seals nothing (pass-through, E §3).
- **6.1.1 (build-sealability per provider — F-new, normative, resolves red-team
  F-R5)**: the
  build seals only what its **material** is available at build time. Because §2.2
  derives `unlock_key` from material identically on both sides, any factor whose
  material `emit()` can compute is **build-sealable** (the universal build ships
  pre-keyed; no post-build reseal needed for that factor):
  - **`env` / `file`** — build-sealable: `emit()` reads the value at the cargo
    boundary (F §7), the default `LITMASK_UNLOCK_KEY` or `Emit::new().key_var(…)` /
    `key_file(path)`.
  - **`machine_id`** — build-sealable **by passing the target machine ID in a
    build-time environment variable**, which `emit()` feeds into the §5.2 derivation
    exactly as the runtime would. (Without it, the binary is sealed for *no* host and
    must be `reseal --to-machine-id`'d per customer — the routine distributed flow,
    §6.2.) There is no way to seal machine_id from the host's own ID at build time
    unless the build runs on that host; the env-var path is the general mechanism.
  - **`custom:`** — **reseal-only by default**: `emit()` cannot execute an arbitrary
    runtime provider, so it cannot know the material a `custom` factor returns. The
    **only** exception is the operator passing `emit()` the **exact material the
    custom provider will return at runtime** (over a §7 channel); then it is
    build-sealable like any other byte string. Otherwise a `custom` factor is sealed
    via `reseal`.
  - **`multi`** — build-sealable iff **every** factor in the set is (§4.4 composes
    all materials); a single reseal-only factor (`custom` without supplied material)
    makes the whole set reseal-only.
- **6.2 (`reseal` — composite-aware, = B/E §6.2 extended)**: `litmask reseal
  <binary> --from <keysrc> --to <keysrc> [-o <out>]` re-keys the wrapper and its
  derived locator; `mask_key`, blobs, and the provider descriptor are unchanged (all
  sealed under the unchanged `mask_key`, so they survive reseal verbatim). The
  machine-id destination is the same verb: `reseal … --to-machine-id <id>` (subsumes
  `bind`; the salt is **recomputed from the wrapper nonce**, §5.2 — **no `--salt`**,
  nothing to carry over). If `reseal` regenerates the wrapper nonce, it derives the
  target salt from that new nonce and the runtime recomputes the identical value
  (§5.4).
  - **Composite targets**: to reseal to a `multi` factor set, `reseal` needs **all
    target factors** (`unlock_key` = compose of all materials, §4.4). The common
    multi-tenant shape is a **shared external secret + per-customer machine-id**, so
    the routine call is `reseal --to-machine-id <bob>` with the shared external
    secret supplied over a §7 channel; `reseal` recomputes `machine_salt` from the
    wrapper nonce (§5.2) and reads the factor order/set from the descriptor (§3.4),
    then composes the target `unlock_key`.
  - **Naming multiple external factors (normative, F-R6)**: when a `multi` target has
    **more than one** external factor, each is supplied over its own §7 channel and
    **matched to the descriptor's declared factor order** (§4.4): the `--to-*` secret
    channels (`--to-env`/`--to-file`/`--to-stdin`) **repeat**, and the n-th occurrence
    binds to the n-th external factor in declared order (`machine_id` factors are
    skipped — they come from `--to-machine-id`/derivation). A count mismatch between
    supplied channels and descriptor external factors is a hard error, not a silent
    miscompose. The verbose fully-per-tenant shape is the honest cost flagged in R-3.
  - **Identity guard (= E R3)**: `reseal --to-machine-id` against a binary whose
    descriptor factor set does **not** include `machine_id` **refuses by default**
    with a clear message, overridable with `--force`. Points at execute-locally
    (E §5.5) for the runtime-success check the descriptor cannot give.
- **6.3 (machine-id is the distributed default, documented front-and-center —
  F-new, reverts E §6.3 demotion)**: `show-machine-id` prints this host's machine
  ID (non-secret, §7-exempt) for off-box derivation. The machine-key derivation is
  reached through `reseal --to-machine-id` (the only operation that needs it); F
  ships **no** standalone `machine-key` verb (its only consumer is `reseal`). The
  **documentation difference vs E**: machine-id and the per-customer reseal flow are
  presented as the **primary distributed-deployment path** (the 80% case, §1.2),
  with the two-factor `multi` form as the recommended hardening — *not* tucked under
  a generic "providers" list as one option among equals. The honesty of §1.4 is
  attached to it, but its structural prominence matches its real-world centrality.
- **6.4 (no `derive`, `bind`, `machine-key`, `record` — = E §6.4)**: unchanged from
  E. Key management (provisioning, derivation-from-master, attribution) is the
  operator's existing infrastructure composed with litmask's minimal seam.

## 7. Secret Input Channels (= B §8 / E §7)

Carried verbatim: any subcommand consuming a secret key (`verify`,
`reseal --from/--to`, and each factor of a composite `--to`) accepts it **only**
via non-argv channels — default `LITMASK_UNLOCK_KEY` env, `--key-env <NAME>` (per
role `--from-env`/`--to-env`), `--key-file <path>`, `--key-stdin`. **No `--key
<value>` flag.** Secret-emitting verbs (`keygen`) print only the value to stdout.
Build-time injection reads the env/keyfile at the cargo boundary (facilitated, not
enforced). The seed is never persisted or logged (B §7.3); `machine_salt` is not
stored at all — it is recomputed from the (non-secret, plaintext) wrapper nonce
(§5.2), and is itself non-secret (§5.1).

## 8. Inherited Foundation, Dev Loop, Diagnostics, Examples

F inherits, unchanged, the following from E (which inherits them from B/D):

- **Foundation (E §2)**: inverted key (E.1), derived locator (E.2), opaque wrapper
  (E.3, `nonce(12) ‖ AEAD(version_byte ‖ mask_key)(33) ‖ tag(16)` = 61 bytes), mute
  release failures (E.4), release-only seal (E.5), provider descriptor blob (E.6,
  extended per §3.4). The release embedded region is `locator(12) ‖ wrapper(61) ‖
  provider_blob` — **identical whether or not a `machine_id` factor is compiled in**,
  because the salt is recomputed from the wrapper nonce and never embedded (§5.3,
  closes F-R8). A debug binary embeds the plaintext literal and carries none of these.
- **Pass-through dev (E §3)**: debug compiles literals in the clear; `init!` is a
  no-op success; no dev key, no setup; the §3.2.1 type-check guard keeps the release
  path type-checked in debug; the §3.6 `seal_in_debug()` opt-in and §3.8
  `LITMASK_SEAL` ambient-notice are unchanged. The §3.7/§8.2 honest residual
  (default debug carries plaintext) applies unchanged.
- **`verify` cut to the essential question (E §5)**: decrypts / does-not-decrypt /
  cannot-check, plus the provider-identity mismatch (E §5.3, extended to factor-set
  mismatch per §3.4). `--deny` and the four-code namespace remain deferred (E §5.4).
- **Diagnostics gating (E §9)**: strings gated on the real `PROFILE`-derived `cfg`; F
  adds **no** new artifact constant — `machine_salt` is recomputed, not embedded
  (§5.3), so there is no added static tell.
- **Examples & docs (E §10)**: topology decision tree + competitive frame lead
  (§1.1/§1.2); pass-through run docs; one fixtures source per example; at least one
  example per provider form including `multi`.

## Honest Residuals (documented, not solved)

- **R-1 (distributed = obfuscation, even multi-factor; same-UID is irreducible)**:
  `multi: [machine_id, env]` raises the floor to "attacker needs the binary, the host,
  **and** the external secret," but on the authorized host with all factors the binary
  must run and therefore must decrypt — the irreducible bottom row of §1.2. Concretely
  (F-R1, §4.3): a **same-UID** attacker (or root) reads `/proc/<pid>/environ` and
  key-file paths and `ptrace`s decrypted plaintext out of memory, defeating **every**
  factor; the external factor only defends the different-UID / off-host / no-live-
  process boundary. F states this; it does not pretend otherwise.
- **R-2 (the salt is non-secret)**: `machine_salt` is recomputable by anyone holding
  the binary (it is a KDF of the public wrapper nonce, §5.2). It provides domain
  separation, not confidentiality (§5.1). This is not a regression from the former
  embed — the salt was never secret — and it removes the static tell (§5.3, F-R8).
  Theft resistance is machine-id; local-attacker resistance is the external factor —
  never the salt.
- **R-3 (composite reseal needs all factors)**: re-keying a `multi` binary requires
  every target factor (§6.2). The routine shared-secret + per-customer-machine-id
  shape keeps this to one `--to-machine-id` call plus a channel-supplied shared
  secret, but a fully per-tenant factor set is more verbose — honest, since a 2FA
  wrapper cannot be resealed with one factor.
- **R-4 (provider *runtime success* — and `multi` composition — unexercised in dev)**:
  = E §8.1, extended for F (F-R7). Pass-through means the provider's unseal first runs
  at execute-locally on the release artifact; the **`multi` composition itself** —
  factor order, length-prefixed mixing, all-or-nothing (§4.4) — is likewise a
  release-only code path and is *never* executed in pass-through debug (where `init!`
  is a no-op). The descriptor (§3.4) catches **identity/factor-set** mismatch offline;
  host machine-id match, env populated, correct factor *values* and their composition
  are execute-locally. Examples MUST include a release execute-locally run of at least
  one `multi` binary so the compose path is exercised somewhere.
- **R-5 (default debug leaks plaintext)**: = E §8.2/§3.7, unchanged. The §3.6
  opt-in covers consumers who cannot accept it.
- **R-6 (build host trust boundary)**: = E §8.5 / B §4.2.1, unchanged.
- **R-7 (the descriptor is readable by a key-holder, F-R9)**: the provider descriptor
  (§3.4) is sealed under `mask_key`, so anyone who can recover `mask_key` (a legitimate
  key-holder, or an attacker who already has the unlock factors) can read the **factor
  set and order**. This is not a confidentiality breach — recovering `mask_key` already
  means the plaintext is exposed — but the factor *topology* is not hidden from a
  party that holds the key. It is hidden from a static/offline attacker without the key
  (the descriptor has no plaintext tell). F accepts this: the descriptor's job is
  offline reseal/verify validation, not secrecy from key-holders.
- **R-8 (`KeyProvider` → `KeyMaterial` is a breaking API change, F-R10)**: the
  three-layer model (§2.1) renames and re-types the public provider trait (returns
  *material* to derive from, not a finished key). This breaks any external
  `impl KeyProvider`. Accepted because litmask is **pre-release** (no stability
  promise yet); it lands as a direct rename with no shim. If F is adopted, the
  migration note is "rename the trait, return raw material instead of a 32-byte key —
  §2.2 now normalizes it."

## Out of Scope

Inherits E's Out-of-Scope set, plus F's additional declines:

- **User-configured salt of any kind** — no `init!(machine_id: "…")`, no `--salt`.
  Secret per-tenant divergence is a second factor (§4.3); non-secret divergence is
  the generated `machine_salt` (§5). An explicit pinned namespace across independent builds
  is a clean *future* addition if a concrete need lands (YAGNI).
- **Operator-supplied `mask_key` / collapsing the wrapper indirection** — would
  delete reseal and force per-customer rebuilds (§2.3).
- **A crate split (core vs distributed)** — the distributed-obfuscation path is the
  default road and stays in the one crate; topology is a provider choice plus a doc
  claim, not a code boundary (§1).
- **Single-factor partial unlock** — a `multi` set is all-or-nothing (§4.4); there
  is no threshold/any-of mode.
- Everything E lists: a compile verb / `litmask run`; `verify --exec`; the
  `LITMASK_SELFCHECK` hook (deferred); a managed secret store; C's broad decl_blob,
  `derive` consolidation, per-customer seed model, workflow guard; a standalone
  `machine-key`/`bind` verb; `--deny` and the four-code `verify` namespace
  (deferred).

## Decision delta vs `SPEC_DEVEX_E.md` (F inherits E's foundation; this is the F-only delta)

| Axis | **E (pass-through dev + honest topology)** | **F (composable providers, distributed-default)** |
|---|---|---|
| Foundation / pass-through dev / opaque wrapper / reseal-default / no-argv channels | inverted key, derived locator, release-only seal, four-verb CLI | **inherited unchanged** |
| Primary market framing | topology honest, but machine-id **demoted** as the weak path | **distributed/multi-tenant obfuscation is the primary 80% path; machine-id re-centered** (§1.2, §6.3) |
| Competitive frame | absent | **explicit improvement over `obfstr`/`litcrypt`: AEAD + key-out-of-binary + binding/multi-factor** (§1.2) |
| Key model | provider → `unlock_key` → `mask_key` (two derivation roles) | **material → `unlock_key` → `mask_key`** (three layers, `KeyMaterial` trait) (§2) |
| Providers composable? | no — one provider per binary | **yes — `multi: [..]` two-factor unlock** (§4) |
| `init!` grammar | `init!()`, `init!(source: <literal>)`, `init!(custom: <expr>)` | **flat: `init!(env:)`/`init!(file:)`/`init!(machine_id)`/`init!(custom:)`/`init!(multi: [..])`** (§3) |
| Local-attacker resistance | machine-id only (honest: none on host) | **`multi: [machine_id, env]` — external factor the binary does not carry** (§4.3) |
| Salt | user-facing (`--salt`, machine-id salt) | **deleted — internal `machine_salt` = `KDF(wrapper_nonce, "litmask-machine-id-salt-v1")`, recomputed on demand, never embedded (no static tell, F-R8); byte-reproducible via the seed-derived nonce** (§5) |
| Provider descriptor | provider family (E.6) | **full factor set + order** (§3.4) so composite reseal validates offline |
| `reseal` | `--from/--to`, `--to-machine-id --salt` | **composite-aware (needs all target factors); no `--salt` (`machine_salt` recomputed from wrapper nonce)** (§6.2) |
| machine-id placement in docs | under "providers," one of many | **front-and-center distributed default, with §1.4 honesty attached** (§6.3) |
| Spec size / surface | smallest of A–E | **E + composition/material layer + flat grammar − user salt** |
| Biggest risk | debug plaintext default; provider runtime success unexercised until execute-locally | **same, plus composite reseal verbosity for fully per-tenant factor sets (R-3); material/trait rename touches the provider API** |
