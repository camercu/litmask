# litmask Developer-Experience — Specification (Variant G: Nonce-Derived Default, Provisioning-Aware Tiers)

> **Status:** design variant, refine phase. Eighth option beside
> `docs/SPEC_DEVEX.md` (build-generated key), `_A` (operator-owned key),
> `_B` (clean slate), `_C` (declarative + layered), `_D` (B minus `K_dev`),
> `_E` (pass-through dev + honest topology), `_F` (composable providers,
> distributed-default).
> **G adopts F's foundation** — three-layer key model, composable
> providers, flat `init!` grammar, `multi:` two-factor, derived `machine_salt`,
> opaque wrapper, reseal-default deployment, topology-first docs — and makes
> **three** changes:
> (1) it **inverts the zero-config default**: bare `init!()` no longer means
> "env provider, fail loud if unset" (F §3.2). It means **nonce-derived Tier-0 key**:
> the build derives an `unlock_key` from the wrapper nonce (`KDF(nonce)`, the same
> construction as F's `machine_salt`) and recomputes it at runtime — nothing minted,
> nothing stored. The default *just works* with no key, no `keygen`, no env var —
> litmask **degrades gracefully to an AEAD upgrade of `obfstr`**, and the floor is
> **bit-reproducible**. Every stronger provider is **opt-in added ceremony the
> consumer chooses**.
> (2) it **states the provisioning-channel assumption explicitly** (G §0) and
> **organizes the providers into three deployment tiers** mapped to the three real
> distribution shapes — shrink-wrap, managed per-customer, centrally hosted.
> (3) it **drops E/F's pass-through dev** (G §3.2): debug builds **seal** like
> release, so the dev loop exercises the real crypto path and a debug binary never
> carries plaintext (closes F-R5). Zero-wiring dev is **not new machinery** — it is a
> usage pattern: a consumer degrades to Tier 0 (bare `init!()`) for quick local checks
> without removing litmask, then names their real provider again. Accidental ship of
> such a build degrades to the obfuscation floor, never plaintext.
> Drafted for a deliberate side-by-side decision. If adopted, G replaces the other
> seven. The project is **pre-release**, so G lands as a direct edit with no
> migration burden.

## Summary

F got the composition model and the honest topology right, but kept E's **wrong
default**: bare `init!()` is the env provider, which **aborts the release binary
when `LITMASK_UNLOCK_KEY` is unset**. That is ceremony at step zero — the consumer
must mint a key and wire it before the library produces a working binary at all. A
string-obfuscation library should produce a *working, protected* binary the moment
it is added, the way `obfstr` does, and reserve key management for consumers who
**ask** for it.

G makes the **default tier dead-simple and strictly better than the competitors**,
then layers custody and binding as **opt-in** choices for consumers whose
deployment shape (and provisioning infrastructure, G §0) can use them.

**The product G leads with (headline value — doc-normative).** litmask's
differentiated, defensible value is **many sensitive strings masked in-place,
unlocked by ONE externally-held key, in a single offline artifact, re-keyable per
customer without a rebuild.** That is neither `obfstr` (no key management) nor a
secrets-manager (fetch each value at runtime). It is the answer for a consumer who
has *hundreds of scattered literals* they want masked where they sit — not
refactored into N runtime fetches — and who can deliver *one small key* (not the
whole secret set) to the runtime. The `obfstr` comparison is the **floor**, not the
pitch: it explains the zero-config Tier-0 onboarding state, and litmask beats it
there, but the floor is not the product. (E's instinct — be skeptical of leading
with obfuscation — was right; F over-rotated to "obfuscation is the 80% market." G
re-headlines on the masked-in-place + single-key-custody + reseal workflow, while
keeping F's entire tooling stack unchanged. See §0.4 for why runtime-fetch does not
substitute.)

**The one product principle G asserts:** *the floor should cost nothing and the
ceiling should be reachable.* `obfstr`-grade protection is the zero-config floor;
key-out-of-binary and per-host binding are one provider token away.

**What G keeps from F (verbatim, the entire stack):**

- Three-layer key model (`material → unlock_key → mask_key`), `KeyMaterial` trait
  (F §2).
- Flat provider grammar + `multi:` two-factor unlock (F §3, §4).
- Derived `machine_salt` = `KDF(wrapper_nonce, "litmask-machine-id-salt-v1")`,
  recomputed on demand, never embedded (F §5).
- Opaque wrapper `nonce(12) ‖ AEAD(version_byte ‖ mask_key)(33) ‖ tag(16)` = 61 B,
  derived locator, reseal-default deployment, sealed provider descriptor (F §8).
- Topology-first honest docs, competitive frame vs `obfstr`/`litcrypt` (F §1).
- `{verify, reseal, keygen, show-machine-id}` CLI, no-argv secret channels
  (F §6, §7).

**What G does NOT keep from F:** pass-through dev (E §3 / F §8). Debug now seals
(G §3.2); the plaintext-in-debug residual (F-R5) is gone, and zero-wiring dev is
just Tier 0 used as a dev usage pattern (G §3.2) — no separate dev-key mechanism.

**What G changes over F — three moves:**

1. **Nonce-derived default key (G §1, replaces F §3.2).** Bare `init!()` falls back
   to an `unlock_key` **derived from the wrapper nonce** (`KDF(nonce,
   "litmask-tier0-v1")`), recomputed at runtime — not a stored or baked constant
   (mirrors F's `machine_salt`). No env var, no `keygen`, no failure mode, and —
   because the nonce is seed-derived — **bit-reproducible** like the rest of the
   build. The honest cost: the key is **recoverable from the artifact** (anyone can
   KDF the public nonce), so it earns F's win #1 (AEAD vs XOR) but **not** #2 (key
   out of binary) or #3 (binding). It is `obfstr` with AEAD and a non-trivial
   decrypt path — the honest floor (G §1.4).

2. **Explicit provisioning assumption + tiered deployment map (G §0, §2).** The
   determining design axis is stated outright: *is there an out-of-band
   provisioning channel from the operator to the runtime?* litmask's **target
   customer has one** (controlled provisioning infrastructure), which is exactly
   why Tier 1/2 custody and binding are **first-class and expected** for serious
   use — not exotic. The providers are organized as a three-rung ladder mapped to
   the three distribution shapes (G §2).

3. **Sealing dev loop, pass-through dropped (G §3.2, replaces E §3 / F §8).** Debug
   builds seal like release, so `cargo run`/`cargo test` exercise the real AEAD
   path and a debug binary carries no plaintext (closes F-R5/E §8.2). Zero-wiring
   dev is **not a mechanism** — it is a **usage pattern Tier 0 enables**: a Tier-1/2
   consumer temporarily writes bare `init!()` to degrade to Tier 0 for a quick local
   check, keeping all litmask machinery active, then restores their provider token.
   No cfg gate, no separate dev key, no profile-dependent code. Accidental ship of
   such a build degrades to the obfuscation floor (AEAD ciphertext), strictly safer
   than pass-through's plaintext.

What G is, in one line: **F, with a zero-config nonce-derived default key that
degrades to an AEAD `obfstr`, an explicit provisioning-channel assumption that makes
the custody/binding tiers the expected upgrade for the target customer, and a sealing
dev loop (pass-through dropped) whose zero-wiring path is just Tier 0 used as a dev
pattern — floor free, ceiling reachable, dev loop honest.**

## 0. The Provisioning-Channel Assumption (doc-normative, G-new)

> Doc-normative. Stated up front because it is the axis that determines which tier
> a consumer lands on, and because it is the assumption that makes litmask's
> stronger tiers *reachable* rather than theoretical.

- **0.1 (the determining question)**: the design axis is **not** "who is the
  attacker" alone (F §1.1) but, paired with it, **"is there an out-of-band
  provisioning channel from the operator to the runtime?"** — a way to deliver a
  key, a per-customer reseal, or a second factor to the host *without* baking it in
  the artifact. The two questions together place a consumer on the tier ladder
  (G §2):
  - **No channel** (anonymous mass download, no per-install contact) → the key
    cannot reach the host out of band → **Tier 0** (baked default) is the honest
    ceiling. This is the `obfstr` market; litmask still wins on AEAD.
  - **Channel exists** (controlled install, per-customer delivery, managed fleet,
    operator-run infra) → the key/factor *can* be delivered out of band →
    **Tier 1/2** are reachable, and key-out-of-binary (win #2) / binding (win #3)
    become real, not theoretical.
- **0.2 (a good chunk of customers have a channel — neither all nor none —
  normative framing)**: the documentation MUST state that **roughly 30–50% of
  litmask's expected consumers have a controlled provisioning channel** (managed
  installs, per-customer delivery, operator-controlled hosts or fleets) and the rest
  do **not** (anonymous mass distribution). Both populations are **first-class**,
  not floor-as-afterthought:
  - **Channel present (~30–50%)**: Tier 1/2 custody and binding are **reachable and
    expected** for any literal warranting more than obfuscation — the channel
    delivers the per-deployment key/reseal/second factor out of band. The baked
    default (Tier 0) is their **onboarding floor**, useful *before* the channel is
    wired and for the subset of literals that never need more.
  - **No channel (~50–70%)**: Tier 0 is the **honest ceiling** (G §1.4) — the key
    cannot reach the host out of band, so an in-artifact key is the best available,
    and AEAD makes it beat the competitors. This population is not a second-class
    afterthought; it is the majority, and the floor is built for them.

  The split is a **doc claim about the market**, not a code boundary — one crate
  serves all of it (G §2.4).
- **0.4 (why embed-mask, not runtime-fetch — the load-bearing rationale,
  doc-normative)**: an obvious objection to the whole library is "*if you can
  deliver an `unlock_key` to the runtime, why not deliver the secret strings
  themselves and embed nothing?*" The documentation MUST answer it, because the
  answer is *why litmask exists* and is not stated anywhere in the prior chain:
  1. **The channel often is not there at all** (§0.2: ~50–70%). Runtime-fetch is
     simply impossible for them; embed-mask is the only option.
  2. **Even where a channel exists, it cannot carry the load.** Fetching every
     masked string, for every customer, on every runtime that needs it, is too much
     data to transfer and too many requests to serve — the provisioning channel is
     thin (sized for keys and config, not for streaming a binary's entire literal
     pool to a fleet). litmask inverts the economics: deliver **one small key once**
     over the thin channel, and decrypt **many embedded literals locally, offline,
     forever** — no per-secret, per-call, per-customer round-trips.
  3. **In-place ergonomics.** The literals are scattered across hundreds of call
     sites; `mask!("…")` masks each where it sits, with no refactor to a fetch-and-
     thread-through-the-program architecture.

  Therefore embed-mask + single-key-delivery is **not redundant** with a
  secrets-manager; it occupies the gap a secrets-manager cannot fill (no channel, or
  a channel too thin to stream every value) and a pure obfuscator cannot fill (no
  external key custody at all). This is the differentiated value the headline
  (Summary) leads with.
- **0.3 (why state it — normative rationale)**: F demoted custody/binding to "the
  weak topology, accept obfuscation." That is right for the no-channel case and
  **wrong** for litmask's actual customer, who has a channel and can therefore reach
  real protection. Making the assumption explicit (a) justifies why Tier 1/2 carry
  first-class weight rather than being exotic, and (b) keeps Tier 0 honest about
  being the floor, not the product. The assumption is a **doc claim about the target
  market**, not a code boundary — the one crate serves all three tiers (G §2.4).

## 1. The Nonce-Derived Default (Tier 0 — `obfstr`, upgraded)

> Normative. This is G's headline change. It replaces F §3.2's "empty default = env
> provider, fail loud." `init!()` with no provider token now means **nonce-derived
> Tier-0 key**, and it is the only form that gets the Tier-0 fallback (G §1.3).

- **1.1 (mechanism — nonce-derived, recomputed, normative)**: when the consumer
  writes bare `init!()` (or no `init!` at all — implicit, G §1.5) and supplies **no
  key material** at build time, the build (in **both** profiles — debug now seals
  too, G §3.2):
  1. generates the wrapper `nonce` as usual (seed-derived, F §8 — `KDF(seed ‖
     site-id)`, so it is deterministic and bit-reproducible, not freshly random);
  2. derives the Tier-0 `unlock_key = KDF(nonce, "litmask-tier0-v1")` — a domain-
     separated function of the **public** wrapper nonce, exactly the construction F
     uses for `machine_salt` (F §5). Nothing is minted and nothing is stored;
  3. derives and seals `mask_key` into the wrapper under it (unchanged from
     F §2.2/§2.3 — the Tier-0 key is *material*, normalized through the §2.2 KDF
     like any other).

  At runtime the unseal path **recomputes** `KDF(nonce, "litmask-tier0-v1")` from the
  nonce already in the wrapper — there is **no stored key region** in the binary. No
  env var, no `keygen` run, no file, no provisioning. Both profiles mask their
  literals out of the box: `cargo run` and the shipped release each work with zero
  wiring (G §3.2), and the key is identical in both profiles (no separate dev key).
  Because the key is derived, not a stored high-entropy constant, there is **no
  static key blob** to find by entropy scan, and because the nonce is seed-derived
  the whole Tier-0 build is **bit-reproducible**.
- **1.2 (Tier 0 rides `StaticProvider`, promoted from tests-only — normative)**: the
  existing `StaticProvider` (today public but documented "tests only / never wire
  into a release build") becomes the **sanctioned Tier-0 carrier**. Its current
  caution is **inverted**: no longer "never ship this" but "this is the zero-config
  floor; it is `obfstr`-grade and documented as such (§1.4)." Its **shape changes**:
  it no longer holds an operator-passed fixed key (`StaticProvider::new(literal)`);
  at Tier 0 it holds the key the runtime **recomputes from the wrapper nonce** (§1.1).
  It is "static" in the sense that matters — a fixed-per-artifact unlock key with **no
  external fetch** — but the key is *derived on demand*, not a stored constant.
  - A consumer hand-coding `StaticProvider::new(literal_key)` in a release path stays
    a documented anti-pattern, strictly worse than the nonce-derived Tier-0 key
    because the literal would also enter source control. The sanctioned Tier-0
    carrier is the build-wired, nonce-derived one — never a source literal.
  - `StaticProvider`'s `KeyMaterial` impl (G inherits F's trait rename, §1.6) returns
    the recomputed bytes as material; §2.2 normalizes them. It composes inside
    `multi:` like any other provider, so there is no special-case key path.
  - **`verify`/`reseal` flag it loudly (normative)**: because the Tier-0 carrier is
    `StaticProvider` with a publicly recomputable key, both tools MUST announce
    "Tier 0 / `StaticProvider` — obfuscation, key recoverable from the artifact"
    whenever they act on such a binary (G §3.4, §3.3).
- **1.3 (only the bare form gets the fallback — NO silent downgrade, normative,
  the critical guard)**: the Tier-0 fallback fires **only** for bare `init!()` with
  no build-time material. **Naming any provider opts out of the fallback
  entirely:**
  - `init!(env: "K")` / `init!(file: …)` / `init!(machine_id)` / `init!(custom: …)`
    / `init!(multi: […])` **never** fall back to the Tier-0 key. If their material is
    absent at the moment it is required, they **fail** per their own contract
    (env/file: build-seal needs the value, F §6.1; or runtime unseal fails loud,
    F §8 mute-release semantics for the runtime side).
  - **Rationale (closes the downgrade footgun)**: a consumer who *chose* custody
    must never silently ship an `obfstr`-grade Tier-0 binary because they forgot to
    set a var. Choosing a provider is an explicit statement of intent ("key lives
    outside the binary"); honoring it loudly is mandatory. The bare form is the
    *only* statement of "I accept the baked floor," so it is the only form the
    fallback may serve. This is the direct G analogue of F3 (silent key rotation):
    a downgrade that changes the security tier MUST NOT happen silently.
  - **Diagnostic (normative)**: a bare-`init!()` release build that took the Tier-0
    fallback emits a build-time **ambient notice** (the F §8 / E §3.8 `LITMASK_SEAL`
    notice channel, reused) stating "litmask: no key material supplied; sealed with
    a nonce-derived Tier-0 key (obfuscation-grade — see docs §1.4). Name a provider
    in `init!` for key-out-of-binary." Non-fatal, suppressible, but present so the
    tier is never a surprise.
- **1.4 (the honest floor — what Tier 0 is and is not, doc-normative)**: Tier 0 is
  **obfuscation, full stop**, and the docs MUST say so beside the `obfstr`
  comparison (F §1.2):
  - **Win it keeps (#1, AEAD not XOR)**: literals are AEAD ciphertext, so there is
    **no** XOR frequency / known-plaintext shortcut — `strings` yields nothing and
    recovery cannot proceed by reading the literals alone. **The honest limit
    (corrects an earlier overclaim, and again under nonce-derivation)**: the Tier-0
    key is **not stored** but is `KDF(public nonce)` (§1.1), so a static analyst does
    **not** even need to *locate* a key blob — they read the wrapper nonce and
    recompute `(key, nonce, ciphertext, tag)`, then decrypt **offline, without
    executing**. litmask's own `verify` does exactly this (§3.4). So the win over the
    competitors is now **only** "literals are AEAD, not XOR, so the attacker must
    reimplement the BLAKE3/KDF/AEAD derivation path rather than run `strings`" — it is
    **not** "must locate an obscured key" and **not** "must run the binary." Still
    strictly stronger than `obfstr` (XOR / random baked constant) and `litcrypt`
    (XOR / baked env key), both reversible by inspection alone, but the margin is
    honest: a determined analyst who reads litmask's (open-source) construction
    recovers Tier-0 plaintext from the artifact alone.
  - **Wins it does NOT have (#2, #3)**: the key is **recoverable from the artifact**
    (it is `KDF(public nonce)`, §1.1). An attacker with the artifact has everything
    needed to decrypt — there is no external secret and no host binding.
    Key-out-of-binary (#2) and per-host binding (#3) require opting into a Tier 1/2
    provider (G §2). The docs MUST NOT claim "key outside the binary" for Tier 0.
  - **Why key = `KDF(nonce)` is acceptable here (not a confidentiality
    construction)**: deriving the AEAD key from the same nonce that keys the AEAD
    would be unsound if Tier 0 claimed confidentiality — but it does not. Tier 0's
    key is recoverable from the artifact by design (above), so key/nonce correlation
    buys an attacker nothing they did not already have. The derivation exists for
    **reproducibility and to remove the static key blob**, not to protect the key.
  - **The honest one-liner**: *Tier 0 = `obfstr` with AEAD and the key derived from
    the wrapper nonce. It raises the cost from "run `strings`" to "reimplement
    litmask's KDF/AEAD derivation." It does **not** force execution and does **not**
    put the key out of reach.*
- **1.5 (implicit init — = current behavior, kept)**: a consumer who calls `mask!`
  with no `init!` at all still works at Tier 0 — implicit init resolves to the bare
  baked default (§1.1). G removes F/E's "bare `init!()` fails if env unset" sharp
  edge, so the implicit path is now a **graceful** floor rather than an opaque
  runtime abort (this also retires the base spec's F1 "opaque runtime death" for the
  default path — there is no missing key to die on).
- **1.6 (inherits F's `KeyMaterial` trait rename, normative)**: G keeps F §2.1's
  `KeyProvider` → `KeyMaterial` change (returns *material*, not a finished key).
  `StaticProvider`'s impl returns the nonce-derived bytes; §2.2 normalizes. Same pre-release
  breaking-change acceptance as F-R10 (G-R5).

## 2. The Tier Ladder (three rungs, three distribution shapes)

> Normative. The providers F made flat (F §3) are **organized** here into three
> tiers by what they buy and which deployment shape (G §0) they serve. The grammar
> is unchanged from F; G adds the **map**, not new syntax.

- **2.1 (Tier 0 — baked default → shrink-wrap / mass distribution)**:
  `init!()` (or implicit). Nonce-derived Tier-0 key (G §1). Serves consumers with **no
  provisioning channel** (G §0.1): anonymous mass download, no per-install contact.
  They cannot deliver a key out of band to millions of hosts, so an in-artifact key
  is the honest best, and AEAD makes it beat the competitors. **Obfuscation (G §1.4).**
- **2.2 (Tier 1 — key custody → centrally hosted + managed delivery)**:
  `init!(env: …)`, `init!(file: …)`, `init!(custom: …)`. The key lives **outside**
  the binary, delivered over the provisioning channel (env at launch, mounted file,
  vault fetch). Two sub-shapes:
  - **Centrally hosted** (operator runs the binary): attacker gets the artifact,
    not the key environment → **real protection** (F §1.1 server-side). This is the
    one topology where litmask is confidentiality, not obfuscation.
  - **Managed delivery** (operator ships to a controlled host but the host is the
    user's): key-out-of-binary (win #2) against an off-host or different-UID
    attacker (F §4.3); still obfuscation against a same-UID/root local attacker
    (F-R1). The provisioning channel delivers the per-deployment key.
- **2.3 (Tier 2 — binding / multi-factor → managed per-customer distribution)**:
  `init!(machine_id)`, `init!(multi: [machine_id, env: …])`. Per-host binding
  (stolen binary inert on another host) and, with a second factor, inertness even on
  the authorized host against a different-UID attacker (F §4.3). The routine
  per-customer flow is **one universal build + `reseal --to-machine-id <customer>`**
  over the provisioning channel (F §6.2). This is the "ship a desktop app to Bob
  with a per-customer key" shape, and it is **reachable precisely because the target
  customer has a provisioning channel** (G §0.2).
- **2.4 (one crate, tiers are a provider choice — normative, = F's "no crate
  split")**: the tier is **the `init!` token plus a doc claim**, never a compile
  boundary or a separate crate. A consumer moves up a tier by naming a stronger
  provider and (for Tier 1/2) wiring the provisioning channel — nothing is recompiled
  away, nothing is feature-gated. The baked default and the `multi:` two-factor path
  are the same `mask!`/wrapper/reseal machinery (G §1.2).
- **2.5 (the upgrade path is monotonic at the SOURCE level — normative ergonomics)**:
  moving Tier 0 → 1 → 2 is **additive in source effort**: change the **one** `init!`
  token (`init!()` → `init!(env)` → `init!(machine_id)`/`multi:`) and recompile.
  **`mask!` call sites and the literals are never touched**, never re-authored,
  never re-masked. The wrapper format is tier-agnostic (the 61-byte shape is
  identical at every tier; only the `unlock_key` *material source* differs), so no
  call-site or format churn accompanies the climb.
  - **Crossing a tier is a rebuild, not a reseal (normative — see §3.3)**: because
    the provider is compiled in from the `init!` token, going up a tier changes
    *which fetch code* is in the binary, which requires recompiling. `reseal` cannot
    perform a tier climb; it only re-keys **within** a tier (same provider, new
    material value). A consumer starting at Tier 0 on day one climbs by editing one
    token and rebuilding when the provisioning channel is ready — cheap, but a
    compile, not an artifact rewrite.
  - **The no-rebuild operation is within-tier per-customer reseal**: once compiled
    at Tier 2 (`init!(machine_id)`), the universal build is resealed per customer
    with no further compile (§3.3, F §6.2). That is the only tier-related operation
    that avoids a rebuild.

## 3. Interaction With the F Foundation (what moves, what holds)

> Normative reconciliation. G changes exactly two things in F; everything else is
> load-bearing and unchanged. This section exists so the side-by-side reviewer can
> see the blast radius is small.

- **3.1 (F §3.2 is replaced, not extended)**: the "empty default = env provider"
  rule is **gone**. `init!()` = nonce-derived Tier-0 key (G §1). The default `LITMASK_UNLOCK_KEY`
  env var is no longer the *implicit* key source — it is reached **explicitly** via
  `init!(env: "LITMASK_UNLOCK_KEY")` or, as a convenience, `init!(env)` with no name
  defaulting to `LITMASK_UNLOCK_KEY` (G keeps the well-known name for the env tier,
  just not as the *bare-`init!()`* behavior). `verify` and build-seal still read
  `LITMASK_UNLOCK_KEY` for the **env tier**; they do not apply to Tier 0 (a Tier-0
  binary has no external key to verify against — `verify` reports "decrypts with the
  nonce-derived Tier-0 key," G §3.4).
- **3.2 (dev loop seals — pass-through DROPPED, G's third change over F)**: G does
  **not** inherit E/F's pass-through dev. Debug builds **seal** (real AEAD wrapper,
  locator, descriptor), so `cargo run`/`cargo test` exercise the actual crypto path
  and a debug binary **never** carries plaintext literals — this closes F-R5 / E §8.2
  (pass-through's sharpest residual). Masking is active in **both** profiles. The
  premise that justified pass-through ("we have no baked key, so don't seal in dev")
  no longer holds under G, which already derives a key for Tier 0 (§1.1); G makes
  the dev loop consistent with that. A consumer's debug build gets a working key by
  **tier**:
  - **Tier 0 (bare `init!()`)**: the nonce-derived Tier-0 key (§1.1) fires in **both**
    profiles, so dev and release each just work with zero wiring. No separate dev
    key.
  - **Tier 1/2 (named provider)**: release seals/unseals under the declared provider
    (§2). In debug the consumer **chooses one of two paths**:
    - **(a) wire the real provider** — supply the provider's key in the dev
      environment (`LITMASK_UNLOCK_KEY`, a keyfile, etc.); debug seals/unseals through
      the **real** provider, giving full dev↔prod parity. The provider's *runtime
      success* is then exercised in dev (closes E R4 / F-R4 for this consumer); or
    - **(b) degrade to Tier 0 (a usage pattern, not a mechanism)** — temporarily edit
      the `init!` token to bare `init!()`, so the dev build seals under the Tier-0
      nonce-derived key (§1.1) with **no** key wiring. litmask machinery stays fully
      active (real seal/unseal, real AEAD); only the key source changes. The consumer
      restores their provider token before shipping. This is **not** separate code,
      not a cfg gate, not a profile-dependent key — it is the same Tier 0 every
      consumer already has, used deliberately for a quick local check.
  - **3.2.1 (no profile-gated key path — simplification over E/F)**: because the
    Tier-0 key is nonce-derived and identical in both profiles (§1.1), and pass-through
    is gone, **no element of the key path is profile-gated** — debug and release run
    the same seal/unseal code. This removes E §3.2.1's concern that a cfg-stripped
    dev-only branch could hide a type error: there is no such branch. (Tier-1/2
    provider construction is likewise compiled in both profiles; `just ci` still runs
    `cargo check --release` as a backstop.)
- **3.3 (`reseal` re-keys within a provider; it CANNOT cross tiers — normative,
  the load-bearing correction)**: `reseal` rewrites **data only** — the wrapper and
  its derived locator (F §6.2). It **cannot** change which provider runs at runtime,
  because the provider — the code that fetches unlock material — is **compiled in**
  from the `init!` token (F §3, the macro expands the fetch path at compile time).
  The wrapper carries no provider selector; the runtime always runs the one
  compiled-in fetch path. Therefore:
  - **Within a tier (no rebuild)**: `reseal` changes the **material value** for the
    **same** compiled-in provider. This is F's reseal-default deployment: build
    **once** with `init!(machine_id)` (the machine_id fetch path compiled in, sealed
    for no host), then `reseal --to-machine-id <bob>`, `<carol>`, … re-keys the
    wrapper per customer. The fetch code is already present; reseal only sets which
    host's wrapper opens. Likewise an `env`-provider binary can be resealed to a
    different env **value**. **This** is the legitimate "universal build, re-key per
    customer" flow.
  - **Across tiers (REQUIRES a rebuild; `reseal` refuses loudly)**: a **Tier-0 binary
    cannot be resealed up to Tier 1/2.** It has only the **Tier-0 fetch** path
    compiled in (the nonce-derived `StaticProvider`, §1.1); it has no
    env/file/machine_id fetch code. Resealing its wrapper under `KDF(env value)` is
    inert — at runtime the binary still recomputes `KDF(nonce)` and the rewritten
    wrapper does not open. So `reseal` on a Tier-0 binary MUST **refuse and announce
    loudly** "this is a Tier-0 / `StaticProvider` artifact; crossing a tier needs a
    rebuild (edit the `init!` token), not a reseal" (the same descriptor read as
    §3.4). Crossing a tier means changing the compiled-in provider, which means
    **editing the `init!` token and recompiling**. There is no artifact-level tier
    upgrade.
  - **Why this is still monotonic in the sense that matters**: the cross-tier climb
    is a rebuild, but it touches **only the `init!` token** — never a `mask!` call
    site, never a literal (G §2.5). The dev edits one line and recompiles; they do
    not re-author or re-mask anything.
  - **Consequence for the "ship baked everywhere" idea (rejected)**: there is **no**
    flow where a single Tier-0 artifact is resealed into managed/bound deployments.
    The universal-build-then-reseal pattern works **only within a tier** — the
    universal build must already be compiled at the tier (e.g. `init!(machine_id)`)
    it will be resealed within.
- **3.4 (`verify` gains a LOUD Tier-0 outcome — normative, extends F §8 / E §5)**:
  `verify` on a Tier-0 binary reports **"decrypts with the nonce-derived Tier-0 key
  via `StaticProvider` — obfuscation, key recoverable from the artifact"** — distinct
  from the env-tier "decrypts with the supplied key" and the "does-not-decrypt /
  cannot-check" outcomes, and stated **loudly** (not a quiet line item) because a
  Tier-0 binary makes no confidentiality claim. This makes the tier auditable
  offline: a reviewer confirms whether a shipped artifact is floor or custody-grade
  without running it, and a developer who left a quick-check `init!()` in place is
  told plainly. The provider descriptor (F §3.4) records "Tier 0 / `StaticProvider` /
  nonce-derived" in the factor set so `verify`/`reseal` see it. Because the key is
  recomputable from the wrapper nonce, `verify` recovers it **offline without
  executing** — the concrete demonstration of §1.4's honest limit (the same recovery
  an attacker performs). For Tier 1/2 binaries `verify` needs the externally-supplied
  key and **cannot** self-recover it from the artifact — that asymmetry is exactly the
  §1.4 win #2 (key out of binary) that Tier 0 lacks and Tier 1/2 has.
- **3.5 (everything else in F holds verbatim — except pass-through, G §3.2)**:
  three-layer key model (F §2), `multi:` (F §4), derived `machine_salt` (F §5),
  opaque wrapper / derived locator / mute-release (F §8), no-argv channels (F §7),
  `{verify, reseal, keygen, show-machine-id}` verb set (F §6). G adds **no** new CLI
  verb and **no** new wrapper region: the Tier-0 key is **derived from the existing
  wrapper nonce** (§1.1, the same construction as F's `machine_salt`, F §5), so it
  needs **no embedded key constant and no new region at all** — it is recomputed on
  demand in both profiles. The one F inheritance G **drops** is pass-through dev
  (E §3 / F §8): debug now seals (§3.2).

## Honest Residuals (documented, not solved)

- **G-R1 (Tier 0 is obfuscation, the key is recoverable from the artifact)**: the
  whole point of the floor is zero ceremony, and the cost is that the Tier-0 key is
  recomputable from the wrapper nonce by anyone with the artifact and litmask's
  (open-source) construction (G §1.4). An attacker with the binary decrypts
  everything. This is **not** a regression — it is strictly better than
  `obfstr`/`litcrypt`, which it replaces — but it must be documented as the floor,
  never sold as confidentiality. The §1.3 ambient notice and the loud §3.4 `verify`
  outcome keep the tier visible.
- **G-R2 (the baked default could lull a consumer into shipping the floor)**: a
  consumer who never reads the docs gets working masking and may believe they have
  "encryption." The §1.3 build notice and §1.4 honest one-liner are the mitigation;
  G accepts that a consumer who ignores both ships Tier 0 knowingly-or-not. The
  counter-design (fail-loud-by-default, F §3.2) trades this for ceremony-at-step-zero
  and was rejected as the wrong default for a string-obfuscation library (G Summary).
- **G-R3 (two "defaults" in the consumer's head)**: bare `init!()` = Tier 0;
  `init!(env)` = custody. A consumer could conflate them. Mitigated by §1.3's
  opt-out rule being crisp (name a provider → no fallback, fail loud) and by the
  monotonic upgrade path (§2.5). The honest cost: the word "default" now means
  "the floor," and consumers must learn that naming a provider is an *upgrade*, not
  a *configuration of the same thing*.
- **G-R4 (inherits most F residuals, but NOT F-R5)**: same-UID irreducibility
  (F-R1), salt non-secret (F-R2), composite reseal needs all factors (F-R3),
  build-host trust (F-R6), descriptor readable by key-holder (F-R7) — unchanged.
  **F-R5 (default debug leaks plaintext) NO LONGER applies** — G drops pass-through,
  so debug seals and carries no plaintext (§3.2). **F-R4 (provider runtime success
  unexercised in dev) is narrowed**: a Tier-1/2 consumer who wires the real provider
  in dev (§3.2 path (a)) now exercises it; it remains only when a consumer degrades to
  Tier 0 for a quick check (§3.2 path (b)), where execute-locally on the real-provider
  build stays the authority for provider *resolution*.
- **G-R5 (`KeyProvider` → `KeyMaterial` breaking change)**: inherited from F-R10.
  Pre-release, direct rename, no shim.
- **G-R6 (Tier-0 locator and key are publicly derivable)**: at Tier 0 the
  `unlock_key = KDF(nonce)` and therefore the derived locator (`KDF(unlock_key,
  "litmask-locator-v1")`, F §8) are both deterministic functions of the **public**
  wrapper nonce — an analyst can locate the wrapper and recompute the key from the
  artifact alone. This is **consistent with** Tier 0 being obfuscation (the locator
  was never a secret; at Tier 1/2 it still rides the real external `unlock_key` and
  stays unguessable). It is documented so no one claims a Tier-0 wrapper is "hidden."
  G's previous cfg-gated dev-key gate — and its fail-toward-release polarity risk —
  is **removed**: there is no profile-dependent key, so there is no way to leak a
  debug-only constant into release. Zero-wiring dev is just Tier 0 (§3.2 path (b)).

## Out of Scope

Inherits F's Out-of-Scope set, plus G's additional declines:

- **A crate split (floor crate vs custody crate)** — the tier is a provider choice
  plus a doc claim, not a code boundary (G §2.4). One crate serves all three rungs.
- **A consumer-facing `StaticProvider::new(literal_key)` release blessing** — a key
  hand-written in source is strictly worse than the nonce-derived Tier-0 key (it also
  enters source control); it stays a documented anti-pattern (G §1.2). The
  build-wired, *nonce-derived* `StaticProvider` is the sanctioned Tier-0 carrier.
- **A separate cfg-gated "dev key" mechanism (an earlier G draft's §3.2.2)** — removed,
  not deferred: it added a profile-dependent key, a fail-toward-release gate, and a
  scrub invariant for near-zero value. Degrading to the nonce-derived Tier 0 (§3.2 path
  (b)) delivers the same zero-wiring dev loop with no new code and no gate to misfire.
- **Failing the bare `init!()` build when no key is supplied** — that is F §3.2,
  explicitly replaced. The floor must produce a working binary (G §1.1).
- **A `--tier` flag or tier enum in the API** — the tier is observable
  (`verify`, G §3.4) and chosen by the `init!` token; it is not a separate
  configuration axis.
- **Pass-through dev (E §3 / F §8) and its `seal_in_debug()` opt-in** — removed, not
  deferred: debug seals unconditionally (G §3.2), so there is no plaintext-in-debug
  default to opt out of. The zero-wiring dev path is simply Tier 0 used as a usage
  pattern (G §3.2 path (b)) — no mechanism, no cfg gate.
- Everything F lists as out of scope (user-configured salt, operator-supplied
  `mask_key`, single-factor partial unlock, a compile/`run` verb, etc.).

## Decision delta vs `SPEC_DEVEX_F.md` (G inherits F's stack; this is the G-only delta)

| Axis | **F (composable providers, distributed-default)** | **G (nonce-derived default, provisioning-aware tiers)** |
|---|---|---|
| Three-layer key / `multi:` / derived salt / opaque wrapper / reseal / channels / CLI verbs | the whole stack | **inherited unchanged** |
| Bare `init!()` meaning | env provider; **aborts release if `LITMASK_UNLOCK_KEY` unset** (ceremony at step zero) | **nonce-derived Tier-0 key; works out of the box, no env/keygen, bit-reproducible** (G §1) |
| Zero-config protection | none — must mint + wire a key first | **`obfstr` + AEAD floor, immediately** (G §1.4) |
| `StaticProvider` | public, "tests only, never ship" | **promoted to the sanctioned Tier-0 carrier, holding a nonce-derived (not source-literal) key** (G §1.2) |
| Silent-downgrade guard | n/a (no fallback existed) | **naming any provider opts out of the baked fallback → no silent tier downgrade** (G §1.3) |
| Provisioning channel | implicit in "distributed-default" framing | **explicit doc-normative assumption; the axis that places a consumer on the tier ladder** (G §0) |
| Provider organization | flat list, distributed-default emphasis | **three tiers mapped to shrink-wrap / managed / centrally-hosted** (G §2) |
| Upgrade path Tier 0→1→2 | implicit | **source-monotonic: change one `init!` token, recompile; `mask!` sites untouched. Crossing a tier is a rebuild (provider is compiled-in code); `reseal` re-keys only *within* a tier** (G §2.5, §3.3) |
| `verify` outcomes | decrypts / does-not / cannot-check (+ identity) | **+ LOUD "decrypts with nonce-derived Tier-0 key via `StaticProvider` (obfuscation)"** (G §3.4) |
| Dev loop | pass-through (debug = plaintext, no seal); zero-wiring by doing nothing | **debug SEALS (no plaintext, real crypto exercised); zero-wiring by degrading to Tier 0 (a usage pattern, §3.2 path (b)) or by wiring the real provider; pass-through dropped, no cfg-gated dev key** |
| Default honesty | fail-loud forces the key question up front | **baked floor + §1.3 ambient notice + §1.4 one-liner + loud `verify`/`reseal` keep the tier visible without forcing ceremony; §1.4 win #1 thinned again under nonce-derivation (AEAD ≠ "must execute" and key need not even be "located" — it is `KDF(public nonce)`)** |
| Biggest risk | debug plaintext; composite reseal verbosity; trait rename | **a consumer shipping the Tier-0 floor unaware it is obfuscation (G-R2). The §3.2.2 dev-key gate and its fail-toward-release polarity risk are GONE (dev key removed; Tier 0 is the dev path). Debug-plaintext risk is GONE (pass-through dropped).** |
