# litmask Developer-Experience — Specification (Variant G: Baked-Key Default, Provisioning-Aware Tiers)

> **Status:** design variant, refine phase. Eighth option beside
> `docs/SPEC_DEVEX.md` (build-generated key), `_A` (operator-owned key),
> `_B` (clean slate), `_C` (declarative + layered), `_D` (B minus `K_dev`),
> `_E` (pass-through dev + honest topology), `_F` (composable providers,
> distributed-default).
> **G adopts F's foundation in full** — three-layer key model, composable
> providers, flat `init!` grammar, `multi:` two-factor, derived `machine_salt`,
> opaque wrapper, reseal-default deployment, pass-through dev, topology-first docs
> — and makes **two** changes:
> (1) it **inverts the zero-config default**: bare `init!()` no longer means
> "env provider, fail loud if unset" (F §3.2). It means **build-baked key**: the
> build generates a random `unlock_key`, seals under it, and **bakes it into the
> binary**. The default *just works* with no key, no `keygen`, no env var — litmask
> **degrades gracefully to an AEAD upgrade of `obfstr`**. Every stronger provider is
> **opt-in added ceremony the consumer chooses**.
> (2) it **states the provisioning-channel assumption explicitly** (G §0) and
> **organizes the providers into three deployment tiers** mapped to the three real
> distribution shapes — shrink-wrap, managed per-customer, centrally hosted.
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
- Pass-through dev: debug compiles literals in the clear; `init!` is a no-op;
  masking is a release property (F §8 / E §3).
- Topology-first honest docs, competitive frame vs `obfstr`/`litcrypt` (F §1).
- `{verify, reseal, keygen, show-machine-id}` CLI, no-argv secret channels
  (F §6, §7).

**What G changes over F — two moves:**

1. **Baked-key default (G §1, replaces F §3.2).** Bare `init!()` falls back to a
   **build-generated, build-baked** `unlock_key`. No env var, no `keygen`, no
   failure mode. This resurrects the *base* `SPEC_DEVEX.md`'s build-generated key —
   but **only as the default tier**, with F's inverted/composable stack as the
   opt-in tiers above it. The honest cost: at this tier the key is **in the
   binary**, so it earns F's win #1 (AEAD vs XOR) but **not** #2 (key out of
   binary) or #3 (binding). It is `obfstr` with AEAD and a non-trivial decrypt
   path — the honest floor (G §1.4).

2. **Explicit provisioning assumption + tiered deployment map (G §0, §2).** The
   determining design axis is stated outright: *is there an out-of-band
   provisioning channel from the operator to the runtime?* litmask's **target
   customer has one** (controlled provisioning infrastructure), which is exactly
   why Tier 1/2 custody and binding are **first-class and expected** for serious
   use — not exotic. The providers are organized as a three-rung ladder mapped to
   the three distribution shapes (G §2).

What G is, in one line: **F, with a zero-config baked-key default that degrades to
an AEAD `obfstr`, and an explicit provisioning-channel assumption that makes the
custody/binding tiers the expected upgrade for the target customer — floor free,
ceiling reachable.**

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
- **0.2 (litmask's target customer has a channel — normative framing)**: the
  documentation MUST state that litmask is designed for consumers who **do** have
  controlled provisioning infrastructure (managed installs, per-customer delivery,
  operator-controlled hosts or fleets). For them the baked default (Tier 0) is an
  **onboarding floor and an `obfstr` replacement**, not the destination: their
  provisioning channel makes Tier 1/2 the expected posture for any literal that
  warrants more than obfuscation. The baked default exists so the library is useful
  *before* the channel is wired and for the subset of literals that never need more.
- **0.3 (why state it — normative rationale)**: F demoted custody/binding to "the
  weak topology, accept obfuscation." That is right for the no-channel case and
  **wrong** for litmask's actual customer, who has a channel and can therefore reach
  real protection. Making the assumption explicit (a) justifies why Tier 1/2 carry
  first-class weight rather than being exotic, and (b) keeps Tier 0 honest about
  being the floor, not the product. The assumption is a **doc claim about the target
  market**, not a code boundary — the one crate serves all three tiers (G §2.4).

## 1. The Baked-Key Default (Tier 0 — `obfstr`, upgraded)

> Normative. This is G's headline change. It replaces F §3.2's "empty default = env
> provider, fail loud." `init!()` with no provider token now means **build-baked
> key**, and it is the only form that gets the baked fallback (G §1.3).

- **1.1 (mechanism — build-generated, build-baked, normative)**: when the consumer
  writes bare `init!()` (or no `init!` at all — implicit, G §1.5) and supplies **no
  key material** at build time, a **release** build:
  1. generates a random 32-byte `unlock_key` (CSPRNG, same mint as `keygen`,
     F §6.1);
  2. derives and seals `mask_key` into the wrapper under it (unchanged from
     F §2.2/§2.3 — the baked key is *material*, normalized through the §2.2 KDF
     like any other);
  3. **bakes the `unlock_key` into the binary** as an embedded constant the runtime
     reads to unseal — structurally a build-time `StaticProvider` whose key the
     build minted rather than the operator.

  No env var, no `keygen` run, no file, no provisioning. The release binary masks
  its literals out of the box. Debug seals nothing (pass-through, F §8 / E §3) — the
  baked key is a **release** construct only.
- **1.2 (it reuses `StaticProvider`, promoted from tests-only — normative)**: the
  existing `StaticProvider` (today public but documented "tests only / never wire
  into a release build") becomes the **sanctioned default carrier**. Its current
  caution is **inverted**: it is no longer "never ship this" but "this is the
  zero-config baked floor; it is `obfstr`-grade and documented as such (§1.4)."
  - The **build** supplies the key (minted, §1.1), so the consumer never hand-codes
    `StaticProvider::new(literal_key)` in a release path — that hand-coded form
    (a key in source) stays a documented anti-pattern, strictly worse than the
    minted baked key because the literal would also appear in source control.
  - `StaticProvider`'s `KeyMaterial` impl (G inherits F's trait rename, §1.6)
    returns the baked bytes as material; §2.2 normalizes them. It composes inside
    `multi:` like any other provider, so there is no special-case key path.
- **1.3 (only the bare form gets the fallback — NO silent downgrade, normative,
  the critical guard)**: the baked fallback fires **only** for bare `init!()` with
  no build-time material. **Naming any provider opts out of the fallback
  entirely:**
  - `init!(env: "K")` / `init!(file: …)` / `init!(machine_id)` / `init!(custom: …)`
    / `init!(multi: […])` **never** fall back to a baked key. If their material is
    absent at the moment it is required, they **fail** per their own contract
    (env/file: build-seal needs the value, F §6.1; or runtime unseal fails loud,
    F §8 mute-release semantics for the runtime side).
  - **Rationale (closes the downgrade footgun)**: a consumer who *chose* custody
    must never silently ship an `obfstr`-grade baked binary because they forgot to
    set a var. Choosing a provider is an explicit statement of intent ("key lives
    outside the binary"); honoring it loudly is mandatory. The bare form is the
    *only* statement of "I accept the baked floor," so it is the only form the
    fallback may serve. This is the direct G analogue of F3 (silent key rotation):
    a downgrade that changes the security tier MUST NOT happen silently.
  - **Diagnostic (normative)**: a bare-`init!()` release build that took the baked
    fallback emits a build-time **ambient notice** (the F §8 / E §3.8 `LITMASK_SEAL`
    notice channel, reused) stating "litmask: no key material supplied; sealed with
    a build-generated baked key (Tier 0, obfuscation-grade — see docs §1.4). Name a
    provider in `init!` for key-out-of-binary." Non-fatal, suppressible, but present
    so the tier is never a surprise.
- **1.4 (the honest floor — what Tier 0 is and is not, doc-normative)**: Tier 0 is
  **obfuscation, full stop**, and the docs MUST say so beside the `obfstr`
  comparison (F §1.2):
  - **Win it keeps (#1, AEAD)**: literals are AEAD ciphertext, not XOR; `strings`
    and static analysis on the artifact yield nothing usable; the attacker must
    execute the decrypt path. This alone is strictly stronger than `obfstr`
    (XOR / random baked constant) and `litcrypt` (XOR / baked env key).
  - **Wins it does NOT have (#2, #3)**: the key is **in the binary**. An attacker
    with the artifact has everything needed to decrypt — there is no external
    secret and no host binding. Key-out-of-binary (#2) and per-host binding (#3)
    require opting into a Tier 1/2 provider (G §2). The docs MUST NOT claim "key
    outside the binary" for Tier 0.
  - **The honest one-liner**: *Tier 0 = `obfstr` with AEAD and a non-trivial
    decrypt path. It raises the cost from "run `strings`" to "run or emulate the
    binary." It does not put the key out of reach.*
- **1.5 (implicit init — = current behavior, kept)**: a consumer who calls `mask!`
  with no `init!` at all still works at Tier 0 — implicit init resolves to the bare
  baked default (§1.1). G removes F/E's "bare `init!()` fails if env unset" sharp
  edge, so the implicit path is now a **graceful** floor rather than an opaque
  runtime abort (this also retires the base spec's F1 "opaque runtime death" for the
  default path — there is no missing key to die on).
- **1.6 (inherits F's `KeyMaterial` trait rename, normative)**: G keeps F §2.1's
  `KeyProvider` → `KeyMaterial` change (returns *material*, not a finished key).
  `StaticProvider`'s impl returns the baked bytes; §2.2 normalizes. Same pre-release
  breaking-change acceptance as F-R10 (G-R5).

## 2. The Tier Ladder (three rungs, three distribution shapes)

> Normative. The providers F made flat (F §3) are **organized** here into three
> tiers by what they buy and which deployment shape (G §0) they serve. The grammar
> is unchanged from F; G adds the **map**, not new syntax.

- **2.1 (Tier 0 — baked default → shrink-wrap / mass distribution)**:
  `init!()` (or implicit). Build-baked key (G §1). Serves consumers with **no
  provisioning channel** (G §0.1): anonymous mass download, no per-install contact.
  They cannot deliver a key out of band to millions of hosts, so a baked key is the
  honest best, and AEAD makes it beat the competitors. **Obfuscation (G §1.4).**
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
  rule is **gone**. `init!()` = baked key (G §1). The default `LITMASK_UNLOCK_KEY`
  env var is no longer the *implicit* key source — it is reached **explicitly** via
  `init!(env: "LITMASK_UNLOCK_KEY")` or, as a convenience, `init!(env)` with no name
  defaulting to `LITMASK_UNLOCK_KEY` (G keeps the well-known name for the env tier,
  just not as the *bare-`init!()`* behavior). `verify` and build-seal still read
  `LITMASK_UNLOCK_KEY` for the **env tier**; they do not apply to Tier 0 (a baked
  binary has no external key to verify against — `verify` reports "decrypts with the
  baked key," G §3.4).
- **3.2 (pass-through dev unchanged, reinforced)**: Tier 0's baked key is a
  **release** construct (G §1.1). Debug still compiles literals in the clear with a
  no-op `init!` (F §8 / E §3). So the baked key never exists in debug, never leaks
  to a dev's source or env, and the §3.2.1 type-check guard still keeps the release
  path type-checked in debug. The pass-through residual (default debug carries
  plaintext, F-R5) is unchanged.
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
  - **Across tiers (REQUIRES a rebuild)**: a **Tier-0 baked binary cannot be
    resealed up to Tier 1/2.** It has only the **baked-fetch** path compiled in; it
    has no env/file/machine_id fetch code. Resealing its wrapper under `KDF(env
    value)` is inert — at runtime the binary still runs the baked-fetch path, reads
    the baked constant, and the rewritten wrapper does not open. Crossing a tier
    means changing the compiled-in provider, which means **editing the `init!` token
    and recompiling**. There is no artifact-level tier upgrade.
  - **Why this is still monotonic in the sense that matters**: the cross-tier climb
    is a rebuild, but it touches **only the `init!` token** — never a `mask!` call
    site, never a literal (G §2.5). The dev edits one line and recompiles; they do
    not re-author or re-mask anything.
  - **Consequence for the "ship baked everywhere" idea (rejected)**: there is **no**
    flow where a single Tier-0 artifact is resealed into managed/bound deployments.
    The universal-build-then-reseal pattern works **only within a tier** — the
    universal build must already be compiled at the tier (e.g. `init!(machine_id)`)
    it will be resealed within.
- **3.4 (`verify` gains a Tier-0 outcome — normative, extends F §8 / E §5)**:
  `verify` on a Tier-0 baked binary reports **"decrypts with the embedded baked
  key (Tier 0 / obfuscation)"** — distinct from the env-tier "decrypts with the
  supplied key" and the "does-not-decrypt / cannot-check" outcomes. This makes the
  tier auditable offline: a reviewer can confirm whether a shipped artifact is
  baked-floor or custody-grade without running it. The provider descriptor (F §3.4)
  records "Tier 0 / static-baked" in the factor set so `verify`/`reseal` see it.
- **3.5 (everything else in F holds verbatim)**: three-layer key model (F §2),
  `multi:` (F §4), derived `machine_salt` (F §5), opaque wrapper / derived locator /
  mute-release (F §8), no-argv channels (F §7), `{verify, reseal, keygen,
  show-machine-id}` verb set (F §6). G adds **no** new CLI verb and **no** new
  wrapper region (the baked key reuses the existing embedded-constant mechanism the
  base spec §1.7 already defined for the debug auto-key — now applied to release
  Tier 0).

## Honest Residuals (documented, not solved)

- **G-R1 (Tier 0 is obfuscation, the key is in the binary)**: the whole point of
  the floor is zero ceremony, and the cost is that the key ships in the artifact
  (G §1.4). An attacker with the binary decrypts everything. This is **not** a
  regression — it is strictly better than `obfstr`/`litcrypt`, which it replaces —
  but it must be documented as the floor, never sold as confidentiality. The
  §1.3 ambient notice and the §3.4 `verify` outcome keep the tier visible.
- **G-R2 (the baked default could lull a consumer into shipping the floor)**: a
  consumer who never reads the docs gets working masking and may believe they have
  "encryption." The §1.3 build notice and §1.4 honest one-liner are the mitigation;
  G accepts that a consumer who ignores both ships Tier 0 knowingly-or-not. The
  counter-design (fail-loud-by-default, F §3.2) trades this for ceremony-at-step-zero
  and was rejected as the wrong default for a string-obfuscation library (G Summary).
- **G-R3 (two "defaults" in the consumer's head)**: bare `init!()` = baked;
  `init!(env)` = custody. A consumer could conflate them. Mitigated by §1.3's
  opt-out rule being crisp (name a provider → no fallback, fail loud) and by the
  monotonic upgrade path (§2.5). The honest cost: the word "default" now means
  "the floor," and consumers must learn that naming a provider is an *upgrade*, not
  a *configuration of the same thing*.
- **G-R4 (inherits all F residuals)**: same-UID irreducibility (F-R1), salt
  non-secret (F-R2), composite reseal needs all factors (F-R3), provider runtime
  success unexercised in dev (F-R4), default debug leaks plaintext (F-R5), build-host
  trust (F-R6), descriptor readable by key-holder (F-R7). Unchanged.
- **G-R5 (`KeyProvider` → `KeyMaterial` breaking change)**: inherited from F-R10.
  Pre-release, direct rename, no shim.

## Out of Scope

Inherits F's Out-of-Scope set, plus G's additional declines:

- **A crate split (floor crate vs custody crate)** — the tier is a provider choice
  plus a doc claim, not a code boundary (G §2.4). One crate serves all three rungs.
- **A consumer-facing `StaticProvider::new(literal_key)` release blessing** — a key
  hand-written in source is strictly worse than the minted baked key (it also enters
  source control); it stays a documented anti-pattern (G §1.2). The *build-minted*
  baked key is the sanctioned Tier-0 carrier.
- **Failing the bare `init!()` build when no key is supplied** — that is F §3.2,
  explicitly replaced. The floor must produce a working binary (G §1.1).
- **A `--tier` flag or tier enum in the API** — the tier is observable
  (`verify`, G §3.4) and chosen by the `init!` token; it is not a separate
  configuration axis.
- Everything F lists as out of scope (user-configured salt, operator-supplied
  `mask_key`, single-factor partial unlock, a compile/`run` verb, etc.).

## Decision delta vs `SPEC_DEVEX_F.md` (G inherits F's stack; this is the G-only delta)

| Axis | **F (composable providers, distributed-default)** | **G (baked-key default, provisioning-aware tiers)** |
|---|---|---|
| Three-layer key / `multi:` / derived salt / opaque wrapper / reseal / channels / CLI verbs | the whole stack | **inherited unchanged** |
| Bare `init!()` meaning | env provider; **aborts release if `LITMASK_UNLOCK_KEY` unset** (ceremony at step zero) | **build-baked key; works out of the box, no env/keygen** (G §1) |
| Zero-config protection | none — must mint + wire a key first | **`obfstr` + AEAD floor, immediately** (G §1.4) |
| `StaticProvider` | public, "tests only, never ship" | **promoted to the sanctioned build-minted Tier-0 carrier** (G §1.2) |
| Silent-downgrade guard | n/a (no fallback existed) | **naming any provider opts out of the baked fallback → no silent tier downgrade** (G §1.3) |
| Provisioning channel | implicit in "distributed-default" framing | **explicit doc-normative assumption; the axis that places a consumer on the tier ladder** (G §0) |
| Provider organization | flat list, distributed-default emphasis | **three tiers mapped to shrink-wrap / managed / centrally-hosted** (G §2) |
| Upgrade path Tier 0→1→2 | implicit | **source-monotonic: change one `init!` token, recompile; `mask!` sites untouched. Crossing a tier is a rebuild (provider is compiled-in code); `reseal` re-keys only *within* a tier** (G §2.5, §3.3) |
| `verify` outcomes | decrypts / does-not / cannot-check (+ identity) | **+ "decrypts with embedded baked key (Tier 0 / obfuscation)"** (G §3.4) |
| Default honesty | fail-loud forces the key question up front | **baked floor + §1.3 ambient notice + §1.4 one-liner keep the tier visible without forcing ceremony** |
| Biggest risk | debug plaintext; composite reseal verbosity; trait rename | **same, plus a consumer shipping the Tier-0 floor unaware it is obfuscation (G-R2) — mitigated by the build notice + `verify` outcome, not eliminated** |
