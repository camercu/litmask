# litmask Developer-Experience Specification — Build-Sealed Keying

> **Status:** selected, canonical DevEx design (refine-then-implement
> phase; no implementation started yet). This supersedes an exploratory
> variant set (base, A–G, plus a deleted circular post-build-self-seal
> attempt) that was bake-offed and culled; those variant docs have been
> removed and their history lives in git. The project is **pre-release**,
> so this lands as a direct edit with no migration burden.
>
> **The one structural move:** there is **one keying path — build-time
> seal** — and the "binary is something you patch" model is deleted
> entirely. With post-build re-keying gone, the re-key/inspect CLI
> (`bind`/`reseal`, `inspect`/`verify`), the **derived locator**, and
> the wrapper's find-without-signature machinery all lose their only
> consumers and are removed. What remains is the masking core plus a
> thin, build-time key seam.

## Summary

litmask's earlier design carried a large apparatus built on a single
assumption: that a **built binary gets re-keyed in place** —
`bind`/`reseal` patch the wrapper, `inspect`/`verify` check it off-box,
and a **derived locator** (a recorded 12-byte wrapper tell that let an
external tool find the wrapper in a stripped binary without a litmask
signature) lets those tools locate it. This spec drops that assumption,
on three findings:

- **Per-customer rebuild is the spine, not reseal.** Under build-time
  seal, each customer/machine binary is a clean build. Reseal's
  "avoid a rebuild" saving is undercut by signing (macOS forces
  re-sign + notarize per artifact regardless), by warm build caches,
  and by provenance (a freshly built artifact is more auditable than
  an in-place-patched one). The per-customer delta is **bounded, not
  free**: the seed is pinned **per customer** (§4.4 stores
  `cryptio/<customer>/seed`), so each customer's `mask_key` and blob
  pool are **distinct** — the literal-isolation property — and a
  per-customer build re-encrypts the literals under that seed, re-seals
  the wrapper, re-links, and re-signs (§0.4). Reseal's only real saving
  over this — skipping blob re-encryption — is cheap in absolute terms
  and dwarfed by the irreducible re-link + re-sign + notarize that
  reseal cannot avoid either.
- **Post-build re-binding mostly cannot help.** The only thing on-host
  re-bind uniquely buys is *deliberate, pre-emptive* migration to a
  new, known machine-id. It **cannot** recover a binary after its
  machine-id has already drifted (that needs the old id — gone), and
  that recovery case is rebuild territory with or without the tool.
- **Off-box decrypt-verification is impossible or tautological.** A
  machine-bound binary won't decrypt on the verifier's box (wrong
  machine-id); supplying `--machine-id` only re-derives the key the
  builder already sealed under. A Tier-0 binary cannot even be
  *located* off-box (its locator would be `KDF(KDF(nonce))` —
  circular). On-host, "verification" is just *running the binary*:
  `init!` self-checks. With the builder owning key provisioning,
  there is no independent party whose key-correctness needs checking.

Remove the patch-the-binary model and the dependent machinery
collapses. The runtime never needed the locator — it reaches the
wrapper by **compile-time address** (`include_bytes!` `static`),
referenced directly by code, carrying no scan signature (still
reachable by disassembling the init path — opacity vs a blind byte
scan, not invisibility). The locator existed **only** for external CLI
tools. Delete those tools and
the locator, the recorded-locator config, and the wrapper's locator
prefix are all dead weight.

**The governing principle:** *if nothing finds the wrapper in a
binary-as-a-file, nothing needs to make it findable.* Keying happens
once, at build, by the party who already owns the keys. Everything that
existed to re-key or inspect a finished artifact is removed.

## Retained foundations

The masking-core and keying primitives the build-sealed model keeps:

- **Tier-0 nonce-derived default.** Bare `init!()` →
  `unlock_key = KDF(wrapper_nonce, "litmask-tier0-v1")`, recomputed at
  runtime, nothing minted or stored, bit-reproducible. The honest
  floor: an AEAD upgrade of `obfstr` — the key is recoverable from the
  artifact, this is not "key out of binary."
- **Provider trait + opt-in stronger keys, composition narrowed.**
  The external factor is an `impl KeyProvider` yielding key **material**
  (`Zeroizing` bytes, any length); the framework applies one KDF at the
  init boundary (`unlock_key = KDF(material)`). The trait is the right
  primitive (the closure-key alternative was evaluated and rejected — a
  bare closure adds only inline sugar over a custom impl). Tiers are
  **build-time** choices, not deploy-time. The only composable
  combination is `machine_id + <external>` (`unlock_key = KDF(len_prefixed
  (machine_material) ‖ len_prefixed(external_material))`), fixed-arity and
  fixed-order — no variadic `MultiProvider` (§2.2 explains why the
  order-significant variadic shape had no footgun-free build/runtime
  agreement).
- **Nonce-derived `machine_salt`, no user salt.**
  `machine_salt = KDF(wrapper_nonce, "litmask-machine-id-salt-v1")`,
  recomputed on demand, never embedded; `machine material =
  KDF(machine_id, salt = machine_salt, info = "litmask-machine-id-v1")`.
  No `--salt`, no salt arg. The salt gives domain separation only; a
  salt is non-secret and cannot add secrecy, so there is nothing to
  expose. (Machine binding is the `machine_id` keyword, not a public
  `MachineIdProvider` value — §2.)
- **`weak_mask!`** — keeps derivation-context literals out of
  `strings(1)`; depends only on the wrapper nonce, independent of the
  removed locator, so it survives.
- **Dirty-word scrub** — build-time regression test ensuring built
  binaries carry no forbidden litmask-identifying substrings.
- **Topology-first, honest deployment docs** — lead with the threat
  topology and state the honest floor rather than overselling.

## What this spec eliminates (the collapse)

| Eliminated | Why it had no surviving consumer |
|---|---|
| `bind` / `reseal` CLI | Re-keying moves to rebuild. Unique capability (pre-emptive on-host migration) is narrow and rebuild-equivalent; drift recovery fails regardless. Removes in-place patching, atomic tempfile/fsync/rename, Windows `MoveFileExW` unsafe, **macOS ad-hoc re-sign hole**, reseal wire-preservation. |
| `inspect` / `verify` CLI (incl. `--check-decrypt`) | Off-box check on a bound binary is impossible (machine-id mismatch) or tautological (re-derives the builder's own key). Tier-0 is uncheckable off-box (circular locator). On-host check = run the binary. Builder owns provisioning, so nothing independent to verify. |
| **Derived locator** + recorded-locator config | Its only purpose was letting an external CLI find the wrapper without a signature. With no such CLI, nothing consumes it. Runtime finds the wrapper by compile-time address. |
| Wrapper locator prefix | No scan → no findability marker needed. |
| Reseal-default deployment shape, no-argv reseal channels | Subsumed by build-time seal. (Build-time secret-input handling is retained — see §3.) |

## 0. The keying model — one path

- **0.1 (build-time seal, normative).** Every real key is applied
  **at build**. `litmask-build::emit()` derives the `mask_key`, seals
  it into the wrapper under the tier's `unlock_key`, and embeds the
  wrapper as `&[u8]` in the output. There is **no** post-build re-key
  step.
- **0.2 (per-customer = per-build, normative).** Distinguishing
  customers/machines is done by **building per customer/machine**, not
  by patching one artifact. This is the documented default for any
  tier above Tier-0. Clean provenance per artifact is a feature, not a
  cost.
- **0.3 (no in-place mutation of shipped binaries).** litmask ships no
  tool that rewrites a built binary. The macOS re-sign hole, atomic
  in-place commit, and platform-specific patching code are gone with
  the tools that needed them.
- **0.4 (per-customer rebuild is acceptable — the thesis that makes
  reseal deletable, normative).** The seed is pinned **per customer**
  (§4.4 stores `cryptio/<customer>/seed`), so each customer's `mask_key`
  — and therefore every per-call-site blob — is **distinct**. This is
  the per-customer **literal isolation** a shared seed would forfeit:
  recovering one customer's `mask_key` (e.g. the legit owner dumping
  their own process) does **not** open another customer's literals,
  because the blobs differ. A per-customer build therefore
  **re-encrypts the literals under that customer's seed, re-seals the
  wrapper, re-links, and re-signs**. Reseal's *sole* real saving over
  this is skipping the blob re-encryption — symmetric AEAD over the
  literal set, cheap in absolute terms — and it is **dwarfed by the
  irreducible per-customer cost (re-link + re-sign + notarize)** that
  reseal cannot avoid either: macOS forces re-sign + notarize per
  artifact regardless, and a freshly built artifact has cleaner
  provenance than an in-place-patched one. Reseal is deleted because
  its marginal saving does not justify the in-place binary mutation it
  requires (the macOS ad-hoc-sign hole, atomic tempfile commit,
  `MoveFileExW` unsafe, and the derived locator that let an external
  tool find the wrapper) — **not** because a rebuild is cost-equivalent
  via a shared blob cache (§9).
  - **0.4.1 (blob/wrapper input separation, normative).** litmask-build
    MUST keep blob encryption keyed on `mask_key`/seed and wrapper
    sealing keyed on `unlock_key` as **distinct build inputs**. This
    bounds the **same-customer patch-rebuild**: with that customer's
    seed pinned, a source-only change re-encrypts only the touched
    literals, and an `unlock_key` rotation alone re-seals the wrapper
    **without** invalidating that customer's blob cache. It does **not**
    make *cross-customer* builds share blobs — each customer's distinct
    seed yields a distinct blob pool by design (§0.4, the isolation
    property). The separation bounds per-customer and per-patch cost; it
    does not collapse customers onto one cache.

## 1. Tier-0 default (inherited)

Bare `init!()` — **or no `init!` call at all** — falls
back to `unlock_key = KDF(wrapper_nonce, "litmask-tier0-v1")`. Works
with no key, no env var, no failure mode; bit-reproducible; degrades to
an AEAD `obfstr`. Key recoverable from the artifact — the honest floor.
Accidental ship of a zero-wired build degrades to this floor, never
plaintext.

- **1.1 (silent-floor hazard + guard, normative).** Tier-0's
  no-failure-mode is double-edged: a higher tier fails loud when its key
  is absent, but a build left at Tier-0 by mistake — forgot to upgrade
  bare `init!()`, or omitted `init!` entirely — opens forever and looks
  healthy. The works-by-default win *is* the silent-misconfig footgun.
  **One guard, at the build, where the floor is decided independently of
  the `init!` form:** `emit()` derives the tier tag from build-input
  presence (§2.4), so when the tag is `tier0` under the release profile
  it emits a `cargo:warning=` ("Tier-0 obfuscation floor in a release
  build"). Because the warning is **presence-driven, not form-driven**,
  one emission covers **both** floor paths the old macro-side split could
  not unify — a *deliberately* bare `init!()` **and** an *omitted*
  `init!` (no-init / lazy-init) — with no per-call-site duplication and
  **no string baked into the shipped binary** (build-log channel only,
  like the §6.2 seed warning; preserves opacity, §7.2). The release gate
  reuses emit()'s existing `Profile::Release` detection
  (`fresh_release_warning`, litmask-build/src/lib.rs:273). This is
  distinct from the §2.4 cross-check, which *errors* when the `init!`
  form and the tag disagree (an *intended* higher tier whose build input
  is missing); §1.1 only *warns*, and only when the tag legitimately is
  `tier0`. (Build-warning re-display caveat: I-R7.)

## 2. Build-time tiers

Tiers are selected at runtime by the `init!` **form**; the wrapper is
sealed **at build** from inputs supplied at build. The external factor is
an opaque `KeyProvider` **value**, but **machine binding is a one-keyword
carve-out** (`machine_id`) so the decision to bind to a host is **explicit
in source** and cross-checkable against the build (§2.4). There are **four
forms** of the single `init!` macro:

- `init!()` — **Tier-0** (nonce-derived floor).
- `init!(<provider-expr>)` — **external-only**; any `impl KeyProvider`.
- `init!(machine_id)` — **machine-only** (single-factor host binding).
- `init!(machine_id + <provider-expr>)` — **machine + external** (the
  headline two-factor tier, §2.3).

The external slot stays a **value**: custom providers are first-class (not
a `custom:` special case), type-checked, and IDE-discoverable. `machine_id`
is the **only** keyword — it is litmask-owned, target-host-resolved, and the
one factor carrying a build/runtime topology hazard, so it earns a
source-visible, macro-checkable form. **There is no general `MultiProvider`
and no variadic ordering surface** — the only composable combination is
machine + one external, fixed-arity and fixed-order (§2.2). Parse: a leading
`machine_id` token (reserved in first position) optionally followed by `+
<expr>`; anything else parses as a bare external `<expr>`. Providers do not
`impl Add`, so `machine_id + X` is never a real binary-add expression.
**Caveat (minor):** `machine_id` is reserved in leading position, so a
value-form provider or local binding literally named `machine_id` is
unreachable via `init!(machine_id …)` (the macro intercepts the token as
the keyword). Low blast radius — documented so a consumer who happens to
name a binding `machine_id` understands the shadowing.

> **Build/runtime agreement is reconciled at compile time (load-bearing).**
> `emit()` seals `mask_key` under an `unlock_key` computed from
> **build-supplied material**, and the runtime independently re-sources the
> same `unlock_key`. The keying is therefore declared in **two places that
> must agree** — build inputs and the `init!` form. Rather than leave that
> agreement to silent runtime AEAD failure, `emit()` publishes a **tracked
> tier tag** (`LITMASK_SEAL_TIER`, §2.4) that the macro reads at expansion
> and **cross-checks against the `init!` form**: a mismatch is a
> `compile_error!`, not a deploy-time surprise. The build still cannot
> evaluate the external provider *value* (symmetric blindness on the
> material bytes — that is `material = identity`, Alice's secret-management
> responsibility), but the *topology* (which factors, machine-bound or not)
> is now agreed at compile time.

- **Tier-0 (default):** nonce-derived, no input. `init!()`.
- **Env/file provider:** `EnvVarProvider` / `FileProvider` as the external
  value. Key material from `LITMASK_UNLOCK_KEY` / a file at runtime; the
  same material is fed to `emit()` at build via `LITMASK_UNLOCK_KEY`.
- **`machine_id` keyword:** the **raw machine-id** is supplied at build
  via `LITMASK_MACHINE_ID` (§4); litmask derives the factor material
  internally (nonce-derived salt, §4.1). Runtime re-derives from the local
  machine-id. Machine binding is **never a passed value** — it is the
  `machine_id` keyword only, so `MachineIdProvider` is **not** a public type.
- **Custom provider:** any `impl KeyProvider` in the external slot whose
  material the runtime fetches via its own credential path. Build-sealable
  only if the operator supplies the *exact* material the provider returns at
  runtime (fed to `emit()` via `LITMASK_UNLOCK_KEY`).
- **machine + external:** the two-factor headline tier (§2.3), written
  `init!(machine_id + <provider>)`. The only composable combination.

There is no deploy-time tier change. To change a binary's tier or key,
**rebuild**.

- **2.1 (no silent downgrade, normative — now a compile-time guarantee).**
  The `init!` form and the build-emitted tier tag (§2.4) MUST agree. A
  higher-tier form whose build input is missing — e.g.
  `init!(machine_id + EnvVarProvider::default())` built with
  `LITMASK_MACHINE_ID` **or** `LITMASK_UNLOCK_KEY` unset — yields a tag that
  does not match the form, which is a **`compile_error!`** (§2.4). `emit()`
  MUST NOT fall back to sealing under a lower tier and let it ship. Fail
  toward the tier the source asked for; never silently ship the floor or a
  weaker binding. This subsumes the former build-side guard: the source-side
  "forgot to upgrade bare `init!()`" case is *also* caught — bare `init!()`
  against a non-`tier0` tag fails to compile (and §1.1 still warns on a
  deliberate release Tier-0).
- **2.2 (composition — always-normalize KDF; fixed machine + external).**
  The framework applies **one** KDF at the init boundary
  (`__init_with_wrapper`): `unlock_key = KDF(info = "litmask-unlock-v1",
  ikm = material)`. For a single external factor, `material` is the
  provider's bytes (`Zeroizing`, *any* length). For
  `init!(machine_id + <provider>)`, the macro injects a fixed two-factor
  composition whose material is the **flat concatenation**
  `len_prefixed(machine_material) ‖ len_prefixed(external_material)` —
  concatenate only, **never** an inner KDF (an inner KDF would produce a
  finished key, reviving the verbatim/derived split — forbidden). One KDF
  either way: single → `KDF(material)`, two-factor → `KDF(Σ len_prefixed
  (..))`. **Order is fixed by construction** (machine material first,
  external second) — there is no variadic constructor and no argument-order
  surface to get wrong, which is precisely why the general `MultiProvider`
  was dropped (its order-significant variadic shape had no
  footgun-free build/runtime agreement; canonical-sort fails on unsortable
  custom providers, and a composition fingerprint only detects). The 8-byte
  LE length-prefix convention is the existing crate-wide one
  (`litmask-internal::kdf`). **All-or-nothing:** if either factor errs,
  init errs. Build-sealable iff **both** factors are build-sealable (the
  custom external is the only one that may not be — §2 custom bullet).
- **2.3 (the two-factor tier is the only thing that stops a local
  attacker).** The point of `init!(machine_id + EnvVarProvider::default())`
  is two-factor: the external factor (env/file/custom) is bytes the binary
  does **not** carry, so a co-resident *different-UID* / off-host process
  can read the victim binary but not its runtime env (process isolation). A
  bare `init!(machine_id)` binds to the host but is reconstructible *on* that
  host (id readable, salt from the artifact); the external factor is what a
  same-host attacker lacks. **Caveat (local-root):** a **same-UID or root**
  attacker reads `/proc/<pid>/environ` and ptraces the decrypted
  `mask_key` from memory — that defeats *every* factor. The two-factor tier
  defends the different-UID / off-host case, not local root.

- **2.4 (build-authoritative tier tag + compile-time cross-check,
  normative).** `emit()` is **dumb and presence-driven**: it selects the
  sealed tier purely from which build inputs are present, and publishes the
  result as a **tracked tier tag** the macro validates against the `init!`
  form.

  - **Tag derivation (presence-driven):**

    | `LITMASK_MACHINE_ID` | `LITMASK_UNLOCK_KEY` | tag |
    |---|---|---|
    | set | set | `machine_external` |
    | set | — | `machine` |
    | — | set | `external` |
    | — | — | `tier0` |

  - **Channel (normative): the tag is a *tracked* build output, not an
    `$OUT_DIR` file.** `emit()` emits
    `cargo:rustc-env=LITMASK_SEAL_TIER=<tag>` plus
    `cargo:rerun-if-env-changed=LITMASK_MACHINE_ID` and
    `=LITMASK_UNLOCK_KEY`. A `rustc-env` value is part of the crate's
    compile fingerprint, so flipping a factor reliably **recompiles** the
    consumer crate and re-runs the macro check. An `$OUT_DIR` marker file
    would **not**: proc-macro reads of `$OUT_DIR` contents are untracked by
    the compiler (`tracked_path` is nightly-only), so a stale check could
    survive a factor flip.
  - **Wrapper freshness (normative clarification).** A factor **flip**
    (tier change) recompiles via the tag fingerprint above. The common
    per-customer case is **not** a flip — same tier, new `unlock_key`
    *value* — so the tag is unchanged and cannot drive freshness. There,
    freshness rides on (i) `rerun-if-env-changed=LITMASK_UNLOCK_KEY`
    re-running `emit()` to rewrite `litmask_wrapper.bin`, and (ii) the
    wrapper being delivered via `include_bytes!`
    (litmask/src/lib.rs:219-225), a compiler builtin that
    **content-tracks** the file and recompiles the consumer crate when
    its bytes change. The wrapper MUST stay `include_bytes!`-delivered
    for this reason: if it ever moved to a proc-macro `std::fs` read
    (untracked, like the key/seed blobs), a same-tier `unlock_key` change
    would go **stale** and ship the prior customer's wrapper. (The tag
    "unsticks the wrapper" only for *flips*; the same-tier value case is
    carried by `include_bytes!`, not the tag.)
  - **Single-crate co-location (normative).** `cargo:rustc-env` and
    `OUT_DIR` reach **only the crate owning the `build.rs` that calls
    `emit()`**. The `init!`/`mask!` call sites MUST live in that same
    crate; a workspace that puts `emit()` in one crate and `init!` in
    another breaks the channel — the macro reads an absent/stale tag. On
    an **absent** `LITMASK_SEAL_TIER` the macro MUST `compile_error!`
    ("litmask: build channel missing — is `litmask_build::emit()` called
    from this crate's build.rs?") and MUST NOT assume `tier0` (assuming
    the floor would silently downgrade an intended higher tier). (I-R6.)
  - **Cross-check (normative): the `init!` form MUST match the tag, or the
    build fails.** 1:1 mapping:

    | `init!` form | required `LITMASK_SEAL_TIER` |
    |---|---|
    | `init!()` | `tier0` |
    | `init!(<expr>)` | `external` |
    | `init!(machine_id)` | `machine` |
    | `init!(machine_id + <expr>)` | `machine_external` |

    Any disagreement is a `compile_error!` naming the missing input. This
    closes **both** drop-a-variable directions: a dropped
    `LITMASK_MACHINE_ID` (tag → `external`) and a dropped
    `LITMASK_UNLOCK_KEY` (tag → `machine`) each contradict an
    `init!(machine_id + …)` source and fail to compile, rather than silently
    downgrading the binding. The tag carries **no secret** and is **never
    embedded** in the shipped binary — it lives only on the build→macro
    channel, so it adds no opacity leak (contrast the rejected
    wrapper-embedded composition fingerprint, which both leaked and only
    *detected*).
  - **AC4 narrowing (owed):** litmask-build's AC4 test currently bans **all**
    `cargo:rustc-env=LITMASK*` (its real intent: no *secret* via rustc-env,
    which logs at `--verbose` and injects downstream). Narrow it to "**no
    secret** via rustc-env; `LITMASK_SEAL_TIER` is the sole whitelisted
    non-secret tag." Do not evade the test by renaming the variable — fix the
    rule to state its intent.

## 3. Build-time secret inputs

- **3.1.** Direct keys / machine-ids / env secrets are read from the
  **build environment** (env var, file, or stdin to `litmask-build`),
  not embedded as project config and never written to a shipped
  artifact in cleartext.
- **3.2 (threat-model note, normative).** A build-time
  key or machine-id is **exposed to the build environment**: any build
  script / proc-macro / build dependency in the tree can read it from
  the process env during the build. **Treat the build host as trusted
  with the key.** This is fine for "Alice builds her own app";
  build-as-a-service or untrusted build dependencies are a documented
  limitation. (Same threat class as the S1 seed-leak; the fix posture
  is "don't echo it," see §6.) **No widened boundary:** the build host
  already holds the seed and derives `mask_key`, so it is already the
  maximally-trusted node; it also seeing each `unlock_key` adds no trust.
  A secret store (JIT fetch, no persistent key pile, audit) handles
  at-rest custody; the irreducible remainder is this same §3.2 in-process
  exposure, once per build.
- **3.3 (named build channels, normative).** The two factor inputs have
  fixed env names so `emit()` can derive the tier tag (§2.4) by presence:
  - `LITMASK_MACHINE_ID` — the **raw** target machine-id (§4.1), not a
    precomputed key.
  - `LITMASK_UNLOCK_KEY` — the external factor's **material** (the same
    bytes the runtime provider re-sources; `material = identity`).
  File / stdin equivalents MAY back either channel, but presence on the
  channel is what drives the tag. Neither value is ever echoed (§6.2); the
  derived `LITMASK_SEAL_TIER` tag is non-secret and is the only litmask
  value permitted on the `rustc-env` channel (§2.4 AC4 narrowing).

## 4. Machine-id tier — raw id at build, no self-service rebind

- **4.1 (raw-id interface, normative).** The provisioning channel
  carries the **raw machine-id** (Bob runs `show-machine-id`,
  reports it to the builder **before** the build). The builder supplies
  the id to `emit()` via `LITMASK_MACHINE_ID` (§3.3), which generates the
  nonce, computes `machine_salt = KDF(nonce)`, and derives the **machine
  factor material**. For `init!(machine_id)` that material alone is KDF'd
  into `unlock_key`; for `init!(machine_id + <provider>)` it is composed
  with the external material first (§2.2). The builder **never** receives
  or re-runs a precomputed key — litmask owns the KDF as the single source
  of truth. Because the raw id is captured **before** the build, the
  machine factor — though a *target-host* property of Bob's machine — needs
  **no post-build re-key**: `emit()` reproduces it from the supplied id and
  the build-owned nonce, exactly as a single-factor seal does
  (per-customer = per-build, §0.2).
- **4.1.1 (self-checking id token, normative).** `show-machine-id`
  prints a **self-validating token** on **stdout** — the raw id plus
  embedded check symbols (Crockford base32 + check digit, or a short
  truncated-BLAKE3 group appended). Human guidance ("send this to your
  vendor") goes to **stderr** only. The checksum rides *in-band* in the
  copied token, never on a separate stream: Bob copies stdout, so a
  stderr checksum would be dropped by the channel. `emit()` validates the
  check group before sealing; a mistyped id is rejected **before** the
  build, not surfaced as an opaque runtime init failure on Bob's deploy
  host (the original F1 friction).
- **4.2 (why raw id, not a precomputed key).** Under nonce-derived
  salt the machine `unlock_key` depends on the build-generated nonce,
  so it **cannot** be precomputed off-box. Passing the raw id is
  therefore the *only* viable interface — and the better one: no trust
  that the channel partner ran the exact KDF, and the build holds the
  nonce so any future `f(nonce, id, salt)` change is a drop-in.
- **4.3 (no self-service rebind, accepted cost).** A machine-id change
  on the deployment host breaks the binary; recovery is a **rebuild**
  by the builder (who is already the per-customer build authority).
  The lost capability is *self-service* on-host migration only. This
  is accepted: machine changes are infrequent, the builder is already
  in the loop, and rebuild-per-machine yields cleaner provenance.
- **4.4 (CLI surface).** Two generate/read-only tools remain; neither
  mutates a binary:
  - **`show-machine-id`** — prints the host's self-checking id token
    (§4.1.1) for the provisioning channel.
  - **`keygen`** — pure stdout generator: 32 random base64url bytes,
    serving as an `unlock_key` *or* a per-customer **seed** (role is
    usage, not format). No binary I/O. Enables seed custody:
    `litmask keygen | <store> put cryptio/bob/seed` up front, per
    customer, so a pinned seed gives bit-reproducible patch-rebuilds
    (I-R4) without the removed ledger.

- **4.5 (scope — machine-id is a stable-host factor, normative).**
  Build-time machine binding targets **stable** hosts: the id is
  captured once (§4.1) and the binary is rebuilt on the rare drift
  (§4.3). For **churning fleets** — autoscaled VMs, ephemeral cloud
  instances, frequent hardware swaps — where the id changes often,
  machine-id is the **wrong factor**: every drift forces a full
  per-customer rebuild + re-sign + notarize cycle (I-R1). Such
  deployments SHOULD bind on an **external factor delivered by the
  orchestrator** instead (`EnvVarProvider` / `FileProvider` / custom),
  which the fleet's existing provisioning (env injection, mounted
  secret, vault fetch) rotates with **no litmask rebuild**. Machine-id
  is for "ship a desktop app to Bob's one durable machine," not for a
  fleet that re-provisions hosts. The docs MUST state this scope so a
  consumer does not reach for machine-id on a churning fleet and land
  on the rebuild treadmill.
  - **4.5.1 (on-host install-time bind — escape hatch, non-normative).**
    Where the target id is knowable only on the host *and*
    rebuild-per-host is unacceptable, an **installer-time** bind is an
    out-of-band option: ship a Tier-0 or env-tier binary and have a
    first-run/installer step on the *trusted* target derive and store
    the host factor, binding subsequent copies. This is **not** a
    litmask mechanism — it is the deleted post-build self-seal, circular
    as a *general* keying path (header), and it protects only against
    theft *after* install (the shipped pre-install artifact is only
    Tier-0/env-grade in transit). It is named only as a deployment
    pattern the operator may build themselves for the narrow
    machine-binding case; litmask ships no tool for it.

## 5. Wrapper format

- **5.1 (normative).** The wrapper is `nonce(12) ‖ AEAD(version_byte ‖
  mask_key) ‖ tag(16)`. **No locator prefix.** No plaintext
  format/cipher header beyond the AEAD-protected `version_byte`.
- **5.2 (located by address, not by scan).** The runtime references the
  wrapper `static` by compile-time address (`include_bytes!`). No
  runtime scan, no symbol tell required in a stripped release binary.
  Opacity is preserved for free: with nothing scanning for the
  wrapper, no findability signature exists to leak. (Not invisibility —
  a disassembler following the init path still reaches the `.rodata`
  address; the gain is over a blind byte scan.)
- **5.3 (no runtime tier introspection — floor warning lives at the
  build).** The Tier-0 floor warning is emitted by `emit()` at build time
  (§1.1), **not** by the runtime. A runtime floor check would have to bake
  an identifying warning string into the shipped `.rodata`, leaking
  litmask presence to `strings(1)` and clashing with the
  panic-message-hygiene rule (litmask/src/runtime.rs:8-12); the build-log
  channel avoids both and still covers the no-init case (presence-driven,
  §1.1). There is likewise **no public `sealed_tier()`/`--security-status`
  surface** (a consumer-callable tier query would have to run before the
  app's own arg parsing — awkward and unenforceable; cut).
  - **Accepted residual (consumer bound-check, was I-3).** A consumer
    (Bob) has **no off-box or on-host query** to confirm "is this
    actually bound to me?" beyond running the app: it works ⇒ it opened.
    Floor-vs-bound off-box would need find + trial-decrypt = the removed
    locator, impossible by design. Accepted: the builder owns
    provisioning; consumer-side assurance is out of scope.

- **5.4 (profile-split runtime diagnostics, normative).** The
  panic-message hygiene that keeps identifying strings out of `.rodata`
  (litmask/src/runtime.rs:8-12) protects **shipped** binaries, so it
  applies to **release** alone. Failure messaging is gated on profile:
  - **Debug (`cfg(debug_assertions)`)** — init and lazy-init failures
    panic **loud and actionable**. The failing arm is known
    (`__init_with_wrapper`, litmask/src/runtime.rs:90-110), so each cause
    maps to a hint: a `KeyProvider` error → provider could not source
    material (`LITMASK_UNLOCK_KEY` unset / malformed?); an AEAD
    authentication failure → the runtime-sourced key did not open the
    build-sealed wrapper (provider material, machine-id, or `init!` form
    disagrees with the build tier); an unrecognized wrapper header →
    build/runtime version mismatch. Debug builds are self-decrypting and
    **never distributed** (§7.1), so identifying text is free here.
  - **Release (`cfg(not(debug_assertions))`)** — the lazy-init and
    decrypt paths keep the bare `panic!()` (no message), preserving
    opacity. The explicit `init!()?` path returns the structured, terse
    `InitError` (litmask/src/error.rs) in **both** profiles for callers
    that handle it.

  This turns F1 *opaque runtime death* (I-R2 — including the
  external-material-mismatch, wrong-source-host, and no-init+machine
  cases that **no** build-time check catches) into a **clear failure on
  the developer's own machine during the debug loop**, before any
  release artifact ships — without weakening release opacity. Implemented
  as one `cfg`-gated internal panic helper replacing the bare lazy-path
  panics (litmask/src/runtime.rs:292,300,317,328); `init!()?` unchanged.

## 6. Build-time guarantees (no runtime self-assertion)

- **6.1 (round-trip is a unit-test invariant, not a per-build step).**
  Seal/unseal correctness is covered by a litmask **unit test**
  (`build_artifacts_wrapper_round_trips_under_unlock_key`,
  litmask-build/src/lib.rs:523, via `decrypt_wrapper`), not a
  per-consumer-build runtime assertion in `emit()`. This drops the
  per-build cost and avoids a tautology: for the machine tier a
  build-time round-trip only proves `emit()` can reopen with the *same*
  id it just sealed under — it says nothing about whether Bob's deploy
  host emits that id (the case that actually matters; see I-R2).
- **6.2 (S1 — no secret echo).** `emit()` MUST NOT print the seed,
  unlock key, machine-id, or any secret input to `cargo:warning=` or
  any build log. Warnings carry no secret values. (Still live in code:
  litmask-build/src/lib.rs:283 echoes `LITMASK_RNG_SEED=<seed>` — owed
  removal. Reproducible rebuild instead relies on the operator pinning
  the seed up front via `keygen`, §4.4 / I-R4; there is no post-hoc
  seed-recovery channel.) Once the echo is removed, the **only**
  sanctioned release `cargo:warning=` from `emit()` is the §1.1 Tier-0
  floor notice, which carries no secret value.

## 7. Threat-model deltas

- **7.1 (debug self-decrypts + diagnoses).** Debug
  builds seal like release (no pass-through plaintext) but **fail loud**:
  init failures carry actionable, identifying messages (§5.4). A debug
  binary is self-decrypting at Tier-0 *and* prints litmask-identifying
  diagnostics, so it **must never be distributed** — the accepted trust
  boundary belongs in `THREAT_MODEL.md`.
- **7.2 (opacity unchanged or improved).** Removing the locator removes
  one derived value from the artifact; the wrapper is indistinguishable
  `.rodata`. The dirty-word scrub still gates against identifying
  substrings.
- **7.3 (host compromise unchanged).** Machine-id binding defends only
  the "exfiltrate the binary, run/analyze it elsewhere" path. A rooted
  deployment host has the live process and the decrypted `mask_key`
  regardless. L2 / partial-L3 posture, defense-in-depth, not a wall.
- **7.4 (build-env key exposure).** See §3.2.

## 8. Doc edits owed (if adopted)

- `README.md` / `DEPLOYMENT.md`: remove the `awk`-on-config key ritual
  and the `bind`/`reseal` workflows; document build-time tiers and the
  raw-machine-id provisioning channel; keep `keygen` + `show-machine-id`;
  document seed-pinning via `keygen` (§4.4) and the self-checking id
  token (§4.1.1).
- `THREAT_MODEL.md`: add §3.2 build-env key exposure, §7.1 debug
  self-decrypt-**and-diagnose** boundary (§5.4), §7.2
  opacity-without-locator.
- `CONTEXT.md`: retire **locator** and **litmask.config** as terms (or
  mark historical); `bind`/`reseal`/`inspect` terms removed. Retire
  **`MultiProvider`** and the public **`MachineIdProvider`** type; add
  **`machine_id` keyword**, **`LITMASK_SEAL_TIER` tier tag**, and the
  **`LITMASK_MACHINE_ID` / `LITMASK_UNLOCK_KEY`** build channels.
- `SPECIFICATION.md`: large surgery — delete §2.9 CLI re-key/inspect
  flows and the derived-locator sections; collapse the wrapper format
  to §5.1.
- `litmask-build` AC4 test: narrow from "no `LITMASK*` rustc-env" to "no
  *secret* via rustc-env; `LITMASK_SEAL_TIER` whitelisted" (§2.4).
- `litmask`: remove `MachineIdProvider` from the public API (machine binding
  is the `machine_id` keyword); `emit()` emits the `LITMASK_SEAL_TIER` tag +
  `rerun-if-env-changed` for both factor channels; `init!` reads the tag and
  cross-checks the form, `compile_error!` on absent tag (§2.4).
- `litmask-build`: `emit()` emits the §1.1 Tier-0 floor `cargo:warning=`
  (release + tag `tier0`), reusing `Profile::Release` detection
  (litmask-build/src/lib.rs:273); remove the §6.2 seed echo (line 283).
- `litmask`: replace the bare lazy-path `panic!()`s
  (litmask/src/runtime.rs:292,300,317,328) with a `cfg(debug_assertions)`-gated
  panic helper carrying actionable messages in debug, bare in release (§5.4).

## 9. Surface disposition (remove / keep / replace)

The net change from litmask's pre-spec design (a post-build
re-key/inspect CLI, a derived locator, and a split init macro). This
doubles as the implementer's delete/replace list against the current
codebase.

| Surface | Disposition |
|---|---|
| Keying paths | **build-seal only** — post-build reseal removed |
| Re-key CLI (`bind`/`reseal`) | **removed** — re-keying moves to rebuild |
| Verify CLI (`inspect`/`verify`, `--check-decrypt`) | **removed** — on-host check = run the binary; seal/unseal round-trip is a unit test (§6.1) |
| Derived locator + recorded-locator config | **removed** — runtime finds the wrapper by compile-time address (§5.2) |
| Wrapper format | `nonce ‖ AEAD ‖ tag`, **no locator prefix**, address-found (§5.1) |
| Machine-id | **build-time raw id only** (§4.1); no `--to-machine-id` reseal |
| CLI surface | **`{keygen, show-machine-id}`** — generate/read-only, no binary mutation (§4.4) |
| Tier-0 default, nonce-salt, `weak_mask!`, dirty-word scrub | **kept** |
| Init macro | **single `init!`** (the `init_with!` split folded in), four forms: `()` / `(<expr>)` / `(machine_id)` / `(machine_id + <expr>)` |
| Factor selection | external = `impl KeyProvider` **value**; `machine_id` = one-keyword carve-out. No keyword DSL, no general `MultiProvider`, no variadic order surface (§2) |
| Multi-factor | **fixed `machine_id + <external>`** — arity-2, order fixed by construction (§2.2) |
| Build/runtime tier agreement | **tracked `LITMASK_SEAL_TIER` tag, cross-checked at compile time** (§2.4); replaces silent runtime AEAD failure on mismatch |
| Tier-0-in-release guard | **build-time `emit()` floor warning** (§1.1); no runtime warning string |
| Runtime failure diagnostics | **profile-split** — loud/actionable in debug, bare/opaque in release (§5.4) |

## 10. Honest residuals

- **I-R1 (no self-service rebind).** Machine changes require a builder
  rebuild (§4.3). Accepted; the builder owns provisioning anyway. Honest
  cost: *every* drift = a full per-customer rebuild + re-sign + notarize
  cycle, re-opening the provisioning channel — reseal's channel cost is
  relabeled, not removed. For fleets with churning ids (VMs, cloud,
  hardware swaps) this recurs; the infrequent-change premise (§4.3)
  is an assumption about the target deployment, not a guarantee.
  **Scoped by §4.5:** machine-id is documented as a **stable-host**
  factor; churning fleets are directed to an external
  orchestrator-delivered factor instead, sidestepping the treadmill.
  The residual stands only for genuinely stable hosts that nonetheless
  occasionally drift, where rebuild is the accepted recovery.
- **I-R2 (no off-box assurance).** No way to confirm a bound binary will
  unlock on a target except by running it there. The former §6
  build-time round-trip is **gone** (it proved crypto-correctness, not
  target-openability — §6.1). Mitigated by (i) the determinism of tier
  derivation, (ii) the build-time floor warning (§1.1), and (iii)
  **loud, actionable debug-build diagnostics (§5.4)** that surface the
  external-material-mismatch, wrong-source-host, and no-init+machine
  misconfigurations on the developer's own machine before a release
  ships. There is **no** consumer-callable tier query (§5.3) and **no**
  runtime warning string in release (opacity preserved); the residual is
  the irreducible "a stable host must be exercised once."
- **I-R3 (build-env key exposure).** §3.2 — build host trusted with
  the key; untrusted build deps out of scope. This is not a new trust
  boundary: the build host already holds the seed + `mask_key`, and a
  secret store handles at-rest custody (§3.2).
- **I-R4 (per-customer build cost — N real builds).** The seed is pinned **per customer** (§4.4), giving each
  customer a distinct `mask_key` and a distinct blob pool — the literal
  isolation property (§0.4). So a per-customer build **does** re-encrypt
  the literals (symmetric AEAD, cheap in absolute terms), re-seals the
  wrapper, re-links, and re-signs. A post-build reseal step (one of the
  surfaces this spec eliminates, §9) would save only the blob
  re-encryption, dwarfed by the irreducible re-link + re-sign +
  notarize that reseal could not avoid either — so dropping reseal in
  favor of a full per-customer build is not a cost regression. The
  earlier "byte-identical blobs reused from cache across customers"
  claim was **wrong** — it assumed one shared seed, which would forfeit
  per-customer isolation — and is **withdrawn**;
  the blob cache survives only across **same-customer** patch-rebuilds
  (same pinned seed), not across customers (§0.4.1). Bit-reproducible
  patch-rebuild requires that customer's seed pinned **up front** (mint
  with `keygen`, store per §4.4); there is no post-hoc seed-recovery
  channel (§6.2).
- **I-R5 (`keygen` — resolved: kept).** Direct-key and seed tiers need a
  generator; `keygen` ships as a pure stdout generator (§4.4), no binary
  I/O, not part of the removed re-key surface. It also resolves seed
  custody (I-R4). CLI surface is `{keygen, show-machine-id}`.
- **I-R6 (cross-crate build channel).** The tier tag and `OUT_DIR` reach
  only the crate that owns `emit()`'s `build.rs`; `init!`/`mask!` MUST
  co-locate there (§2.4 single-crate co-location). A workspace split is
  rejected at compile time (absent-tag `compile_error!`), never silently
  downgraded — a hard failure, but discoverable at build, not at Bob's
  runtime.
- **I-R7 (build-warning re-display).** The §1.1 floor warning rides
  cargo's build-script `cargo:warning=` channel, which cargo only
  re-displays when `build.rs` re-runs. A source-only incremental rebuild
  of an already-built tier0 crate may not re-echo it;
  `rerun-if-env-changed` on the factor vars covers tier flips and a
  fresh/release build always shows it. Same limitation as the seed
  warning today; accepted.

## Appendix A. Origin friction (F1–F7, S1)

This design exists to remove a catalogue of friction observed live in the
pre-spec codebase (not theorized). It is preserved here so the rationale
behind each mechanism survives without external documents. Each entry
notes where this spec addresses it.

1. **F1 — Opaque runtime death.** A missing *or* wrong `unlock_key` both
   abort with the same opaque `explicit panic` and no hint. Exit codes
   differed by profile, not cause (debug 101 unwind, release 134
   `panic = "abort"`). Missing-key and wrong-key are internally distinct
   (`runtime.rs` NotFound vs decrypt) yet present identically. The default
   `mask!`-only path (implicit init) bypassed the `sysexits` codes that
   only fire under `init_with!` + `InitError` handling. **Addressed:** the
   profile-split diagnostics (§5.4) make debug builds fail loud and
   actionable while release stays bare/opaque (§5.3, opacity preserved).
2. **F2 — `awk` ritual.** Extracting the key for every run/deploy required
   `awk -F'"' '/^unlock_key/...' litmask.config`. **Addressed:** the
   build-sealed model has no runtime `unlock_key` to extract and no config
   file to parse — tier-0 self-unlocks (§1), higher tiers take material as
   build env (§3). The `litmask.config` channel is removed entirely (§9).
3. **F3 — Silent key rotation.** Any `build.rs` rerun (touch, CI, fresh
   checkout) rotated the release `unlock_key`; a previously-captured key
   then died with the same opaque panic, no staleness signal. Root cause:
   `emit()` (build.rs) and macro-expansion (compile) were decoupled —
   `emit` rewrote the config + `OUT_DIR` key files, but cargo did not
   always recompile the consumer when only `OUT_DIR` changed, so a
   freshly-emitted config could carry a key the on-disk binary's baked
   wrapper did not match. **Addressed:** the seal is baked into the binary
   at build (§2.4, single-crate co-location of `emit`/`init!`/`mask!`); no
   separately-stored key to drift, no post-build re-key surface (§9).
   Reproducibility comes from per-customer seed pinning (§4.4).
4. **F4 — Shared-config clobbering.** (a) Every build overwrote the single
   `target/<profile>/litmask.config`, so building Carol after Bob lost
   Bob's config/locator. (b) `bind` mutated that same shared file in place.
   **Addressed:** no shared config file exists (§9); per-customer identity
   lives in per-customer seeds (§4.4) and N real per-customer builds (§0.4,
   I-R4).
5. **F5 — No per-customer build/key ergonomics.** Minting a per-customer
   seed was hand-rolled (`head -c32 /dev/urandom | basenc`). **Addressed:**
   `keygen` mints seed/key material as a pure stdout generator (§4.4,
   I-R5).
6. **F6 — No key-wire helper.** Nothing wired the matching key to a binary;
   the operator hand-assembled `LITMASK_UNLOCK_KEY=… ./app`. **Addressed:**
   the dev loop wires nothing (tier-0 self-unlock, §1); release material is
   a build-time input (§3), not a runtime wiring step.
7. **F7 — `inspect` is locator-only.** It confirmed the config's `locator`
   was present in the binary but never that the `unlock_key` actually
   decrypted the wrapper — a right-locator/wrong-key config passed
   `inspect` yet died at runtime. **Addressed:** `inspect` and the
   locator concept are removed (§9); the seal's correctness is established
   at build time (§6), not asserted by a separate post-build tool.
8. **S1 (security) — Seed leak into CI logs.** A fresh **release** build
   emitted a `cargo:warning=` containing `LITMASK_RNG_SEED=<seed>` — the
   master secret (derives both `mask_key` and `unlock_key`). CI captures
   build warnings into shared logs, and cargo caches+replays the warning on
   every build. **Addressed:** `emit()` MUST NOT print the seed value
   (§6.2); the build warning carries no secret material.
