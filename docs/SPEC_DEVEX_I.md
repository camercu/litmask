# litmask Developer-Experience — Specification (Variant I: Build-Sealed Only, No Post-Build Tooling)

> **Status:** design variant, refine phase. Successor to
> `docs/SPEC_DEVEX_G.md`. **Letter skip:** there is no live variant H —
> an earlier H (post-build self-sealing) was created, found fatally
> circular, and deleted (see `project-devex-spec` memory). The letter
> H is left burned; this variant takes the next free letter, I.
>
> **I adopts G's product framing and Tier-0 default** — nonce-derived
> zero-config floor, opt-in stronger tiers, topology-first docs — and
> makes **one structural move**: it **deletes the "binary is something
> you patch" model entirely.** There is **one keying path: build-time
> seal.** With post-build re-keying gone, the CLI (`bind`/`reseal`,
> `inspect`/`verify`), the **derived locator**, and the wrapper's
> find-without-signature machinery all lose their only consumers and
> are removed. What remains is the masking core plus a thin,
> build-time key seam.
>
> Drafted for a deliberate side-by-side decision. If adopted, I
> replaces G (and the rest). The project is **pre-release**, so I lands
> as a direct edit with no migration burden.

## Summary

G got the default right (works-by-default Tier-0) but inherited from
F/B/E a large apparatus built around a single assumption: that a
**built binary gets re-keyed in place** — `bind`/`reseal` patch the
wrapper, `inspect`/`verify` check it off-box, and a **derived locator**
lets those tools find the wrapper in a stripped binary without a
litmask signature.

I challenges that assumption and finds it does not pay:

- **Per-customer rebuild is the spine, not reseal.** Under build-time
  seal, each customer/machine binary is a clean build. Reseal's
  "avoid a rebuild" saving is undercut by signing (macOS forces
  re-sign + notarize per artifact regardless), by warm build caches,
  and by provenance (a freshly built artifact is more auditable than
  an in-place-patched one).
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

**The one principle I asserts:** *if nothing finds the wrapper in a
binary-as-a-file, nothing needs to make it findable.* Keying happens
once, at build, by the party who already owns the keys. Everything that
existed to re-key or inspect a finished artifact is removed.

## What I keeps (verbatim where possible)

- **Tier-0 nonce-derived default (G §1).** Bare `init!()` →
  `unlock_key = KDF(wrapper_nonce, "litmask-tier0-v1")`, recomputed at
  runtime, nothing minted or stored, bit-reproducible. The honest
  floor: AEAD upgrade of `obfstr` — key recoverable from the artifact,
  not "key out of binary."
- **Provider trait + composable, opt-in stronger keys (F/G §2).** A
  factor is an `impl` yielding key **material** (`Zeroizing` bytes, any
  length); `unlock_key = KDF(Σ len-prefixed materials)` — single or
  `multi` (§2.2/§2.3). The trait is the right primitive (the closure-key
  alternative was evaluated and rejected — a bare closure adds only
  inline sugar over a custom impl). Tiers are **build-time** choices,
  not deploy-time.
- **Nonce-derived `machine_salt`, no user salt (F §5, G).**
  `machine_salt = KDF(wrapper_nonce, "litmask-machine-id-salt-v1")`,
  recomputed on demand, never embedded; `machine material =
  KDF(machine_id, salt = machine_salt, info = "litmask-machine-id-v1")`.
  No `--salt`, no salt arg on `MachineIdProvider`. Domain separation only;
  a salt is non-secret and cannot defend (F §5.1).
- **`weak_mask!`** (keeps derivation-context literals out of
  `strings(1)`; independent of the locator — survives).
- **Dirty-word scrub** build-time regression (opacity: built binaries
  carry no forbidden litmask-identifying substrings).
- **Topology-first, honest competitive docs (G §0/§1 framing).**

## What I eliminates (the collapse)

| Eliminated | Why it had no surviving consumer |
|---|---|
| `bind` / `reseal` CLI | Re-keying moves to rebuild. Unique capability (pre-emptive on-host migration) is narrow and rebuild-equivalent; drift recovery fails regardless. Removes in-place patching, atomic tempfile/fsync/rename, Windows `MoveFileExW` unsafe, **macOS ad-hoc re-sign hole**, reseal wire-preservation. |
| `inspect` / `verify` CLI (incl. `--check-decrypt`) | Off-box check on a bound binary is impossible (machine-id mismatch) or tautological (re-derives the builder's own key). Tier-0 is uncheckable off-box (circular locator). On-host check = run the binary. Builder owns provisioning, so nothing independent to verify. |
| **Derived locator** (B §2) + recorded-locator config | Its only purpose was letting an external CLI find the wrapper without a signature. With no such CLI, nothing consumes it. Runtime finds the wrapper by compile-time address. |
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

## 1. Tier-0 default (inherited)

Bare `init!()` — **or no `init!` call at all** — falls
back to `unlock_key = KDF(wrapper_nonce, "litmask-tier0-v1")`. Works
with no key, no env var, no failure mode; bit-reproducible; degrades to
an AEAD `obfstr`. Key recoverable from the artifact — the honest floor
(G §1.4). Accidental ship of a zero-wired build degrades to this floor,
never plaintext.

- **1.1 (silent-floor hazard + guards, normative).** Tier-0's
  no-failure-mode is double-edged: a higher tier fails loud when its key
  is absent, but a build left at Tier-0 by mistake — forgot to upgrade
  bare `init!()`, or omitted `init!` entirely — opens forever and looks
  healthy. The works-by-default win *is* the silent-misconfig footgun.
  Two guards, because the floor is reachable two ways:
  - **Compile-time (bare `init!()` only).** The proc macro knows the
    init form at expansion. Under `cfg(not(debug_assertions))` the bare
    `init!()` expansion emits a compile warning ("Tier-0 obfuscation
    floor in a release build"). The macro cannot observe an *absent*
    init call, so this covers bare `init!()` but not no-init.
  - **Runtime (any floor build, incl. no-init).** See §5.3: an internal
    init-time check compares the resolved `unlock_key` to
    `KDF(wrapper_nonce, "litmask-tier0-v1")` and emits a one-shot release
    warning. Backstops the no-init case the macro cannot see. No public
    API (runs inside init, no arg-parsing dependency).

## 2. Build-time tiers

Tiers are selected at runtime by the `KeyProvider` **value** passed to
the single `init!` macro; the wrapper is sealed **at build** from inputs
supplied at build. There is **one** init macro: bare `init!()` is Tier-0;
`init!(<provider-expr>)` selects a provider; `init!(MultiProvider::new(
[..]))` composes. This is the value form already in the code (`init!()`
defaults to `EnvVarProvider`; old `init_with!($provider:expr)` accepted any
provider value) collapsed into one entry point — bare = default, arg = any
`impl KeyProvider`. **No keyword DSL.** Every selectable factor is an
ordinary `KeyProvider` value, so custom providers are first-class (not a
`custom:` special case) and the set is type-checked and IDE-discoverable.

> **Build/runtime are blind to each other (load-bearing).** The macro
> arg is a *runtime* value the build cannot observe (symmetric blindness,
> §7-deltas). The DSL keywords never drove the build either: `emit()`
> seals `mask_key` under `unlock_key` computed from **build-supplied
> material**, and the runtime provider independently re-sources the same
> `unlock_key`. So the keying is declared in **two places that must
> agree** — build inputs and the runtime provider value. Dropping the DSL
> loses no build wiring; it never had any.

- **Tier-0 (default):** nonce-derived, no input. Bare `init!()`.
- **Env/file provider:** `EnvVarProvider` / `FileProvider`. Key material
  from `LITMASK_UNLOCK_KEY` / a file at runtime; the same material is fed
  to `emit()` at build.
- **`MachineIdProvider`:** the **raw machine-id** is supplied at build
  (§4); litmask derives the factor material internally. Runtime re-derives
  from the local machine-id.
- **Custom provider:** any `impl KeyProvider` whose material the runtime
  fetches via its own credential path. Build-sealable only if the operator
  supplies the *exact* material the provider returns at runtime.
- **`MultiProvider`:** two or more providers composed (§2.2). The headline
  tier (§2.3).

There is no deploy-time tier change. To change a binary's tier or key,
**rebuild**.

- **2.1 (no silent downgrade, normative).** When a provider above Tier-0
  is selected but its build-time key input is missing — e.g.
  `init!(EnvVarProvider::default())` with `LITMASK_UNLOCK_KEY` unset at
  build — `emit()` **fails the build**. It MUST NOT fall back to sealing
  under Tier-0. Fail toward the secure tier the source asked for; never
  silently ship the floor. (Build-side guard; the source-side "forgot to
  upgrade bare `init!()`" case is caught by §1.1.)
- **2.2 (composition — always-normalize KDF; provider yields material).**
  A `KeyProvider` yields key **material** (`Zeroizing` bytes, *any*
  length), **not** a finished key. There is **no verbatim path**: the
  framework applies **one** KDF at the init boundary
  (`__init_with_wrapper`): `unlock_key = KDF(info = "litmask-unlock-v1",
  ikm = material)`. `MultiProvider::new([&a, &b, ..])` is itself a
  `KeyProvider` whose material is the **flat concatenation** `Σ
  len_prefixed(child_material_i)` — it **concatenates only, never KDFs**.
  This is what makes a provider behave **identically standalone and inside
  a multi**: single → `KDF(material)`, multi → `KDF(Σ len_prefixed(..))`,
  one KDF either way. (A `MultiProvider` that KDF'd internally would
  produce a finished key, reviving the verbatim/derived split and breaking
  nesting — forbidden.) Constructor takes a **flat slice/array** (`new([&a,
  &b, &c])`), not binary `new(a, b)`, so the len-prefix boundaries stay
  flat and unambiguous under nesting. **Order = argument order**
  (order-significant). **All-or-nothing:** `MultiProvider` returns `Err` if
  any child errs. Build-sealable iff **every** child is build-sealable
  (custom is the only one that may not be — §2 custom bullet).
- **2.3 (multi is the only thing that stops a local attacker).** The
  point of `MultiProvider::new([&MachineIdProvider, &EnvVarProvider::
  default()])` is two-factor: the external factor (env/file/custom) is
  bytes the binary does **not** carry, so a co-resident *different-UID* /
  off-host process can read the victim binary but not its runtime env
  (process isolation). A single machine-id provider binds to the host but
  is reconstructible *on* that host (id readable, salt from the artifact);
  the external factor is what a same-host attacker lacks. **Caveat
  (F-R1):** a **same-UID or root**
  attacker reads `/proc/<pid>/environ` and ptraces the decrypted
  `mask_key` from memory — that defeats *every* factor. multi defends
  the different-UID / off-host case, not local root.

## 3. Build-time secret inputs

- **3.1.** Direct keys / machine-ids / env secrets are read from the
  **build environment** (env var, file, or stdin to `litmask-build`),
  not embedded as project config and never written to a shipped
  artifact in cleartext.
- **3.2 (threat-model note, normative, owed by F/G too).** A build-time
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

## 4. Machine-id tier — raw id at build, no self-service rebind

- **4.1 (raw-id interface, normative).** The provisioning channel
  carries the **raw machine-id** (Bob runs `show-machine-id`,
  reports it to the builder **before** the build). The builder passes
  the id to `emit()`, which generates the nonce, computes
  `machine_salt = KDF(nonce)`, derives `unlock_key`, and seals. The
  builder **never** receives or re-runs a precomputed key — litmask
  owns the KDF as the single source of truth.
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
- **5.3 (internal floor detection, no public API).** During `init`, the
  runtime holds the wrapper by address (hence the nonce) and the resolved
  `unlock_key`. If `unlock_key == KDF(wrapper_nonce, "litmask-tier0-v1")`
  it is at the Tier-0 floor; under `cfg(not(debug_assertions))` it emits
  a one-shot warning. This backs §1.1's no-init guard — it runs *inside*
  init, so there is no arg-parsing ordering problem. **No public
  `sealed_tier()`/`--security-status` surface** (a consumer-callable
  tier query would have to run before the app's own arg parsing —
  awkward and unenforceable; cut).
  - **Accepted residual (consumer bound-check, was I-3).** A consumer
    (Bob) has **no off-box or on-host query** to confirm "is this
    actually bound to me?" beyond running the app: it works ⇒ it opened.
    Floor-vs-bound off-box would need find + trial-decrypt = the removed
    locator, impossible by design. Accepted: the builder owns
    provisioning; consumer-side assurance is out of scope.

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
  seed-recovery channel.)

## 7. Threat-model deltas

- **7.1 (debug self-decrypts, inherited from G §3.2).** Debug builds
  seal like release (no pass-through plaintext). A debug binary is
  self-decrypting at Tier-0 and **must never be distributed** — the
  accepted trust boundary belongs in `THREAT_MODEL.md`.
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
  self-decrypt boundary, §7.2 opacity-without-locator.
- `CONTEXT.md`: retire **locator** and **litmask.config** as terms (or
  mark historical); `bind`/`reseal`/`inspect` terms removed.
- `SPECIFICATION.md`: large surgery — delete §2.9 CLI re-key/inspect
  flows and the derived-locator sections; collapse the wrapper format
  to §5.1.

## 9. What I removes vs G

| Surface | G | I |
|---|---|---|
| Keying paths | build-seal + reseal (post-build) | **build-seal only** |
| Re-key CLI (`bind`/`reseal`) | present | **removed** |
| Verify CLI (`inspect`/`verify`) | present | **removed** (build-only seal; on-host check = run the binary; round-trip is a unit test §6.1) |
| Derived locator + recorded config | present (B §2) | **removed** |
| Wrapper | `nonce ‖ AEAD ‖ tag` + locator prefix | `nonce ‖ AEAD ‖ tag`, address-found |
| Machine-id | reseal `--to-machine-id` or build | **build-time raw id only** |
| Retained CLI | `{verify, reseal, keygen, show-machine-id}` | **`{keygen, show-machine-id}`** (generate/read-only) |
| Tier-0 default, nonce-salt, `weak_mask`, scrub | present | **kept** |
| Init macro | `init!` + `init_with!` (split) | **single `init!`** (bare = Tier-0, arg = any `impl KeyProvider`) |
| Factor selection | keyword DSL (`env:/file:/machine_id/multi:[..]`) | **provider values** (`EnvVarProvider`, `MultiProvider::new([..])`); no DSL |

## 10. Honest residuals

- **I-R1 (no self-service rebind).** Machine changes require a builder
  rebuild (§4.3). Accepted; the builder owns provisioning anyway. Honest
  cost: *every* drift = a full per-customer rebuild + re-sign + notarize
  cycle, re-opening the provisioning channel — reseal's channel cost is
  relabeled, not removed. For fleets with churning ids (VMs, cloud,
  hardware swaps) this recurs; "machine changes are infrequent" (§4.3)
  is an assumption about the target deployment, not a guarantee.
- **I-R2 (no off-box assurance).** No way to confirm a bound binary will
  unlock on a target except by running it there. The former §6
  build-time round-trip is **gone** (it proved crypto-correctness, not
  target-openability — §6.1). Mitigated only by the determinism of tier
  derivation. No consumer-callable tier query (§5.3); the internal
  floor warning is the only runtime signal, and only for the floor case.
- **I-R3 (build-env key exposure).** §3.2 — build host trusted with
  the key; untrusted build deps out of scope. No boundary expansion vs
  G: the build host already holds the seed + `mask_key`, and a secret
  store handles at-rest custody (§3.2).
- **I-R4 (per-customer build cost).** N machines = N builds. Softened
  by build caching; the heavy step is re-encrypting blobs after a
  changed seed. Accepted as the price of clean provenance.
  Bit-reproducible patch-rebuild requires the customer's seed pinned
  **up front** (mint with `keygen`, store per §4.4); "deterministic from
  build inputs" holds only with the seed treated as a pinned input —
  there is no post-hoc seed-recovery channel (§6.2).
- **I-R5 (`keygen` — resolved: kept).** Direct-key and seed tiers need a
  generator; `keygen` ships as a pure stdout generator (§4.4), no binary
  I/O, not part of the removed re-key surface. It also resolves seed
  custody (I-R4). CLI surface is `{keygen, show-machine-id}`.
