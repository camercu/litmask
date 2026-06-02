# litmask Developer-Experience — Specification (Variant D: B, Minus the Baked Debug Key)

> **Status:** design variant, refine phase. Fifth option beside
> `docs/SPEC_DEVEX.md` (build-generated key), `_A` (operator-owned key),
> `_B` (clean slate), `_C` (declarative + layered). **D adopts B's foundation
> verbatim** — operator-owned `unlock_key`, derived locator, opaque wrapper,
> reseal-default deployment, no-argv secret channels, the four-outcome `verify`
> — and makes exactly two changes, both of which **remove** machinery:
> (1) it **deletes the baked debug constant `K_dev`** and the entire
> self-decrypting-debug-binary hazard class it creates, replacing zero-*per-run*
> wiring with a one-time **developer-environment key**; (2) it adopts C's
> **single `init!` provider site** (removing `init_with!`) — the one C ergonomic
> that costs **no wire format** — while **dropping** C's decl_blob, `derive`-verb
> consolidation, per-customer-seed model, and workflow guard. Drafted for a
> deliberate side-by-side decision. If adopted, D replaces the other four. The
> project is **pre-release**, so D lands as a direct edit with no migration
> burden. **Red-team folded (D-1..D-7):** the ambient-key footgun (a local
> release build sealing under the dev key) is now contained by a clean-env
> release rule (§3.6); the dev story is **tooling-agnostic** — a gitignored
> keyfile read by `FileProvider`/`emit().key_file()` is the portable baseline,
> with `direnv`/`just`/env strictly optional (§3.2); the dev loop runs the **real**
> compiled provider for **every** family (env/file/machine_id/custom) by sealing
> the dev build under the key that provider resolves on the dev host (§3.1/§3.5),
> so B §3.7 is fixed **universally** and the `init!` site never changes between
> dev and prod; dev-key secret hygiene is stated (§3.7).

## Summary

B reduced the design to its core: invert the key (operator owns `unlock_key`),
derive the locator (delete the config file), and reseal one universal build per
customer (delete the per-customer-build assumption). What B *kept* from the
build-generated lineage is the one mechanism that no longer earns its place once
the key is inverted: **`K_dev`, the baked per-crate debug constant.**

`K_dev` exists to make `cargo run` decrypt with zero wiring. But the *reason* to
bake a key into the binary only ever existed in the build-generated model
(`SPEC_DEVEX.md` §1.7): there the build **generated** the `unlock_key`, so the
developer could not know it, and baking it in was the only way to avoid the awk
chase. **A's inversion removed that reason** — once the operator *owns* the key,
the developer simply *has* a dev key. A, B, and C carried `K_dev` forward by
inertia; none noticed the inversion had made it unnecessary.

The cost of keeping it is not small. A `K_dev`-sealed debug binary is
**self-decrypting** (it carries both the key and the ciphertext), so it must
never be distributed — and that single fact spawns a chain of machinery across
B and C: per-crate derivation to bound the blast radius (B §3.3), a hard
scrub-invariant that `K_dev` bytes be absent from release (B §3.5), a `PROFILE`
gate fused to the seal decision (B §3.4), the documented caveat that debug
success does **not** prove the provider is wired (B §3.7), and C's entire §7
workflow guard built to detect a shipped debug build.

D deletes all of it. The dev loop reads its key from a standard §8 **channel** —
the tooling-agnostic baseline being a **gitignored keyfile** (read by
`FileProvider` at runtime and `emit().key_file()` at build), with an exported env
var / `direnv` as an optional alternative where the developer already uses it —
set up **once**. litmask assumes **no** specific tooling. Consequences:

- **No self-decrypting binary.** A debug build seals the `mask_key` under the
  dev's env key exactly as release seals it under the production key; neither
  embeds the `unlock_key`. A leaked debug binary is **inert without the key** —
  the same property release has. The "never distribute a debug build" caveat,
  the per-crate derivation, the release scrub concern for the constant, and C's
  workflow guard **all disappear** — there is no dangerous artifact to guard.
- **The dev loop runs the real provider path — for every provider.** B §3.7's
  caveat — that `K_dev` rescues a *misconfigured* provider, so a green
  `cargo run` does **not** prove the deployed wiring works — is fixed
  **universally**: the dev build seals under the key the compiled-in provider
  resolves on the dev host (§3.1/§3.5), so the runtime exercises the **actual**
  provider — env, file, machine_id, or custom — and a wiring bug surfaces in
  development, not production. The `init!` site is never changed between dev and
  prod; the only per-family cost is *obtaining* the build-time key value — turnkey
  for `env`/`file`, a one-line fetch for `custom`, and for `machine_id` a one-time
  **seal-to-machine-id binding** that leaves the dev build host-locked (§3.5).
- **The build-time key gate simplifies.** With no `K_dev` fallback, a missing
  build-time key is a hard build error in **every** profile (§3.3), not a
  PROFILE-gated fork between "error in release" and "fall back in debug." The
  `PROFILE`-derived `cfg` now governs **only** the loud diagnostic *strings*
  (§9) — it no longer has to also govern a key.

D additionally takes C's single declarative `init!` site (§2bis) because it
collapses B's build-vs-runtime provider divergence (B §4.4.1's three-site
hazard) at the source for **zero wire-format cost** — but it pointedly does
**not** take C's decl_blob, which spent a new AEAD-sealed wire element to make
provider intent offline-recoverable. D keeps B's honest answer instead:
**alignment is validated by executing the binary** (B §4.4.2), not by an
embedded record.

What D is, in one line: **B, with the last vestige of the build-generated model
removed and one no-cost ergonomic added.** Smallest surface of any variant; one
whole hazard class deleted rather than guarded.

## Audience & Mode Model

- **Developer / operator loop** — iterate, run examples/tests, ship to
  customers. Zero-*per-run* wiring comes from a **one-time** setup (§3): the dev
  key is supplied through a §8 channel (a gitignored keyfile — the portable,
  no-tooling baseline — or an env var), so `cargo run` / `cargo test` both seal
  (at build) and unseal (at run) under it with no per-invocation flags. **A debug
  build is NOT self-decrypting** — it
  embeds no key and is inert without the dev key, exactly like release. (This is
  the central departure from A/B/C, whose debug builds are self-decrypting and
  must never be distributed.)
- **Production** — CI builds release supplying the operator's per-customer key
  from a secret store; the same value reaches the runtime provider out-of-band.
  The attacker holds **the shipped binary only**; the release binary is mute and
  free of litmask-identifying strings (including any stored metadata, which no
  longer exists, §2).

## Foundation (inherited from B, stated for portability)

D inherits **all** of B's Foundation (B.1–B.4) unchanged.

- **D.1 (inverted key, = B.1):** the `unlock_key` is an **operator-supplied
  input**, never a build output. The build seals `mask_key` under the supplied
  key.
- **D.2 (derived locator, = B.2):** the locator is
  `KDF(unlock_key, "litmask-locator-v1")`, recomputed by build / runtime / CLI;
  **no metadata file exists.**
- **D.3 (opaque wrapper, = B.3 / B §2.5):** `nonce(12) ‖ AEAD(version_byte ‖
  mask_key)(33) ‖ tag(16)` = **61 bytes**, no plaintext header; cipher recovered
  by trial-decrypt (AEAD tag = discriminator). Carried verbatim from B §2.5;
  not restated here.
- **D.4 (mute release failure paths, = B.4):** release runtime failures stay
  bare (`panic!()` / `Err(Decryption)`), no identifying text.

**D adds no wire-format element to B's layout.** The binary is
`locator(12) ‖ wrapper(61)` exactly as in B. (This is the deliberate contrast
with C, which adds the decl_blob.)

## 1. Key Ownership Model (inversion, = B §1)

- **1.1**: `litmask_build::emit()` obtains the `unlock_key` from a build-time
  environment variable (default `LITMASK_UNLOCK_KEY`), validates it (base64url,
  exactly 32 bytes, ASCII-whitespace-trimmed per 1.3), and seals the
  freshly-derived `mask_key` into the wrapper under it. The key is **never
  generated** by the build and **never written to any artifact**.
- **1.1.1 (default name matches the runtime — normative)**: The build default,
  `verify` (§5), and the runtime `EnvVarProvider` default MUST all read the same
  variable, `LITMASK_UNLOCK_KEY`. A divergence silently yields runtime
  `NotFound` for every default user and is a spec violation.
- **1.1.2 (the build var is the SEAL side; the runtime provider is the UNSEAL
  side — normative)**: The build-time variable is consumed **only at compile
  time**, by `emit()`, to **seal** the wrapper (and embed `locator =
  KDF(its value)`). The runtime provider supplies the **unseal** key
  *independently*:
  - for **`env`/`file`** the runtime reads the **same channel**, so seal and
    unseal coincide — the build var value *is* the runtime value;
  - for **`machine_id`/`custom`** the runtime **ignores the build var** and
    re-derives (machine-id KDF) or fetches (vault/HSM) the key on its own. Seal
    and unseal are then **two independent computations that MUST yield the
    identical value**, or the wrapper will not open.

  For `machine_id` specifically, one-shot `cargo run` works **iff** the build-time
  `LITMASK_UNLOCK_KEY` was set to `litmask machine-key` derived with the **same
  machine-id and the same salt** as the compiled-in `machine_id("salt")` literal
  (§3.5): build host == run host, and `--salt` == the literal. A mismatch
  (different host, or different salt) seals under one key and unseals under
  another → decrypt failure. This is the mechanism behind the §3.5 host-lock.
- **1.2**: The build-time variable name is configurable to match a renamed
  runtime provider via `litmask_build::Emit::new().key_var("CRYPTIO_KEY").run()`,
  paired with `init!(source: env("CRYPTIO_KEY"))` at runtime (§2bis). A custom
  name must be set on **both** sides.
- **1.3 (input normalization — normative)**: Every key channel (env,
  `--key-file`, `--key-stdin`, the build var) trims surrounding ASCII whitespace
  — notably a trailing newline — before base64url-decoding.
- **1.4**: A malformed build-time key reports the required encoding (base64url),
  length (32 bytes), and points at `litmask keygen` (§6.1) and the §3.2 dev-key
  setup. (Build-time developer input — not subject to the runtime
  message-hygiene rule.)
- **1.5 (build-time key channels — normative)**: `emit()` obtains the build-time
  key from **either** the env var (default `LITMASK_UNLOCK_KEY`, §1.1) **or** a
  keyfile via `litmask_build::Emit::new().key_file(<path>)` — the build-side
  parallel of the runtime `file(<path>)` provider (§2bis.2). Both apply §1.3
  normalization. The keyfile channel lets a consumer keep the key **out of the
  process environment on both sides** (§3.2/§3.7) with no env var at all, and —
  being gitignored — keeps it absent from clean/CI builds (§3.3/§3.6).

## 2. Derived Locator — No Metadata File (= B §2)

Carried verbatim from B §2 / §2.5. In brief: `locator =
KDF(ikm = unlock_key, info = "litmask-locator-v1")`, truncated ≥ 12 bytes;
build embeds `locator ‖ wrapper`; runtime and CLI **recompute** the locator from
the key they hold. No `litmask.config` / `litmask-meta.toml`, no `--config` /
`--meta` flag, no sidecar precedence, no keyless `--locator-only` mode, no
gitignore/attribution concern (there is no file to commit). All locating
subcommands take only `(binary, key)`. The opaque wrapper (B §2.5) removes the
`0x01,0x01` format-version/cipher-id tell; cipher is recovered by trial decrypt,
the format version rides inside the AEAD payload, the derivation-scheme version
lives in the KDF `info` string. See B §2 for the full normative text; D changes
nothing here.

## 2bis. Single Provider Site (declarative `init!`, `init_with!` removed)

D adopts C §2's single-site provider model — and **only** that. It is the one C
move that adds no wire format: it is a macro-API change, not a binary-layout
change. D deliberately does **not** adopt C's decl_blob (§3 of C), so there is no
offline-recoverable record of the declaration; alignment is validated by
execution (§4.4 / B §4.4.2), exactly as in B.

- **2bis.1 (one provider-declaration site — normative)**: A consumer declares
  its key-acquisition intent at **exactly one** place: a single source-level
  `init!` invocation. `build.rs` supplies **key bytes only** (`emit()` reads
  `LITMASK_UNLOCK_KEY`, §1.1) and declares **no** provider. The legacy
  `init_with!` (runtime-constructed provider passed in by value) is **removed**.
  One site cannot diverge from itself — this closes B §4.4.1's build-vs-runtime
  divergence at the source, without an embedded record.
- **2bis.2 (the three declaration forms — normative)**: `init!` takes one of
  three forms, in increasing escape-hatch order:

  ```rust
  litmask::init!()?;                                   // (a) default: env LITMASK_UNLOCK_KEY
  litmask::init!(source: machine_id("cryptio-v1"))?;   // (b) built-in, named
  litmask::init!(custom: VaultProvider::new("…"))?;    // (c) custom, opaque
  ```

  - **(a) `init!()`** — read `LITMASK_UNLOCK_KEY` via the built-in
    `EnvVarProvider`.
  - **(b) `init!(source: <built-in>)`** — `env("NAME")`, `file("path")`, or
    `machine_id("salt")`, constructed by litmask from a **string literal**
    argument. A non-literal argument is a **compile error** directing the author
    to a literal or to form (c). (Consequence: a name/path/salt that must come
    from a `const` or a cfg cannot use form (b) and falls to the form-(c) escape
    hatch — a known ergonomic cliff inherited from C; accepted, as non-literal
    provider config is rare.)
  - **(c) `init!(custom: <expr>)`** — an arbitrary runtime expression evaluating
    to a `KeyProvider` (vault/HSM/etc.). This is the documented escape hatch.
- **2bis.3 (why the declaration cannot live in `build.rs` — normative
  rationale, = C §2.3)**: `build.rs` is a separate compilation unit that runs
  before and apart from the consumer crate; a custom provider's *fetch code*
  (vault round-trip, HSM call) must compile **into the deployed binary** to run
  at startup, so it must originate in consumer **source**, not the build script.
  This is why the single site is the source `init!` and `build.rs` stays
  bytes-only.
- **2bis.4 (init exit-code accuracy — normative, = B §5.6 / C §2.5)**:
  `init!(…)?` with a bare `?` yields Rust's default `Err` termination (exit 1,
  `Debug`-printed variant), **not** a sysexit. At least one example MUST map
  `InitError` to `sysexit_code()` (returning `ExitCode`); docs distinguish the
  `?`→exit-1 path from the explicit-mapping→`sysexits` path.
- **2bis.5 (no decl_blob — normative, scope boundary)**: D embeds **no** record
  of the `init!` declaration in the binary. `verify` and `reseal` cannot read
  the runtime's intended provider (B §4.4.1's blindness stands), and offline
  alignment checking is **not** offered. The authoritative provider-alignment
  test is executing the binary (§4.4 / B §4.4.2). This is the deliberate D-vs-C
  line: D pays for the single-site ergonomic with no wire format and accepts
  B's execute-locally answer rather than C's decl_blob machinery.

## 3. Dev-Loop Zero-Setup (developer-supplied key, any channel — replaces B §3 `K_dev`)

This section **replaces** B §3 in full. There is **no `K_dev`** in D: no baked
constant, no per-crate derivation, no `cfg`-stripping of a key value, no
self-decrypting debug binary. litmask assumes **no specific developer tooling**
— not `direnv`, not `just`, not GitHub. The only requirement is that the dev key
reach **both** build and runtime through a standard §8 channel.

- **3.1 (the dev build seals under the runtime provider's dev-host key —
  normative)**: The dev loop decrypts because the build seals `mask_key` under
  **the very key the compiled-in provider will resolve on the dev host**
  (§1.1/§1.5), and the runtime then unseals by **running that same, real
  provider**. The key is **never embedded in the binary**; a debug build is
  therefore **inert without it**, exactly like a release build (the central
  §-Summary property). Because the runtime provider is **compile-time fixed** and
  resolves its key from the dev host's own channel / credentials / identity, the
  developer can always obtain that value and hand it to the build channel (§3.5)
  — so the dev loop runs the **actual production provider** for **every**
  family, with **no `init!`-site change** between dev and prod and **no
  debug/release behavior fork**. (Machine-deriving providers additionally require
  a one-time **seal-to-machine-id binding** before the binary will run, and the
  result is host-locked — §3.5; the `init!` site still does not change.)
  - **3.1.1 (B §3.7 is fixed for every provider — normative)**: because the dev
    loop executes the **real** provider (not a dev substitute), a misconfigured
    provider **fails in development** for `env`, `file`, `machine_id`, and
    `custom` alike. B §3.7 ("a green run ≠ the deployed wiring works") is fixed
    **universally** — the earlier env/file-only scoping is superseded. The only
    per-family difference is *how the build-time key value is obtained* (§3.5),
    never *whether* the real provider runs.
- **3.2 (portable baseline = a gitignored keyfile; all tooling optional —
  normative)**: The tooling-agnostic baseline, working on **every OS with plain
  cargo and no shell hook**, is a **gitignored keyfile**: write 32 base64url
  bytes to e.g. `.litmask-dev-key`, read it at runtime via
  `init!(source: file(".litmask-dev-key"))` (§2bis.2 form (b)) and at build via
  `litmask_build::Emit::new().key_file(".litmask-dev-key")` (§1.5). No value
  enters the process environment (lower exposure, §3.7). Equivalent but
  **optional** channels, none required by litmask:
  - an **exported env var** (`LITMASK_UNLOCK_KEY`), optionally via a `direnv`
    `.envrc` where the developer already uses direnv — convenient, not assumed.
  - litmask's **own repo** offers a `just dev-key` recipe (generates a gitignored
    keyfile via `keygen`, §6.1, and appends it to `.gitignore`) purely as a
    **repo convenience**; a consumer without `just` writes the file directly.

  Setup is **one-time per clone**; after it the per-run wiring is **zero**,
  matching A/B/C's `cargo run` ergonomics. The trade vs A/B/C is this one-time
  step in exchange for deleting the self-decrypting-binary hazard class.
- **3.3 (missing build-time key is always a hard build error — normative,
  fail-safe, simpler than B §3.4)**: With no `K_dev` fallback in any profile, a
  missing build-time key is a **hard build error in every profile** — debug and
  release alike — naming the channel and pointing at `litmask keygen` (§6.1) and
  the secret store. There is **no PROFILE-gated fork** between "error in release"
  and "fall back in debug" (B §3.4): the gate is unconditional. A **gitignored
  keyfile is absent in a clean/fresh-clone/CI environment**, so — unlike a sticky
  exported env var that persists across a whole shell session — it **cannot
  silently seal an unrelated build**: the error fires and forces an explicit key
  (see §3.6). The `PROFILE`-derived `cfg` survives only to gate diagnostic
  **strings** (§9), never a key.
- **3.4 (litmask's own examples use a committed non-secret dev key — normative)**:
  The repository's `examples/`, scrub tests, and `just test` / `just ci` recipes
  build under a **committed, non-secret** dev key — a checked-in keyfile (or an
  env value exported by the recipe). It is non-secret by design: it protects
  only the example **fixtures**, which are public test strings (§10.1). A fresh
  clone runs `just test` and it works; to `cargo run` an example interactively,
  the contributor uses the committed keyfile (or the §3.2 setup).
  - **3.4.1 (a committed dev key is NOT `K_dev` — normative clarification)**: A
    fixed, even public, dev key is categorically different from `K_dev`. `K_dev`
    was **baked into the binary**, making it self-decrypting; the dev key lives
    in a **channel** (file/env) and is **never embedded**, so the binary it
    produces is inert without it. The dev key being a known constant is
    irrelevant to the binary's extraction-resistance, because the binary does not
    contain it. A **real consumer** (Alice/Cryptio) sets her **own** dev key,
    kept private / gitignored; litmask's public examples use a public one only
    because their fixtures are public.
- **3.5 (obtaining the build-time key per provider — normative)**: The dev build
  must seal under the key the compiled-in provider resolves on the dev host
  (§3.1). The `init!` site is **never** changed for dev; only the build-channel
  *value* differs, and litmask makes the built-ins turnkey:
  - **`env` / `file`**: the build channel **is** the runtime channel — supply the
    dev key once (§3.2); no extra step.
  - **`machine_id("salt")` (and any machine-deriving `custom`)**: the binary is
    **inert until its wrapper is sealed to the dev host's machine ID** — machine
    binding is an explicit seal step, **not** a value the channel supplies for
    free. Two ways: **(i)** build directly under the locally-derived machine-key —
    `LITMASK_UNLOCK_KEY=$(litmask machine-key --machine-id "$(litmask
    show-machine-id)" --salt salt)` (have `just dev-key` derive it into the
    gitignored keyfile once, §3.2), after which plain `cargo run` on that host
    seals-then-runs; or **(ii)** the deployment-faithful path — build under the
    dev key, then `litmask reseal --to-machine-id "$(litmask show-machine-id)"
    --salt salt` **before** running. Either way the runtime `MachineIdProvider`
    recomputes the same machine-key on that host and unseals → **the real provider
    runs**. Consequence: a machine-bound dev build is **host-locked** — runnable
    only on the machine it was sealed for; a different dev host (or CI runner) must
    re-derive and re-seal. This binding step (and the host-lock) is the price
    machine providers pay that `env`/`file` do not.
  - **`custom` (vault/HSM/…)**: the developer fetches the key via the provider's
    own credential path — which they hold, being the app's author — and supplies
    it to the build channel: `LITMASK_UNLOCK_KEY=$(my-vault-fetch …)`. `build.rs`
    cannot run the custom provider (its fetch code compiles into the consumer
    binary, not the build script, §2bis.3), so this one resolution is the
    developer's; the runtime then exercises the real provider.

  In every case the **runtime runs the actual provider** (§3.1.1), and after the
  one-time §3.2 step the per-run wiring stays **zero**. (Replaces B §3.8; no
  `K_dev` `NotFound`-rescue subtlety arises — there is no `K_dev`.)
- **3.6 (the ambient-key hazard — local release builds are not shippable —
  normative, fail-safe)**: Build-time key acquisition is **ambient**: whatever
  channel holds the dev key, a build run in that tree/shell will seal under it.
  Therefore a **local release build is NOT shippable** — it may seal `mask_key`
  under the **dev key** instead of `build_key`. The **shippable universal build
  MUST be produced in a clean environment** (dev keyfile absent / env unset) with
  `build_key` supplied explicitly via a §8 channel — i.e. CI from a fresh clone.
  **Corollary (verify):** `verify --deny` (§5.7) proves lock-out **only against
  the key the universal build actually used**; if a dev key could have sealed the
  artifact, the `build_key` deny-check passes **vacuously** and gives false
  confidence. The gitignored-keyfile channel (§3.2) narrows the blast radius to
  *local dev-tree* release builds, since the file is absent in clean CI; an
  exported env var does not (the export persists). This is the cost of an
  always-present dev key, and the reason the clean-env release rule is normative.
- **3.7 (dev-key secret hygiene — normative)**: The dev key is a **real secret**
  (it decrypts the dev build's fixtures, and more if reused). An **env-var** dev
  key is exposed in the process environment — `/proc/<pid>/environ`, crash dumps,
  child-process inheritance, CI logs — and MUST receive §8 hygiene. A
  **gitignored keyfile** keeps it out of the process environment and is the
  lower-exposure default (§3.2). Setup MUST write the key **gitignored** and
  **never commit it**, the sole exception being litmask's own public-fixture
  example key (§3.4). This is an honest trade vs `K_dev`, which was non-secret
  and had none of these exposure channels: D deletes a baked-binary hazard and
  accepts a smaller, file-channel-mitigated dev-secret-handling burden.

## 4. Deployment Shape (reseal-default, = B §4)

Carried verbatim from B §4, including §4.1 universal-build-plus-per-customer-
reseal, §4.1.1/§4.1.2 the dedicated long-lived `build_key`, §4.2/§4.2.1 the
reseal security property and `build_key` plaintext-equivalence, §4.3 per-customer
builds as the opt-in for differing content / leak attribution, §4.4 machine-id
deployment, §4.4.1 provider-alignment is unverifiable offline, and §4.4.2
validate-by-execution. D changes nothing here.

- **4.4 (provider alignment — D restatement)**: As B §4.4.1/§4.4.2: the
  compiled-in provider is chosen in runtime `init!` code and **no offline check
  observes it** (D adds no decl_blob, §2bis.5, so this is identical to B). The
  authoritative alignment proof is **executing the binary** with the key env
  cleared (B §4.4.2): reseal a throwaway copy to the local machine-id, run it
  with `LITMASK_UNLOCK_KEY` cleared, and confirm self-decrypt; the provider is
  compile-time fixed, so one such run proves alignment for every subsequent
  reseal of the same binary.
- **4.4.3 (dev loop covers every provider; only the offline CLI stays blind — D
  note)**: With §3.1/§3.5 the **dev loop exercises the real provider for every
  family** (env/file/machine_id/custom), since the dev build seals under the key
  that provider resolves on the dev host. The prior "machine_id/custom is
  thin-coverage" concern is therefore closed on the *execution* side. What remains
  blind is the **offline CLI** (`verify`/`reseal`): with no decl_blob (§2bis.5) it
  still cannot observe the compiled-in provider — exactly as in B — so the
  authoritative *offline* alignment proof stays execute-locally (§4.4.2). Both the
  dev loop and execute-locally now run the real provider; the only thing that
  never sees it is a static, non-executing inspection. This is B's accepted
  stance, not a D regression.

## 5. Coherence & Failure Diagnostics (= B §5)

Carried verbatim from B §5: `verify` is keyed decrypt-success by default; **four
outcomes** (coherent / locator-absent / key-fails / indeterminate) over four
distinct `sysexits` codes (`EX_OK` / `EX_NOINPUT` / `EX_DATAERR` /
`EX_UNAVAILABLE`); debug-only provider-source naming via `source_hint()`
(default `None`, non-breaking); verify-against-the-runtime-key (§5.4); machine-id
off-box returns *indeterminate* without `--machine-id`/`--salt` (§5.5); the
`--deny` post-reseal lock-out check (§5.7) proving `build_key` cannot open a
shipped artifact. The F7 false-pass is **unreachable by construction** (keyed
locator needs the key; there is no keyless mode). D changes nothing here.

- **5.3 (debug provider-source naming — D note)**: Sourced from the provider's
  own `source_hint()`, **not** from any embedded declaration (D has no
  decl_blob, §2bis.5). Release stays mute. (This is C §4.5's conclusion reached
  without C's machinery — D never had a decl_blob to be tempted to read.)
- **5.7 (`--deny` is only as good as the build key — D note, fold of D-1)**: per
  §3.6, the `build_key` lock-out proves nothing if the universal build was sealed
  under an **ambient dev key** rather than `build_key` — the deny-check then
  passes vacuously. The clean-env release rule (§3.6) is what makes `--deny`
  meaningful: CI MUST produce the shippable build with **no dev key present**.

## 6. Tooling / CLI Surface (= B §6)

The distributable CLI is **{`verify`, `reseal`, `keygen`, `machine-key`,
`show-machine-id`}** — B's surface exactly. D does **not** adopt C's `derive`
consolidation or C's per-customer `seed` derivation (those pull key-management
into litmask, §-Out-of-Scope). The CLI never compiles and has no `run` verb;
every subcommand is configless (`(binary, key)` only).

- **6.1 (`keygen`)**: Mints a fresh 32-byte `unlock_key` (CSPRNG, base64url
  no-padding) and prints **only** the key to stdout (§8.3). Pure generator —
  touches no binary. Used both for per-customer provisioning
  (`litmask keygen | gh secret set CRYPTIO_KEY_BOB`) and to back `just dev-key`
  (§3.2). Distinct keys per run by default; cannot *enforce* distinctness but
  makes it the lazy path (recovers cross-customer isolation at provisioning).
- **6.2 (`reseal`)**: `litmask reseal <binary> --from <keysrc> --to <keysrc>
  [-o <out>]` re-keys the wrapper and its derived locator; `mask_key` and blobs
  unchanged. Machine-id target: `reseal … --to-machine-id <id> --salt <s>`
  (subsumes legacy `bind`). Because `reseal` cannot see the compiled provider
  (§4.4 / B §4.4.1), `--to-machine-id` emits a non-secret notice that the
  artifact self-decrypts on the bound host **only if** built with a
  machine-id-aware provider, and points at execute-locally (§4.4.2). (D does
  **not** add C §5.2's decl-driven refusal — it has no decl to read.)
- **6.3 (`machine-key`)**: Derives the machine key off-box using the same KDF as
  the runtime `MachineIdProvider`, printing it per §8.3. Feeds reseal's
  `--to-machine-id` path and lets an operator pre-derive a target's key. (Kept
  as a top-level verb — D makes no `derive` consolidation.)
- **6.4 (`show-machine-id`)**: Prints this host's machine ID — the exact bytes
  `MachineIdProvider` feeds into derivation. Non-secret identifier, exempt from
  §8.

## 7. Seed & Reproducibility (= B §7)

Carried verbatim from B §7: decrypt-reproducibility is **free** (owned key — F3
cannot occur); per-site nonces are `KDF(seed ‖ site-id ‖ plaintext)`
(structural nonce-reuse safety — a pinned seed cannot reuse a nonce against
edited plaintext, B §7.2); the seed is **never persisted to disk and never
written to any build-log line** (S1 gone structurally — no `cargo:warning`
carrying the seed, no `litmask-seed.*` file, B §7.3); bit-identical
reproducibility is opt-in via `LITMASK_RNG_SEED` (B §7.4), a rare need stored
`unlock_key`-grade when pinned. **Observed (`litmask-build/src/lib.rs:258`)**: a
malformed pinned seed already hard-fails the build (panic, exit 101) — correct
direction — but the message omits the 32-byte length and a `litmask keygen`
pointer; closing that is implementation work. D adds **no** per-customer
seed-derivation model (that is C §6.7, dropped — see Out of Scope).

## 8. Secret Input Channels (= B §8)

Carried verbatim from B §8: any subcommand consuming a secret key (`verify`,
`reseal --from/--to`) accepts it **only** via non-argv channels — the default
`LITMASK_UNLOCK_KEY` env, an explicit `--key-env <NAME>` (per role: `--from-env`,
`--to-env`, `--deny-env`), `--key-file`, or `--key-stdin`. **There is no `--key
<value>` flag** (argv lands in the process table, readable by every user via
`ps`, and is unreliably masked in CI logs). Secret-emitting verbs (`keygen`,
`machine-key`) print **only** the value to stdout. Build-time injection reads
`LITMASK_UNLOCK_KEY` from the environment at the cargo boundary, which litmask
facilitates but cannot enforce; documentation states the discipline.

## 9. Diagnostics Gating (security-correctness — simpler than B §9)

- **9.1 (strings only — normative)**: Debug-only loud diagnostics (§5.3
  identifying strings) are gated on the **actual build profile** via a
  `PROFILE`-derived `cfg` plumbed from a runtime-crate `build.rs` — not on
  `debug_assertions` (user-tunable per profile, which would leak strings into
  release). The gate is automatic and fail-safe.
- **9.2 (no key to gate — the D simplification)**: Unlike B §9.2, there is **no
  `K_dev` value, derivation, or fallback branch** for this `cfg` to also strip.
  The gate governs **strings, full stop.** The key never reaches the binary
  except as the operator-sealed wrapper (§1.1, §3.1), so there is no
  litmask-specific key constant that could survive into release and become a
  distinguishing signature — B §3.5's scrub-invariant concern for `K_dev` bytes
  **does not arise in D**. This is the cleanest expression of the security
  boundary across all variants: the only thing the profile gate touches is
  human-readable text.

## 10. Examples, Fixtures & Documentation (= B §10, adjusted for §3)

- **10.1 (single fixtures source, = B §10.1)**: Each example declares its masked
  fixtures in one source of truth the scrub test consumes. The fixtures are
  public test strings, which is why the example dev key (§3.4) can be a committed
  non-secret.
- **10.2 (run docs)**: Every example header documents how to **run** it: after
  the one-time §3.2 setup (or `direnv allow`), plain `cargo run` works with the
  key supplied from the environment — no awk, no metadata file, no baked
  constant, and no "this binary is self-decrypting" warning (it is not). For
  verifying the *release* artifact, supply the owned key over a §8 channel.
- **10.3 (dev-vs-release split)**: Documentation states why release is mute; that
  **debug and release behave identically with respect to key handling** — both
  seal under an operator-supplied key, neither embeds it, neither is
  self-decrypting (the standout simplification vs A/B/C); that a missing
  build-time key **fails at build time in every profile** (§3.3); and the §2bis.4
  init exit-code accuracy.
- **10.4 (declarative `init!` shown)**: At least one example uses each of the
  three §2bis.2 forms — `init!()`, `init!(source: machine_id(…))`,
  `init!(custom: …)` — and documents that offline alignment is **not** offered
  (D has no decl_blob); the authoritative check is executing the binary
  (§4.4.2). Documentation shows that `init_with!` **no longer exists** and how to
  port each old call.
- **10.5 (per-customer pipeline end-to-end, = B §10.5)**: `keygen` per customer
  into the secret store → one universal `cargo build --release` under
  `build_key` → `reseal` per customer → `verify` each with `--deny-env
  BUILD_KEY` (keyed coherence + build-key lock-out, §5.7) → inject each customer
  key into its runtime provider. No metadata file travels; no debug build can be
  confused for a shippable one.

## Architecture notes

**Removing `K_dev` is the whole of D's novelty, and it is a deletion.** Every
other section is B (often verbatim) or C's single-`init!` (a no-wire-format
ergonomic). The insight is that `K_dev` is a vestige of the build-generated
model: baking a key into the binary was only ever necessary when the build
*generated* the key and the developer could not otherwise know it. A's inversion
made the developer the key's *owner*, at which point "the dev sets their own dev
key in the environment" is available — and an environment key, unlike a baked
constant, **never enters the binary**, so the debug build stops being
self-decrypting. A/B/C kept `K_dev` past the point where its premise held.

**The deletion cascades.** No baked key ⇒ no self-decrypting debug binary ⇒ no
per-crate derivation to bound its blast radius, no scrub-invariant that the
constant be absent from release, no `PROFILE` gate fused to a seal decision, no
"debug success ≠ wired" caveat, and no workflow guard (C §7) to detect a shipped
debug build. The profile `cfg` narrows to its essential job: gating
human-readable strings (§9). The build-time key gate simplifies to "required in
every profile" (§3.3). One conceptual subtraction removes machinery from five
sections.

**The price is one-time setup, paid once per clone.** D trades A/B/C's
literally-zero-wiring for a one-time step — at minimum dropping a gitignored
keyfile in place (no tooling required); optionally `direnv`/`just` where already
used. For a tool whose audience is developers deliberately hiding secrets, this
is a trivial ask, and it buys a dev loop that exercises the **real** provider
path for **every** provider family — so wiring bugs surface in development, not
production (fixing B §3.7 universally, §3.1.1). The dev build seals under the key
the compiled-in provider resolves on the dev host (§3.5) rather than substituting
a different provider, so the `init!` site is identical in dev and prod.

**Two costs D owns honestly.** (1) The dev key is always present in the dev
channel, so a *local* release build can seal under it instead of `build_key`
(§3.6) — D mandates that the **shippable** universal build be produced in a clean
env (no dev key) and notes a gitignored keyfile, being absent from clean CI,
contains the blast radius better than a sticky env var. (2) The dev key is a real
secret needing §8 hygiene (§3.7), unlike the non-secret `K_dev`; the keyfile
channel keeps it out of the process environment. Both are the cost of deleting
the self-decrypting-binary hazard class — a trade D considers worth it.

**Single `init!` without the decl_blob.** D takes C's one-provider-site
ergonomic (collapsing build-vs-runtime divergence, B §4.4.1) because it costs no
wire format, and rejects C's decl_blob because making provider intent
offline-recoverable spent a new AEAD-sealed wire element on a real-but-rare
problem B already answered honestly (execute the binary, B §4.4.2). The
single-site change is pure macro API; the binary layout stays B's `locator ‖
wrapper`.

**What D refuses from C.** The decl_blob, the `derive`-verb consolidation, the
per-customer `seed = KDF(master_seed, customer-id)` model, the attribution-ledger
shape, and the §7 workflow guard. The seed/derive/ledger machinery pulls key
**management** (provisioning, derivation-from-master, attribution) into litmask;
D holds the line that litmask is a **masking primitive + thin verification tool**
and key management is the operator's existing infrastructure (vault, gh secrets,
KMS), composed with litmask's minimal seam (seal / unseal / re-key / verify).

**Secret hygiene.** The owned `unlock_key` and `build_key` travel via
env/file/stdin only (§8), never argv or logs. **No binary — debug or release —
embeds the `unlock_key`**; both embed only the operator-sealed wrapper, so
neither is self-decrypting (the D departure from A/B/C). There is no metadata
file and the seed is never persisted or logged (§7). The build host holding all
customers' keys (and `build_key`) is an accepted, documented trust boundary
(THREAT_MODEL.md); `build_key` is plaintext-equivalent (B §4.2.1).

**Testing strategy.** Inherit B's matrix (reseal compartmentalization; four
`verify` outcomes/exit codes; no-metadata-file decrypt; opaque-wrapper
trial-decrypt + scrub-clean of the `0x01,0x01` tell; release no-key build
failure; seed never persisted/logged incl. cached rebuild; pinned-seed
byte-identical blobs + edit-changes-nonce; machine-id off-box
indeterminate/with-flags; `keygen`/`machine-key` encoding + derivation
reproduction; `--deny` pass/fail; execute-locally provider proof). **Change for
D:**
- **assert NO key is embedded in either profile** — `strings`/scrub finds no
  `unlock_key` and no `K_dev`-style constant in **debug** as well as release
  (D's central claim); assert a **debug** binary built under one env key
  **fails to decrypt** when run with a *different* key or with the key cleared
  (it is inert without the key — NOT self-decrypting), the direct contrast with
  A/B/C's `K_dev` `NotFound`-rescue test;
- assert a missing `LITMASK_UNLOCK_KEY` at build time **fails the build in both
  debug and release** (§3.3 — no profile fork);
- assert the `PROFILE`-derived `cfg` strips only diagnostic **strings** and that
  there is **no key value or fallback branch** under it (§9.2);
- assert `init_with!` is **removed** (the macro no longer compiles) and each
  §2bis.2 form constructs the right provider; assert `build.rs` declares no
  provider (bytes-only, §2bis.1);
- assert there is **no decl_blob** in the binary layout (§2bis.5) — the embedded
  region is exactly `locator ‖ wrapper`, and `verify`/`reseal` offer **no**
  offline alignment check (execute-locally is the authority, §4.4);
- assert the example/test suite builds under the committed non-secret dev key
  (§3.4) and that a fresh `just test` succeeds with no per-developer setup;
- **ambient-key guard (D-1)**: assert a release build with the dev key present in
  the channel seals under the **dev key**, while a **clean-env** release build
  (dev keyfile absent / env unset) with only `build_key` seals under `build_key`;
  assert `verify --deny-env BUILD_KEY` **fails to lock out** a dev-key-sealed
  artifact (regression guard for the vacuous deny-pass, §3.6/§5.7);
- assert a **gitignored keyfile is absent after a fresh clone** so a clean build
  **hard-errors** (§3.3) rather than sealing silently;
- assert `Emit::new().key_file(path)` (build, §1.5) and runtime `file(path)`
  round-trip and that no value reaches the process environment via that channel;
- **provider-agnostic dev loop (§3.1/§3.5)**: assert a dev build whose `init!` is
  `machine_id(salt)`, sealed-to-machine-id under `machine-key(local-id, salt)`
  (build-under-machine-key **or** `reseal --to-machine-id`), decrypts at runtime
  via the **real** `MachineIdProvider` on that host, and is **host-locked** (the
  same binary fails under a different machine ID); assert a `custom`-provider dev
  build sealed under the provider-fetched key decrypts via the **real** custom
  provider; assert **no `init!`-site change** is needed between
  dev and prod and that a *misconfigured* provider fails the dev run (B §3.7
  fixed for every family, not just env/file).
Reuse the `example_scrub` harness; one fixtures source per example (§10.1).

## Out of Scope

Inherits B's Out-of-Scope set, plus the C machinery D deliberately declines:

- A CLI verb that compiles a target, and a `litmask run` exec/key-wiring verb
  (run-loop convenience is the §3.2 key channel + cargo; building is cargo's).
- A managed seed/key **secret store**, or solving the build-host-holds-all-keys
  trust boundary — documented in THREAT_MODEL.md, accepted here.
- Build-emitted provider **selection** / metadata, and **C's decl_blob** (an
  offline-recoverable record of provider intent): rejected — provider intent is
  validated by execution (§4.4 / B §4.4.2), not by an embedded record. D pays no
  wire-format cost for alignment.
- **C's `derive`-verb consolidation and per-customer seed-derivation model**
  (`derive seed --from-master`, `derive mask-key`): key-management belongs to the
  operator's infrastructure, not litmask. `keygen` + `machine-key` + the
  operator's secret store cover provisioning; D adds no derivation surface.
- **C's debug-never-ship workflow guard (§7)**: there is no self-decrypting debug
  build to guard against in D, so the guard has nothing to detect. (Debug builds
  remain non-shippable for the **ordinary** reasons — unoptimized, and they carry
  the loud §9 diagnostic strings — but that is standard cargo `--release`
  discipline, not a litmask-specific hazard, so D adds no guard for it.)
- A baked debug key (**`K_dev`**) in any profile: removed entirely (§3); replaced
  by a developer-environment key.
- Changing the wrapper crypto, `mask_key` derivation, or release-runtime failure
  paths (D inherits B's wire format unchanged and adds nothing to it).
- Enforcing cross-customer key distinctness in the binary (provisioning, B §6.1).

## Decision delta vs `SPEC_DEVEX_B.md` and `SPEC_DEVEX_C.md`

| Axis | **B (clean slate)** | **C (declarative + layered)** | **D (B minus K_dev)** |
|---|---|---|---|
| `unlock_key` / locator / wrapper | operator input / derived / opaque | inherited from B | **inherited from B, unchanged** |
| Deployment shape | one build + per-customer reseal | inherited from B | **inherited from B, unchanged** |
| Dev-loop zero-wiring | baked per-crate `K_dev` constant | `K_dev` (from B) | **developer-supplied key via any §8 channel (gitignored keyfile baseline; env/direnv optional), one-time setup; NO baked key** |
| Debug binary | **self-decrypting** (carries `K_dev`) — must never ship | self-decrypting (from B) | **inert without the key — same as release; safe to mishandle** |
| Self-decrypting-binary machinery | per-crate derivation + scrub MUST + PROFILE gate + §3.7 caveat | all of B's + §7 workflow guard | **all deleted — no such binary exists** |
| Build-time key gate | PROFILE fork: error in release, `K_dev` in debug | same as B | **hard error in every profile (no fork)** |
| `PROFILE` `cfg` governs | strings **and** the `K_dev` key/branch | same as B | **strings only** |
| Dev loop exercises real provider | no (`K_dev` rescues `NotFound`, B §3.7) | no (from B) | **yes — for EVERY provider (env/file/machine_id/custom); dev build seals under the provider's dev-host key (§3.1/§3.5); B §3.7 fixed universally** |
| Provider site | `init_with!` + `emit` + reseal target (3) | one source `init!`; build bytes-only (1) | **one source `init!`; build bytes-only (1)** |
| Provider intent offline | invisible (execute-locally only) | recoverable via decl_blob (built-ins) | **invisible (execute-locally only) — NO decl_blob** |
| Binary layout | `locator ‖ wrapper` | `locator ‖ wrapper ‖ decl_blob` | **`locator ‖ wrapper` (no wire-format add)** |
| CLI surface | verify, reseal, keygen, machine-key, show-machine-id | verify, reseal, keygen, **derive**, show-machine-id | **verify, reseal, keygen, machine-key, show-machine-id (= B)** |
| Per-customer seed / ledger | per-customer build under fresh seed; ledger out of scope | `derive seed --from-master`; lightweight ledger shape | **none — key-management is the operator's infra** |
| Spec size / surface | smallest of A/B/C | largest (decl_blob + derive + layers + guard) | **smallest overall — a net deletion from B** |
| One-time dev setup | none | none | **drop a gitignored keyfile (any OS, no tooling); env/direnv/just optional** |
| Biggest risk | bigger break from current code (opaque wrapper + no config) | over-built; value ∝ built-in usage | **ambient dev key can seal a *local* release build → clean-env release rule (§3.6); plus one-time dev setup** |
