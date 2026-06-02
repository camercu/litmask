# litmask Developer-Experience — Specification (Variant B: Clean Slate)

> **Status:** design variant, refine phase. Third option beside
> `docs/SPEC_DEVEX.md` (build-generated key) and `docs/SPEC_DEVEX_A.md`
> (operator-owned key). B starts from A's inversion and goes further:
> it **deletes the metadata file** (the root of most friction) by deriving
> the locator from the owned key, and **rethinks the deployment shape**
> (one build + per-customer reseal, not N per-customer builds). Drafted for
> a deliberate side-by-side decision. If adopted, B replaces both. The
> project is **pre-release**, so B lands as a direct edit with no migration
> burden.

## Summary

A (`SPEC_DEVEX_A.md`) correctly identifies that every friction point is a
secret crossing build → human → runtime by hand, and removes it by making the
`unlock_key` an operator-owned **input**. B keeps that and asks the next
question: *why is there a sidecar file at all?* Tracing the friction —
F2 (awk it), F3 (it desyncs from the binary), F4 (it clobbers / needs
sidecars), F7 (`inspect` trusts it over the binary), S1 (the seed leaks near
it) — **every pain is the `litmask.config` file.** A demotes it to non-secret
metadata; B **eliminates it.**

Two clean-slate moves do this:

1. **Derived locator → no metadata file (§2).** The locator exists only so the
   CLI can find the wrapper in a binary without embedding a fixed magic header
   (which would be a litmask *signature*, breaking the scrub invariant). Once the
   operator owns the key, the locator can be **derived** from it
   (`locator = KDF(unlock_key, "litmask-locator")`) instead of stored. The CLI
   and runtime recompute it; an attacker without the key sees only
   random-looking bytes (the scrub property is preserved). With nothing left to
   store, `litmask.config`/`litmask-meta.toml`, the `--config`/`--meta` flag, the
   sidecar-precedence rules, and the keyless `--locator-only` check **all
   disappear** — `verify` and `reseal` take `(binary, key)` and nothing else.

2. **Reseal-default deployment (§4).** Both prior specs assume *unique build per
   customer*. B observes that when the masked content is the **same** across
   customers (the common case — same app, same secrets), a unique per-customer
   `mask_key` buys almost nothing: the plaintext is identical, so leaking one
   customer's `mask_key` reveals strings every other customer's binary already
   contains. The property that actually matters — **a stolen binary is inert
   without its key, and one customer's key won't open another's binary** — is
   delivered by **resealing one universal build's wrapper under a per-customer
   `unlock_key`** at 1/N the build cost. Per-customer *builds* (unique blobs) are
   then reserved for the two cases that genuinely need them: **per-customer
   differing content**, and **leak attribution / watermarking**.

What this collapses, by removal:

- **F1 (opaque death):** dev loop self-decrypts via a debug constant (§3); a
  release build with no key is a **build-time error** (§3.4), not a runtime
  panic. The remaining release-runtime miss is diagnosed (§5.3), not opaque.
- **F2 / F6 (awk / key-wire):** gone — the operator owns the key; nothing is
  extracted, and there is no metadata file to read.
- **F3 (silent rotation):** gone — an owned key never rotates under the
  developer; rebuild freely (§7.1).
- **F4 (config clobber / sidecars):** gone — **there is no config file** (§2).
- **F5 (hand-rolled seed/key):** `keygen` mints keys (§6.1); the seed demotes to
  the rare bit-repro case and is never persisted or logged (§7).
- **F7 (inspect false-pass):** unreachable — `verify` is keyed decrypt-success
  by construction (§5.1); there is no locator-only mode to pass weakly.
- **S1 (seed in logs):** gone — the build neither generates the `unlock_key` nor
  persists/logs the seed (§7.3).

**What is preserved unchanged.** The masking promise (plaintext absent from the
binary), the AEAD wrapper crypto and `mask_key` derivation, the `KeyProvider`
trait and `mask!*` macro surface, the zero-identifying-strings release scrub,
and the locator-is-not-a-magic-header discipline (now satisfied by derivation
rather than out-of-band storage).

**The governing tradeoff (stated, not hidden).** B gives up *independence by
construction* (per-build-unique `unlock_key`) exactly as A does, recovering
distinctness at the provisioning layer (`keygen` per customer, §6.1). It
additionally gives up *unique-`mask_key`-per-customer by default* in favor of
reseal — accepting a **shared `mask_key` across customers of one universal
build** (§4.2). This is defensible precisely because, for identical masked
content, the shared `mask_key` exposes nothing a per-customer build would have
hidden (the plaintext is the same), while reseal delivers the compartmentalization
that matters at a fraction of the cost. Operators who need unique blobs
(differing content or leak attribution) opt into per-customer builds (§4.3),
which fall out of the same machinery.

## Audience & Mode Model

- **Developer / operator loop** — iterate, run examples/tests, ship to
  customers. Debug builds seal under a per-crate **non-secret** dev constant
  `K_dev` (§3), so `cargo run` / `cargo test` decrypt with zero wiring.
  Consequence: a **debug build is self-decrypting and must never be
  distributed** — `K_dev` is a public constant, not a baked per-build secret, so
  no key-baking machinery is required.
- **Production** — CI builds release supplying the operator's key from a secret
  store; the same value reaches the runtime provider out-of-band. The attacker
  holds **the shipped binary only**; the release binary is mute and free of
  litmask-identifying strings (including any stored metadata, which no longer
  exists).

## Foundation (what changes vs the build-generated design)

- **B.1 (inverted, as A):** the `unlock_key` is an **operator-supplied input**,
  not a build output. The build seals `mask_key` under the supplied key.
- **B.2 (new — derived locator):** the locator is **not stored**; it is
  `KDF(unlock_key, domain)` recomputed by the build (to place it), the runtime
  (to find the wrapper), and the CLI (to scan). No metadata file exists.
- **B.3 (crypto core unchanged; wrapper made opaque):** a per-build seed
  deterministically derives `mask_key` and per-site nonces (§7.2); the AEAD
  primitive, `mask_key` derivation, blob format, and `KeyProvider` trait are
  untouched. The **wrapper wire format changes**: B removes the two plaintext
  header bytes (format-version, cipher-id) so the whole wrapper is
  indistinguishable from random (§2.5). A B-built binary is therefore **not
  byte-compatible** with the current self-describing wrapper — acceptable
  because the project is pre-release.
- **B.4 (unchanged failure hygiene):** release runtime failure paths stay mute
  (bare `panic!()` / `Err(Decryption)`, no identifying text).

## 1. Key Ownership Model (inversion)

- **1.1**: `litmask_build::emit()` obtains the `unlock_key` from a build-time
  environment variable (default `LITMASK_UNLOCK_KEY`), validates it (base64url,
  exactly 32 bytes, ASCII-whitespace-trimmed per 1.3), and seals the
  freshly-derived `mask_key` into the wrapper under it. The key is **never
  generated** by the build and **never written to any artifact**.
- **1.1.1 (default name matches the runtime — normative)**: The build default,
  `verify` (§5), and the runtime `EnvVarProvider` default MUST all read the same
  variable, `LITMASK_UNLOCK_KEY`. A divergence silently yields runtime `NotFound`
  for every default user and is a spec violation.
- **1.2**: The build-time variable name is configurable to match a renamed
  runtime provider via `litmask_build::Emit::new().key_var("CRYPTIO_KEY").run()`,
  paired with `EnvVarProvider::new("CRYPTIO_KEY")` at runtime. A custom name must
  be set on **both** sides.
- **1.3 (input normalization — normative)**: Every key channel (env, `--key-file`,
  `--key-stdin`, the build var) trims surrounding ASCII whitespace — notably a
  trailing newline — before base64url-decoding.
- **1.4**: A malformed build-time key reports the required encoding (base64url),
  length (32 bytes), and points at `litmask keygen` (§6.1). (Build-time developer
  input — not subject to the runtime message-hygiene rule.)

## 2. Derived Locator — No Metadata File

- **2.1 (derived locator — normative)**: The locator is
  `locator = KDF(ikm = unlock_key, info = "litmask-locator-v1")`, truncated to a
  fixed width ≥ 12 bytes, using the BLAKE3-based KDF already in the workspace.
  The build embeds `locator ‖ wrapper` in the binary; the runtime and CLI
  **recompute** the locator from the key they hold and scan for it. The locator
  is **never stored in any file.**
- **2.2 (scrub invariant preserved — normative)**: Because the locator is keyed
  KDF output **and** the wrapper carries no plaintext header bytes (§2.5), an
  attacker without the `unlock_key` sees the embedded region (locator ‖ wrapper,
  ≈ 73 bytes) as **uniformly high-entropy data** — no fixed magic header, and,
  unlike today's wrapper, not even the low-entropy `0x01,0x01`
  format-version/cipher-id tell. The binary carries **no litmask-identifying
  constant**. A party that holds the key (the legitimate runtime, the build
  host) can recompute the locator and decrypt the wrapper; that party can
  already read the plaintext, so locating it reveals nothing new.
- **2.3 (no config/metadata file — normative)**: `litmask.config` /
  `litmask-meta.toml` and the `--config` / `--meta` flag **do not exist** under
  this variant. The wrapper length is a fixed function of the known
  cipher/schema set (§2.5), recomputed by tooling, not stored. All locating
  subcommands take only `(binary, key)`; there is no file to resolve, no
  precedence rule, no sidecar, and no gitignore/attribution concern (there is no
  file to commit). This eliminates F2/F3/F4/F7-config and the metadata half of
  S1 by construction.
- **2.4 (collision handling)**: A 12-byte keyed needle makes a false-positive
  scan match astronomically unlikely (~2⁻⁹⁶). `verify` retains an *ambiguous*
  outcome (multiple differing matches) for robustness, but it is not expected to
  occur in practice.

## 2.5 Opaque Wrapper — No Plaintext Header Bytes (normative)

The current wrapper self-describes its decrypt format in the clear: byte 0 is
`FormatVersion`, byte 1 is `CipherId` (both `0x01` today). Those two bytes are a
low-entropy, litmask-specific tell — a constant an analyst can scan for even
without the key. B removes them; nothing in the wrapper is plaintext except the
nonce, which is itself random.

- **2.5.1 (layout)**: A B wrapper is `nonce ‖ AEAD(version_byte ‖ mask_key) ‖
  tag` — i.e. `nonce(12) ‖ ciphertext(33) ‖ tag(16)` = **61 bytes**. There is no
  plaintext version byte and no plaintext cipher-id byte. The nonce stays
  plaintext (it is a decrypt input and cannot be sealed by the key it helps
  recover) but is high-entropy random, indistinguishable from the surrounding
  bytes.
- **2.5.2 (cipher by trial decryption — normative)**: The cipher is **not**
  signalled in the clear. The reader trial-decrypts over the known cipher set
  (`ChaCha20Poly1305`, `Aes256Gcm`); the AEAD **tag is the discriminator and the
  integrity proof in one** — whichever cipher's tag verifies is the cipher. A
  separate checksum MUST NOT be added (redundant, and a potential tell). A
  cross-cipher false-positive tag verification has probability ≈ 2⁻¹²⁸ and is
  treated as impossible.
- **2.5.3 (version inside the authenticated payload — normative)**: The
  format-version byte is the **first byte of the AEAD plaintext** (`version_byte
  ‖ mask_key`), read only after a tag-verified decrypt. The tag authenticates
  it, so it cannot be flipped without detection. The format is thus
  self-describing *after* decrypt, never before — a property only the
  key-holder can observe.
- **2.5.4 (derivation-scheme version in the KDF info string — normative)**: The
  **locator-derivation** scheme is versioned out-of-band in the KDF `info`
  string (`"litmask-locator-v1"`, §2.1), not by any embedded constant. A scheme
  bump (`-v2`) is resolved by the reader trying known scheme-versions in
  sequence; the embedded locator bytes stay fully keyed. This is distinct from
  the wrapper *format* version of 2.5.3 (which governs payload interpretation,
  not the scan needle).
- **2.5.5 (wrapper length at scan time — normative)**: Having found the locator
  (§2.1), the reader recovers the wrapper as the next L bytes, where L is fixed
  by the (cipher, payload-schema) candidate. For a single known schema L is a
  constant (61). If a future schema changes L, the reader enumerates known
  (cipher, schema) candidates — slice, trial-decrypt, check tag — a **bounded,
  key-holder-only** loop (today: `|ciphers| × |schemas|` = 2 × 1). No length is
  stored anywhere.
- **2.5.6 (diagnostics — strictly better than the plaintext byte)**: The two
  observable outcomes carry real information: **all** candidate trials fail the
  tag → wrong key *or* corrupt wrapper; a trial **succeeds** but yields an
  unknown `version_byte` → "binary uses a newer wrapper format; upgrade
  litmask." The current design cannot distinguish these without trusting an
  unauthenticated byte.
- **2.5.7 (weak-XOR layer unaffected)**: `weak_mask!` keys its obfuscation on
  the wrapper **nonce** (`derive_weak_xor_key`), which remains plaintext and
  stable across reseal; removing the header bytes only shifts the nonce offset
  (today 2 → 0) and does not touch the weak-XOR derivation.
- **2.5.8 (cost & threat-model fit)**: Trial decryption runs only on the
  key-holder side (runtime, build, CLI) and costs ≤ `|ciphers| × |schemas|`
  cheap symmetric operations on ~33 bytes. An attacker without the key gains
  nothing from the removal of the header bytes and **loses** the two-byte
  classification tell — a net opacity gain at negligible legitimate cost. Offline
  forensic tooling can no longer classify a wrapper's cipher without the key,
  which is desirable under litmask's hide-from-static-analysis threat model.

## 3. Debug Zero-Wiring (`K_dev`)

- **3.1**: A debug build seals under a per-crate non-secret constant `K_dev` so
  `cargo run` / `cargo test` decrypt with **zero key wiring** (kills the dev-loop
  halves of F1/F2/F6). The debug runtime resolution is "use the configured
  provider; if it reports the key **absent** (`KeyError::NotFound`), use `K_dev`."
  The derived locator (§2.1) for a debug build is `KDF(K_dev, …)`, recomputed the
  same way — so the configless scan works in debug too.
- **3.2 (fallback trigger — structural, normative)**: The `K_dev` fallback fires
  **only** on `KeyError::NotFound` (it sits at the key-retrieval layer, before
  decryption, so it can only observe found/not-found). A key that is present but
  wrong flows through unchanged and is surfaced by §5.3 — not masked.
- **3.3 (per-crate `K_dev`, normative)**: `K_dev = KDF(crate-identity ‖ litmask
  domain salt)` (e.g. `CARGO_PKG_NAME` + version), **not** a global constant. A
  single published constant would be a crates.io-readable skeleton key decrypting
  *every* accidentally-shipped debug build; per-crate derivation bounds the blast
  radius to one project. `K_dev` is non-secret by design (the price of
  zero-wiring); per-crate derivation is blast-radius reduction, not secrecy. Both
  the build (to seal) and the runtime (to fall back) recompute it from the same
  `CARGO_PKG_*` inputs — **no secret crosses crates**, and in release both the
  value and its derivation are `cfg`-stripped (§3.5, §9).
- **3.4 (release absence is a hard build error — normative, fail-safe)**: The
  `K_dev` path fires **only when `PROFILE == "debug"` exactly**. Every other value
  — `"release"`, a custom release-derived profile, an unset/unexpected `PROFILE`
  — is treated as release: a missing build-time key is a **hard build error**
  naming `LITMASK_UNLOCK_KEY` and pointing at `litmask keygen`, and no `K_dev` is
  sealed or compiled in. The gate **must** fail toward Release. (A custom
  *debug-derived* profile whose `PROFILE` is not literally `"debug"` also takes
  the release branch and loses zero-wiring — an accepted fail-safe papercut;
  iterate under the literal `dev`/`test` profiles or supply a key.)
- **3.5 (`K_dev` release-absence — MUST, scrub-invariant)**: A release binary MUST
  contain **zero `K_dev` bytes** — value, derivation, and fallback branch all
  `cfg`-stripped by §9. Any litmask-specific constant surviving into release is a
  distinguishing signature on the same footing as "no plaintext in the binary."
  This fuses with §3.4: one `PROFILE` gate decides both "seal under `K_dev`" and
  "compile `K_dev` in at all," failing toward Release.
- **3.6 (debug distribution caveat, normative)**: A debug build carries `K_dev`
  and the ciphertext, so it is **self-decrypting** and offers no extraction
  resistance. It MUST NOT be distributed. Per-crate `K_dev` bounds — does not
  eliminate — the damage if leaked. Documented loudly (§10) and recorded in
  THREAT_MODEL.md.
- **3.7 (zero-wiring masks broken provider wiring — normative caveat)**: Because
  `K_dev` rescues `NotFound`, a debug run whose configured provider is itself
  misconfigured is *rescued* and looks correct, yet the real key path was never
  exercised. Debug success therefore does **not** prove the deployed provider is
  wired. The authoritative test is `verify` on the **release** artifact with the
  production key (§5.4). Documented so a green `cargo run` is not mistaken for a
  validated deployment.
- **3.8**: A debug `cargo run` using `init_with!(MachineIdProvider::new())` is
  **not** rescued by §3.1 (the provider returns a derived key that fails to
  decrypt until resealed — §3.2). Documentation states the consequence: in the
  dev loop use the default/env provider or reseal under the machine key (§6.3).

## 4. Deployment Shape (reseal-default)

- **4.1 (universal build + per-customer reseal — the default)**: The supported
  default for shipping to multiple customers with **identical masked content** is
  **one universal release build**, sealed under an operator-owned **build-key**
  `build_key`, then **resealed per customer** under that customer's `unlock_key`
  (§6.2). The resealed binary's wrapper (and derived locator, §2.1) is re-keyed;
  the `mask_key` and blobs are unchanged. Ship the resealed binary; the runtime
  receives the matching per-customer key out-of-band.
- **4.1.1 (`build_key` is a `keygen` key in a role, not a new key type —
  normative)**: `build_key` is an ordinary `keygen`-minted `unlock_key` (§6.1) —
  same CSPRNG, encoding, and §8 channels. What makes it the build-key is solely
  the operator's choice to seal the universal build under it and reseal away from
  it. No distinct key type, format, or storage path is introduced. By default it
  is **long-lived** (reused across rebuilds and reseal batches), which is what
  lets the operator add a customer later — `reseal --from $BUILD_KEY --to
  <new>` against the retained universal artifact — **without rebuilding**. An
  operator who prefers an ephemeral build-key may simply discard it after a
  batch; that is a usage *policy*, not a separate mechanism, and it forfeits the
  rebuild-free add-customer path.
- **4.1.2 (`build_key` MUST be distinct from every shipped customer key —
  normative)**: The universal build MUST be sealed under a dedicated `build_key`
  that is never shipped to a customer. Sealing it under a real customer's key
  (e.g. `reseal --from bob --to carol`) would make Bob's *shipped* key open the
  in-house universal artifact, re-introducing a cascade. A dedicated
  never-shipped build-key keeps every shipped key unable to open the universal
  build.
- **4.2 (security property of reseal — normative)**: Reseal provides
  **per-customer key compartmentalization**: a binary resealed under Bob's key is
  inert without Bob's key, and Carol's key will not open it. It does **not**
  provide unique-`mask_key` isolation: all customers of one universal build share
  a `mask_key`, so the blobs are byte-identical across customers. For identical
  masked content this exposes nothing extra — the plaintext is the same in every
  binary — so the shared `mask_key` is not a meaningful additional exposure.
- **4.2.1 (`build_key` blast radius — normative, do not overstate)**: `build_key`
  opens the **universal build**, which under reseal-default **never ships**. It
  does **not** open any shipped per-customer binary (those are sealed under
  customer keys), so leaking `build_key` does **not** cascade to the fleet. Its
  worst-case exposure is "a holder of `build_key` *and* the in-house universal
  artifact can read the plaintext" — and that plaintext is identical across
  customers and is the source text the operator already owns. `build_key` is thus
  **plaintext-equivalent**, not a skeleton key over customers. Store it
  `unlock_key`-grade as hygiene, but the threat model MUST NOT imply its leak
  compromises shipped binaries.
- **4.3 (per-customer builds — opt-in, for the cases that need them)**: A
  per-customer **build** (build once per customer under that customer's key,
  yielding unique `mask_key` and unique blobs) is the path for the two cases
  reseal cannot serve: (a) **masked content that differs per customer** (different
  plaintext ⇒ different blobs necessarily), and (b) **leak attribution /
  watermarking** (unique ciphertext per customer lets a leaked binary be traced
  to a customer). Documentation frames the build shape as **determined by these
  needs**, not as a security dial: if content is identical and attribution is not
  required, reseal is strictly preferred.
- **4.4 (machine-id deployment)**: For `MachineIdProvider` deployments where the
  target machine-id is known at build/reseal time, the operator derives the
  machine key off-box with `machine-key` (§6.4) and reseals under it
  (`reseal --to-machine-id`), shipping a binary that self-decrypts on the bound
  host with no env. Where the machine-id is only knowable on the target host,
  reseal on-host over secure transport is the residual case.
- **4.4.1 (provider alignment is unverifiable offline — normative)**: The
  compiled-in `KeyProvider` is chosen in *runtime* code (`init_with!` / implicit
  default); neither `reseal` nor `verify` can observe it. `reseal --to-machine-id`
  on a binary that actually uses `EnvVarProvider` produces a well-formed artifact
  that will **not** self-decrypt on the bound host (the runtime reads the env, not
  the machine), and **no offline check detects this** — `verify --machine-id`
  only proves the *wrapper opens under the machine key*, not that the runtime will
  *request* it. This blindness is by construction (the same fact that makes
  build-emitted provider metadata unworkable); litmask does not add a guard.
  Documentation MUST state the limitation and MUST NOT let `verify` pose as a
  provider-alignment check.
- **4.4.2 (authoritative machine-id validation — execute, do not just `verify`)**:
  The alignment proof is **running the actual binary**, not `litmask verify`.
  Because machine-id is locally reproducible (`show-machine-id`, `machine-key`),
  the operator validates against their **own** host as a faithful proxy without
  the customer's machine:
  1. Reseal a **throwaway** copy to the local machine-id and **execute it with the
     key env cleared** — `litmask reseal cryptio --from-env BUILD_KEY
     --to-machine-id "$(litmask show-machine-id)" -o cryptio-local` then `env -u
     LITMASK_UNLOCK_KEY ./cryptio-local`. Self-decrypt (correct output / exit 0)
     proves the binary self-decrypts from machine-id alone; an `EnvVar` binary
     fails here. The env MUST be cleared — an ambient `LITMASK_UNLOCK_KEY` equal to
     the local machine key would false-positive.
  2. The provider is **compile-time fixed**, so this one execution proves alignment
     for every subsequent reseal of the *same* binary. Reseal the ship copy to the
     target id and run the §5.7 `verify --machine-id … --deny-env BUILD_KEY` crypto
     gate. The residual gap shrinks to "was the customer's machine-id captured
     correctly."
  This validates the self-decrypt **behavior**, not the provider *type* — a custom
  provider deriving the same key passes, which is correct. It requires the
  build/CI host to **execute** the artifact; cross-compiling for a different target
  arch falls back to a **target-platform runner** as the faithful proxy.

## 5. Coherence & Failure Diagnostics

- **5.1 (`verify`, keyed decrypt-success by default)**: `litmask verify <binary>`
  reads the owned key per §8 and performs the authoritative **decrypt-success**
  check (derive locator → locate wrapper → decrypt). It is the only verification
  mode; there is no keyless locator-only check (the derived locator needs the
  key, §2.1), so the F7 false-pass is **unreachable by construction** — stronger
  than A, which had to make the keyless check an explicit opt-in.
- **5.2 (outcomes — normative)**: `verify` reports **four** outcomes via four
  distinct exit codes: *coherent* (locator found and key decrypts), *locator-
  absent* (no matching keyed locator — wrong binary or wrong key entirely),
  *key-fails* (a locator matched but decrypt failed — rare under a keyed locator,
  but possible after a partial/forged match), and *indeterminate* (machine-id
  off-box without `--machine-id`/`--salt`, §5.5). A natural `sysexits` assignment:
  coherent ⇒ `EX_OK`, locator-absent ⇒ `EX_NOINPUT`, key-fails ⇒ `EX_DATAERR`,
  indeterminate ⇒ `EX_UNAVAILABLE`. (Note: with a keyed locator, "wrong key" and
  "wrong binary" both usually surface as *locator-absent* — the key that would
  find the wrapper is the same key that would decrypt it. This is acceptable: the
  operator's question is "does this binary decrypt under this key," answered by
  *coherent* vs not.)
- **5.3 (debug provider-source naming)**: In **debug** builds only, a key failure
  not resolved by §3.1 names the **provider-specific source** the runtime tried
  (`EnvVarProvider::var_name()`, a file path) instead of a bare `explicit panic`
  (F1). Custom providers participate via the optional
  `fn source_hint(&self) -> Option<&str> { None }` trait method (default `None`,
  non-breaking). Release keeps the mute abort.
- **5.4 (verify against the runtime key — normative)**: A coherence check is only
  meaningful with the **same key the runtime will use**. `verify` MUST read the
  key from the same secret-store entry that feeds the deployed provider.
  Verifying against a freshly-`keygen`'d or otherwise different key proves nothing
  and is a false-confidence trap; documentation states this.
- **5.5**: For a `MachineIdProvider` binary, off-box decrypt-success needs the
  machine key the CLI cannot reproduce; `verify` accepts `--machine-id`/`--salt`
  and derives it. Without them it returns *indeterminate*, never *coherent*. A
  *coherent* result here proves only that the **wrapper opens under the machine
  key** — **not** that the runtime will request it (the provider is invisible to
  `verify`, §4.4.1). Provider alignment is proven only by executing the binary
  (§4.4.2), never by `verify`.
- **5.6 (`init_with!` exit-code accuracy — normative)**: Documentation MUST NOT
  claim `init_with!(…)?` "yields the `sysexits` codes." Observed: the bare `?`
  path yields Rust's default `Err` termination (exit 1 with a `Debug`-printed
  variant — `NotPresent` vs `Decryption` distinguishable), **not** a sysexit. At
  least one example MUST map `InitError` to `sysexit_code()` (returning
  `ExitCode`) so the documented codes are real, and docs distinguish the
  `?`→exit-1 path from the explicit-mapping→`sysexits` path.
- **5.7 (`--deny` post-reseal lock-out check — normative)**: `verify` accepts an
  optional `--deny <keysrc>` (per-role §8 sources: `--deny-env`, `--deny-file`,
  `--deny-stdin`) asserting that the named key **cannot** open the binary.
  `litmask verify cryptio-bob --key-env CRYPTIO_KEY_BOB --deny-env BUILD_KEY`
  passes (exit `EX_OK`) iff the `--key` key is *coherent* **and** the `--deny` key
  is **not** *coherent* (it returns *locator-absent* or *key-fails*); otherwise it
  exits non-zero. This is Alice's authoritative post-reseal validation: the
  build-key value is never embedded by construction (B.1), so the meaningful
  question is **capability** — "can `build_key` still open this shipped
  artifact?" — answered here. It catches a botched reseal **and** the most likely
  reseal-default footgun, **shipping the universal artifact by mistake** (under
  build-key it would read *coherent*, failing the gate). The derived locator
  (§2.1) makes the negative cheap and unambiguous: a key whose `KDF`-derived
  needle is absent is structurally locked out (cannot even locate the wrapper),
  independent of the AEAD seal.

## 6. Tooling / CLI Surface

The distributable CLI is **{`verify`, `reseal`, `keygen`, `machine-key`,
`show-machine-id`}**. It never compiles and has no `run` verb — building is
cargo's, run-loop convenience is `just`'s. Every subcommand is **configless**
(§2.3): inputs are a binary path and key sources only.

- **6.1 (`keygen`)**: Mints a fresh 32-byte `unlock_key` (same CSPRNG and
  base64url-no-padding encoding `emit()` and the providers expect) and prints
  **only** the key to stdout (§8.3). Pure generator — touches no binary.
  Provisioning is one pipe per customer:
  `litmask keygen | gh secret set CRYPTIO_KEY_BOB`. Running it once per customer
  yields distinct keys by default (independent draws); it cannot *enforce*
  distinctness but makes it the lazy path (§4.2 recovery of distinctness).
- **6.2 (`reseal` — the one re-keying verb)**: `litmask reseal <binary>
  --from <keysrc> --to <keysrc> [-o <out>]` decrypts the wrapper under the
  `--from` key and re-encrypts it under the `--to` key, rewriting the wrapper and
  its derived locator (§2.1) in place (or to `-o`). `--from`/`--to` are §8
  key-sources (env/file/stdin). The **machine-id case** is the same verb with a
  derived target: `reseal <binary> --from <keysrc> --to-machine-id <id> --salt
  <s>` (this subsumes the legacy `bind` verb — bind is "reseal to a machine key").
  Because `reseal` cannot see the binary's compiled provider (§4.4.1),
  `--to-machine-id` emits a non-secret notice that the artifact self-decrypts on
  the bound host **only if** it was built with `MachineIdProvider`, and points at
  the execute-locally validation (§4.4.2).
- **6.3 (`reseal` covers per-customer distribution)**: The §4.1 default reseals
  then gates each artifact under §5.7:
  `for c in bob carol; do litmask reseal cryptio --from-env BUILD_KEY --to-env
  "CRYPTIO_KEY_${c^^}" -o "cryptio-$c" && litmask verify "cryptio-$c" --key-env
  "CRYPTIO_KEY_${c^^}" --deny-env BUILD_KEY; done` (key sources read from the
  environment, never argv, §8). No metadata file travels; the `--deny-env
  BUILD_KEY` gate proves the build-key cannot open the shipped artifact.
- **6.4 (`machine-key`)**: Derives the machine key off-box using the **same KDF**
  as the runtime `MachineIdProvider`, printing it per §8.3. Feeds reseal's
  `--to-machine-id` path and lets an operator pre-derive a target's key.
- **6.5 (`show-machine-id`)**: Prints this host's machine ID — the exact bytes
  `MachineIdProvider` feeds into derivation. Non-secret identifier, exempt from
  §8. The input an operator captures from a customer host.

## 7. Seed & Reproducibility

- **7.1 (decrypt-reproducibility — free)**: Because the operator owns the
  `unlock_key`, **every rebuild and every reseal decrypts with the same key**
  regardless of the internal seed. F3 ("my captured key went stale") cannot
  occur. Rebuild and reseal freely.
- **7.2 (nonce derivation — structural nonce-reuse safety, normative)**: Per-site
  AEAD nonces are derived as `nonce = KDF(seed ‖ site-id ‖ plaintext)` truncated
  to nonce width, where `site-id` is the literal's stable source location. This
  is deterministic from the seed (so a pinned seed reproduces byte-identical
  blobs) **and** incorporates the plaintext, so changing a literal's content
  changes its nonce — a pinned seed **cannot** reuse a nonce against differing
  plaintext. This structurally eliminates the nonce-reuse hazard that a
  draw-order-based scheme has when a pinned seed meets edited source; no
  build-time guard is required. (The derivation is stated here because it **is**
  the correctness criterion.)
- **7.3 (seed is never persisted or logged — S1 fix, normative)**: A fresh random
  seed is generated per build and **never persisted to disk and never written to
  any build-log line** (no `cargo:warning=` carrying the seed, no
  `target/<profile>/litmask-seed.*` file). Under owned keys the seed has no role
  in runtime decryptability or everyday rebuilds (§7.1), so there is nothing to
  capture. This removes S1 entirely — including cargo's cache-and-replay of a
  seed-bearing warning — rather than scrubbing the value from a retained warning.
- **7.4 (bit-identical reproducibility — opt-in)**: Reproducing identical binary
  *bytes* (attestation, supply-chain hashing, patch-and-diff) requires pinning
  `LITMASK_RNG_SEED` (base64url, 32 bytes), minted by an optional `seed` verb.
  This is a **rare** need (debugging needs only §7.1). When pinned, the seed is a
  master secret (it derives `mask_key`) and is stored with `unlock_key`-grade
  care; the operator who pins it already holds it, so nothing need be emitted.
  **Observed (current `litmask-build/src/lib.rs:258`):** a malformed pinned
  `LITMASK_RNG_SEED` already **hard-fails the build** (build-script panic, exit 101)
  — correct fail-direction — but the message
  (`"LITMASK_RNG_SEED must be base64url-encoded: Invalid"`) omits the 32-byte length
  and a pointer to the `seed`/`keygen` verb; closing that is implementation work.

## 8. Secret Input Channels (normative)

- **8.1**: Any subcommand consuming a secret key (`verify`, `reseal --from/--to`)
  accepts it **only** through non-argv channels: the default env var
  `LITMASK_UNLOCK_KEY`, an explicit `--key-env <NAME>` (per role: `--from-env`,
  `--to-env`), a `--key-file <path>`, or `--key-stdin`. **There is no `--key
  <value>` flag.**
- **8.2 (rationale)**: A secret in argv lands in the process **argument vector**,
  readable by every user on the host via `ps`, and is not reliably masked in CI
  logs. A process **environment** is owner/root-restricted; a file/stdin secret
  never enters the process table. This is the discipline `vault`, `op`, and `gh`
  follow.
- **8.3**: Any subcommand that *emits* a secret (`keygen`, `machine-key`) prints
  **only** the value to stdout, undecorated, so it pipes directly into a secret
  store, and carries the egress warning (never route into shared/CI logs).
- **8.4 (build-time injection — same discipline, not litmask-enforceable)**: The
  build reads `LITMASK_UNLOCK_KEY` from the environment (§1.1), not argv. The
  injection happens at the cargo boundary, which litmask does not control;
  documentation states the discipline (inject from a secret store into the build
  env, never inline the literal) and notes litmask can *facilitate* it, not
  guarantee it.

## 9. Diagnostics Gating (security-correctness)

- **9.1**: Debug-only loud diagnostics (§5.3 identifying strings) are gated on the
  **actual build profile** via a `PROFILE`-derived `cfg` plumbed from a
  runtime-crate `build.rs` — not on `debug_assertions` (user-tunable per profile,
  which would leak strings into release). The gate is automatic and fail-safe.
- **9.2**: This cfg governs **strings**; the `K_dev` value, its derivation, and
  the fallback branch are gated by the same `PROFILE` decision (§3.4/§3.5) and
  MUST be absent from release. There is no generated key and no metadata file, so
  the build-generated design's cross-crate key-gate concern does not arise.

## 10. Examples, Fixtures & Documentation

- **10.1**: Each example declares its masked fixtures in a single source of truth
  the scrub test consumes (no duplication across source, doc comments, and the
  scrub test).
- **10.2**: Every example header documents how to **run** it: in debug, plain
  `cargo run` with no key wiring (§3); for verifying the *release* artifact,
  supply the owned key over a §8 channel — no `awk`, no metadata file, no
  inferring an env var from another file.
- **10.3**: Documentation states the dev-vs-release split: why release is mute,
  why debug is loud and self-decrypting under `K_dev` (and must never be
  distributed), how coherence is verified (§5), that a release build with no key
  **fails at build time** (§3.4), and the §5.6 `init_with!` exit-code accuracy.
- **10.4**: Documentation leads with the **reseal-default** distribution recipe
  (§4.1) and frames per-customer builds (§4.3) as the opt-in for differing
  content or leak attribution — `machine_id_provider`/`EnvVarProvider` docs match
  observed output and show the configurable-variable-name case.
- **10.5**: Documentation shows the per-customer pipeline end-to-end: `keygen` per
  customer into the secret store, one universal `cargo build --release` under
  `build_key`, `reseal` per customer (§6.3), `verify` each with `--deny-env
  BUILD_KEY` (keyed coherence + build-key lock-out, §5.7), and inject each
  customer key into its runtime provider.

## Architecture notes

**Derived locator is the central simplification.** The metadata file existed only
to store a locator that could not be a fixed magic header (a signature). Keyed
derivation removes the file: `locator = KDF(unlock_key, "litmask-locator-v1")`,
embedded as the wrapper prefix, recomputed by whoever holds the key. The scrub
invariant holds because KDF output is indistinguishable from random to a party
without the key; the legitimate key-holder gains nothing by locating a wrapper it
can already decrypt. Everything the prior specs spent on config: the file, the
`--config`/`--meta` flag, sidecar paths, resolution precedence, the
gitignore/attribution caveat, and the keyless `--locator-only` check — is deleted,
not redesigned.

**Reseal vs per-customer build.** One re-keying primitive (`reseal`) re-encrypts a
wrapper from one key to another (the legacy `bind` is `reseal --to-machine-id`).
The default ships one universal build resealed per customer (compartmentalization
at 1/N cost); per-customer builds are reserved for differing content or leak
attribution. The build shape follows from a content/attribution question, not a
security toggle — a sharper framing than "unique build per customer as the model."

**Debug zero-wiring via a constant.** Sealing debug under a public per-crate
`K_dev` (recomputed both ends from `CARGO_PKG_*`, never crossing crates as a
secret, `cfg`-stripped from release) gives zero-wiring `cargo run` with no
key-baking machinery and no cross-crate gate — same "debug self-decrypting, never
distribute" caveat, minimal mechanism. (Carried over from A.)

**Nonce derivation closes the repro hazard.** Deriving per-site nonces from
`(seed, site-id, plaintext)` makes pinned-seed builds both reproducible and
nonce-reuse-safe under edited source, dissolving A's §8.4 hazard structurally
instead of guarding it.

**Secret hygiene.** The owned `unlock_key` and `build_key` travel via
env/file/stdin only (§8), never argv or logs. The debug binary embeds the
non-secret `K_dev` and is self-decrypting — never distribute it. There is no
metadata file and the seed is never persisted or logged (§7.3). The build host
holding all customers' keys (and `build_key`) is an accepted, documented trust
boundary (THREAT_MODEL.md). Note `build_key` is **plaintext-equivalent**, not a
fleet skeleton key (§4.2.1): it never ships and opens no shipped binary.

**Testing strategy.** Reseal one universal build under two distinct owned keys;
assert `verify` reports *coherent* for the matching key and *locator-absent* for
the other (keyed locator, §2.1/§5.2), over env/file/stdin channels, and assert no
argv `--key` flag exists (§8.1); assert the four `verify` outcomes carry four
distinct exit codes (§5.2); assert a binary built/resealed with **no metadata
file present anywhere** still verifies and decrypts (§2.3 — the file genuinely does
not exist); assert the derived locator is absent-as-a-constant from a release
binary scrub and that two binaries resealed under different keys share identical
blobs but differ in wrapper+locator (§4.2); assert a **debug** build decrypts with
the key unset (`K_dev` rescues `NotFound`, §3.1) but a **wrong** explicit env value
is not rescued and hits the §5.3 diagnostic, and that a misconfigured-provider
debug run is silently rescued (§3.7); assert a **release** build with no key fails
at build time (§3.4), a custom release-derived/unset `PROFILE` takes the release
branch (no `K_dev`), and a release artifact embeds zero `K_dev` bytes and stays
scrub-clean (§3.5/§9); assert a fresh release build emits **no** seed-bearing
build-log line and persists **no** seed file, including on a cached no-op rebuild
(§7.3); assert a pinned seed reproduces byte-identical blobs, and that **editing a
masked literal changes that site's nonce** while leaving other sites' nonces
unchanged (§7.2 — no nonce reuse); assert the machine-id off-box path returns
*indeterminate* without flags and decrypt-success with `--machine-id`/`--salt`
(§5.5); assert `keygen`/`machine-key` output is valid base64url/32-byte and that
`machine-key` reproduces the runtime `MachineIdProvider` derivation (§6.4); assert
the §5.3 diagnostic string form is absent from the release binary; assert the
`sysexits` example maps `InitError` to `sysexit_code()` and that the bare `?` path
is documented as exit 1 (§5.6); assert the **opaque wrapper** carries no plaintext
version/cipher byte — a resealed wrapper trial-decrypts to the correct cipher with
the AEAD tag as discriminator, the version byte is recovered only post-decrypt, and
the embedded `nonce ‖ ciphertext ‖ tag` region is scrub-clean of the `0x01,0x01`
tell (§2.5); assert `verify --deny` **fails** when the named key opens the binary
(e.g. the universal artifact under `build_key`) and **passes** when it cannot (a
resealed artifact under `build_key`), in the same run that asserts `--key`
coherence (§5.7); assert the **execute-locally** provider proof (§4.4.2) — a
machine-id-resealed `MachineIdProvider` example **runs to success with
`LITMASK_UNLOCK_KEY` cleared**, while the same example built with `EnvVarProvider`
and resealed `--to-machine-id` **fails** the cleared-env run (proving `verify`
alone cannot catch the mismatch). Reuse the `example_scrub` harness; one fixtures
source per example (§10.1).

## Out of Scope

- A CLI verb that compiles a target, and a `litmask run` exec/key-wiring verb
  (run-loop convenience is a `just` recipe; building is cargo's).
- A managed seed/key **secret store**, or solving the build-host-holds-all-keys
  trust boundary — documented in THREAT_MODEL.md, accepted here.
- Build-emitted provider metadata / build-declared provider selection (the runtime
  owns provider identity via §5.3).
- Changing the wrapper wire format, `mask_key` derivation, or the release-runtime
  failure paths (B changes the *source* of the key, the *storage* of the locator,
  and the *deployment shape* — not the wrapper crypto).
- Enforcing cross-customer key distinctness in the binary (moved to provisioning,
  §6.1) — `keygen` makes it easy, not mandatory.
- A build-identity **ledger** (SPEC_DEVEX §7): decrypt-repro is free (§7.1) and
  bit-repro is pin-the-seed (§7.4); a record of which build shipped to whom is
  relevant **only** to the per-customer-build/attribution mode (§4.3) and is left
  to that operator, not built here.

## Open Questions (all resolved)

- **OQ-1 — RESOLVED (opaque wrapper, §2.5).** Original concern: should the
  embedded prefix carry a plaintext wire-format version byte for scan-time
  detection? Resolution: go the **other** way and remove *both* existing
  plaintext header bytes. Cipher is recovered by trial decryption (AEAD tag =
  discriminator, §2.5.2); the format version moves **inside** the authenticated
  payload (§2.5.3); the locator-derivation scheme version lives in the KDF `info`
  string (§2.5.4). The whole wrapper becomes high-entropy, eliminating the
  `0x01,0x01` tell rather than adding a third low-entropy byte. Cost is a
  bounded, key-holder-only trial loop (§2.5.5/§2.5.8).
- **OQ-2 — RESOLVED (dedicated long-lived `build_key`, §4.1.1/§4.2.1).** Renamed
  `Kb` → `build_key` (build-key). It is a long-lived `keygen` key in a *role*, not
  a new key type. Dedicated wins over ephemeral because reseal-default's value is
  *decoupling* build from distribution (add a customer later via reseal, no
  rebuild); an ephemeral build-key re-couples them. The blast-radius worry that
  motivated "ephemeral" is moot: `build_key` is **plaintext-equivalent** — it
  never ships and opens no shipped binary, so its leak does not cascade (§4.2.1).
  Ephemeral remains available as a discard *policy*, not a built mechanism.
  Normative additions: build-key MUST be distinct from every shipped customer key
  (§4.1.2), and Alice validates lock-out via `verify --deny` (§5.7).
- **OQ-3 — RESOLVED (no guard; validate by execution, §4.4.1/§4.4.2/§5.5).** The
  blindness is *fundamental and symmetric*: neither `reseal` nor `verify` can see
  the runtime-chosen provider, so no offline guard can confirm provider alignment
  (a guard would need build-emitted provider metadata, already rejected). The
  authoritative validator is **running the actual binary**, not `litmask verify`.
  For machine-id: reseal a throwaway to the **local** machine-id and **execute it
  with the key env cleared** — self-decrypt proves provider behavior (an `EnvVar`
  binary fails); the proof transfers to all reseals of the same binary since the
  provider is compile-time fixed. Then reseal to target and run the §5.7
  `verify --machine-id … --deny-env BUILD_KEY` crypto gate. Same-platform and
  clean-env caveats apply; cross-compiles use a target-platform runner. `verify`'s
  claim is tightened (§5.5) and `reseal --to-machine-id` warns (§6.2).

## Decision delta vs `SPEC_DEVEX.md` and `SPEC_DEVEX_A.md`

| Axis | `SPEC_DEVEX` (build-gen) | `SPEC_DEVEX_A` (operator-owned) | **B (clean slate)** |
|---|---|---|---|
| `unlock_key` | build output, chased back | operator input | operator input |
| Metadata file | secret `litmask.config` | non-secret `litmask-meta.toml` | **none — locator derived from key** |
| Wrapper opacity | plaintext version+cipher byte tell | same | **opaque — no plaintext header; cipher by trial-decrypt (§2.5)** |
| `--config`/`--meta` flag | required | override | **does not exist** |
| Dev-loop wiring | baked per-build key | `K_dev` constant | `K_dev` constant |
| Coherence default | locator-only (secret-free) | `verify` keyed; `--locator-only` opt-in | **`verify` keyed only — F7 impossible** |
| Deployment shape | unique build per customer | unique build per customer | **one build + per-customer reseal**; per-cust build = opt-in |
| Cross-customer | unique `mask_key` by construction | `keygen` per customer | `keygen` per customer + reseal compartmentalization |
| Seed | persisted (debug), warned (release) | sensitive, pin for bit-repro | **never persisted, never logged**; pin = opt-in |
| Nonce-reuse on pinned seed | possible | guarded (§8.4.1) | **structurally impossible (§7.2)** |
| Repro/audit | opt-in ledger | decrypt-repro free | decrypt-repro free; ledger only for attribution mode |
| CLI surface | inspect, bind, extract, seed, record, show-machine-id | verify, bind, keygen, machine-key, show-machine-id | **verify, reseal, keygen, machine-key, show-machine-id** |
| Secret CLI input | config-read | env/file/stdin, never argv | env/file/stdin, never argv |
| Spec size / surface | largest | large | **smallest — deletes the config subsystem** |
| Biggest risk | friction → S1-style leaks | lazy key reuse | bigger break from current code (opaque wrapper + no config) |
