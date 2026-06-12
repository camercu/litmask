# litmask

A Rust library that obfuscates string literals at compile time and
decrypts them at runtime, defeating static binary analysis tools that
recover plaintext from a compiled program (`strings(1)`, disassemblers,
hex editors). The bounded goal is to raise the cost of static binary
analysis from minutes to hours; it is not a credential vault.

## Language

### Keys

**Mask key** ([`MaskKey`]):
The 32-byte AEAD key that encrypts every per-call-site ciphertext blob.
Generated once per build, decrypted once per process at init, held in
a process-global cell for the program's lifetime.
_Avoid_: "master key", "litmask key", "internal key".

**Unlock key** ([`UnlockKey`]):
The 32-byte AEAD key that encrypts the **mask key** for embedding in
the binary. In the **Embedded** seal tier (default) it is derived from
the cleartext wrapper **nonce** — `BLAKE3::derive_key("litmask-embedded-v1",
nonce)` — and recomputed identically at build and at runtime, so nothing
is stored between them. Higher seal tiers instead source it at runtime
from a [**key provider**](#keys), keeping it out of the binary.
_Avoid_: "user key", "external key", "configuration key".

**Seed**:
A 32-byte build-time random value. The **mask key** and every **nonce**
derive from it; the **unlock key** does not (it is nonce-derived in the
Embedded tier, or provider-supplied above it). Persisted (debug builds
only) at `target/<profile>/litmask_seed.bin` so two cargo invocations in
the same target directory produce matching artifacts.
_Avoid_: "rng seed" in code (it's just "seed"); reserve "RNG seed" for the
`LITMASK_RNG_SEED` env var name.

### Cryptographic artifacts

**Wrapper**:
The 61-byte envelope around the encrypted **mask key**: 12-byte cleartext
nonce + 33-byte ciphertext of `format-version byte ‖ mask key` + 16-byte
authentication tag. The format version is authenticated inside the AEAD
plaintext, never cleartext; the cipher is fixed at compile time and never
written to the wire. Embedded in the user binary's `.rodata` and read by
reference via `include_bytes!`.
_Avoid_: "envelope", "container", "encrypted mask_key" (the wrapper IS
the encrypted mask key plus its nonce and tag).

**Blob** (per-string ciphertext blob):
The encrypted form of a single masked literal: 12-byte nonce + ciphertext +
16-byte tag. One blob per `mask!()` call site.
_Avoid_: "ciphertext" alone (ambiguous with the wrapper's ciphertext field);
"encrypted literal".

**Weak key**:
A 64-byte XOR key derived deterministically from the wrapper **nonce**:
32 bytes of position-dependent bit rotations of the nonce, concatenated
with 32 bytes from `BLAKE3::keyed_hash(rotated, nonce)`. Used by
`weak_mask!` to obfuscate literals. The derivation uses no string
literals (avoiding binary fingerprints) and depends only on the nonce.
_Avoid_: "XOR key", "obfuscation key".

**Nonce**:
A 12-byte AEAD nonce. Two kinds, deterministically derived via BLAKE3:
the **wrapper nonce** (one per build, from the seed and a fixed
domain separator) and the **call-site nonce** (one per `mask!()`
call site, from the seed and the site's identity).

### API surface

**Key provider** ([`KeyProvider`]):
Trait that supplies the **unlock key** at runtime. Built-in
implementations: [`EmbeddedProvider`] (keyless default — recomputes the
**unlock key** from the wrapper's cleartext **nonce**), [`EnvVarProvider`]
(env var), `FileProvider` (path). The machine-ID provider is `pub(crate)`,
reachable only through the `init!(bind_to_machine)` seam — never named in
downstream code.
_Avoid_: "key source", "key backend".

**Mask** (verb): To encrypt a literal at compile time via `mask!()` or
its variants. **Unmask** is the inverse runtime operation.

**`mask!`**: Strong-obfuscation macro. AEAD-encrypts the literal with
the **mask key**; tampering detected by tag verification.

**`weak_mask!`**: Anti-`strings(1)` obfuscation. XORs the literal
against the **weak key** (derived from the wrapper **nonce** via
bit rotation + BLAKE3 keyed hash; see **weak key** below). Both
the obfuscated bytes and the nonce they derive from live in the
same binary, so a disassembler-equipped attacker recovers the
plaintext trivially. Reserved for strings that must be readable
before `init!()` runs (env-var names, default file paths). The
derivation uses only the nonce.
_Avoid_: "soft mask", "light mask".

**`MaskDebug`**: Derive macro generating a `core::fmt::Debug` impl
whose type, field, and variant names go through the same AEAD pipeline
as `mask!` instead of landing as cleartext in the binary. Output is
byte-identical to the plain derive; names decrypt on each `fmt` call
and are released afterwards (no cache, no leak, no feature gate —
works in `no_std` + `alloc`).
_Avoid_: "debug mask", "masked debug derive" (the derive masks names,
not formatted values).

**`MaskSerialize`** (EXPERIMENTAL, `unstable-serde` feature): Derive
macro generating a `serde::Serialize` impl whose struct and field
names go through the same AEAD pipeline as `mask!` instead of landing
as cleartext in the binary. Output is byte-identical to the plain
serde derive; names decrypt once at first serialization and stay
cached (leaked) for the process lifetime. Semver-exempt until the
feature stabilizes as `serde`.
_Avoid_: "serde mask", "masked serde derive" (the derive masks names,
not serialized data).

**`init!` / `init_with!`**: Macros that decrypt the **wrapper** with the
**unlock key** and populate the process-global **mask key** cell. `init!`
(a proc-macro) has four forms, each cross-checked against the build's
**seal tier** tag: no-arg `init!()` uses the keyless [`EmbeddedProvider`];
`init!(<provider>)` unlocks an **external** seal; the `init!(bind_to_machine)`
keyword form unlocks a **machine** seal; `init!(bind_to_machine + <provider>)`
unlocks the two-factor **machine_external** seal. Any form↔tier mismatch
is a `compile_error!`. `init_with!` (declarative) takes any
[`KeyProvider`] — the External form's equivalent.
Vocabulary: the build **seals** (fixes the tier and key material at
compile time); `bind_to_machine` **binds** (re-reads the host machine id
at runtime and succeeds only on the sealed machine).
_Avoid_: "lock to machine", "machine_id form".

### Build pipeline

**Build helper** (`litmask_build::emit()`): Invoked from the
downstream user's `build.rs`. Generates the **seed**, derives the
**mask key** and **nonces** from it and the **unlock key** from the
wrapper **nonce**, encrypts the **mask key** into the **wrapper**, writes
artifacts to `OUT_DIR` (and, Embedded tier only, `litmask.config`).

**`litmask.config`**: TOML diagnostic artifact written at build time by
the **Embedded** tier only. Contains that tier's nonce-derived
**unlock key**; the runtime recomputes the same key from the public
wrapper nonce, so the file is a tooling convenience, not a runtime
input. Still secret; do not commit.

**Seal tier**: How the **unlock key** is sourced for a build, in
ascending strength: **Embedded** (default — nonce-derived, keyless
obfuscation floor), **external** (provider-supplied), **machine**
(machine-ID-bound), **machine_external** (both). `emit()` publishes the
chosen tier as the **`LITMASK_SEAL_TIER`** tag.
_Avoid_: "level", "mode", "key tier".

**`LITMASK_SEAL_TIER`**: Build-authoritative, non-secret tag published
by `emit()` via `cargo:rustc-env`. Names the build's **seal tier** (e.g.
`embedded`). Read by `init!` at macro-expansion time to cross-check that
the chosen `init!` form matches the tier the build was sealed under. The
sole `LITMASK*` value whitelisted onto `rustc-env`; never embedded in the
shipped binary.

### CLI

**`litmask keygen`**: Mints unlock **material** — 32 random bytes,
base64url-encoded, printed to stdout (nothing on stderr). A pure
generator: pipe it into `LITMASK_UNLOCK_KEY` to seal an **external**-tier
build, or stash it in a secret store. The bytes are material, not a
finished **unlock key** — `EnvVarProvider`/`FileProvider` still run the
unlock KDF over them.

**`litmask show-machine-id`**: Prints this host's **machine-id token** to
stdout, with usage prose on stderr. The token is the value a consumer
feeds to `LITMASK_MACHINE_ID` to seal the **machine** tier.

**Machine-id token** (self-checking token): The host **machine id**
followed by `.` and a short checksum — `raw_id "." base64url(BLAKE3(raw_id)
[..5])`. The in-band checksum lets `emit()` reject an id mistyped or
mangled in transit _before_ it seals a binary nobody can open.
`LITMASK_MACHINE_ID` requires this token form; `emit()` decodes and
validates it, then derives the **machine** key from the bare raw id.
_Avoid_: "machine-id checksum", "fingerprint".

## Relationships

- One **seed** per build → derives one **mask key** and all **nonces**.
  The **unlock key** is nonce-derived (Embedded tier) or provider-supplied,
  not seed-derived.
- One **mask key** per build → encrypts every per-call-site **blob**
  AND is itself encrypted into the **wrapper** under the **unlock
  key**.
- The **unlock key** lives outside the binary; the **wrapper** lives
  inside it, sealed under the **unlock key** at build time.
- A **key provider** supplies the **unlock key** at runtime; the
  user's `init!()` — or, on an Embedded-sealed build only, the first
  `mask!()` call (lazy init) — invokes it.

## Example dialogue

> **Dev:** "If two builds use the same **seed**, do they produce the
> same **wrapper**?"
>
> **Maintainer:** "Yes — the **seed** determines the **mask key** and the
> wrapper **nonce**, and in the Embedded tier the **unlock key** is itself
> derived from that nonce. AEAD with the same key, nonce, and plaintext is
> deterministic, so the **wrapper** bytes are byte-identical. Same for
> per-call-site **blobs**, given the same source layout."
>
> **Dev:** "How does the runtime find the **wrapper** in the binary?"
>
> **Maintainer:** "It doesn't search — the **wrapper** is embedded at a
> fixed address via `include_bytes!`, so `init!()` reads it by
> reference. The only cleartext field is the 12-byte **nonce** at the
> front; there's no stored locator and no byte scan."
>
> **Dev:** "Why have both `mask!` and `weak_mask!`?"
>
> **Maintainer:** "`mask!` needs the **mask key**, which doesn't
> exist until `init!()` runs. But `init!()` itself needs to know
> which env var to read for the **unlock key**. So that one string —
> the default `LITMASK_UNLOCK_KEY` literal — has to be readable
> before `init!()`. `weak_mask!` covers that bootstrap window: XOR
> the literal against the **weak key** (derived from the wrapper
> **nonce**), recover at first access. The 'weak' is because the
> **nonce** is right there in the binary; anyone with a disassembler
> derives the same **weak key** and reverses it instantly. That's
> fine — it's an env var name, not a secret."

## Flagged ambiguities

- **"Walking skeleton"** — previously used to name an integration test
  file. The term is a software-development metaphor (Cockburn,
  _Agile Software Development_), referring to a thin end-to-end
  implementation that proves the architecture. It is **not** a litmask
  domain term and carries no meaning for a future reader. The file
  was renamed to `mask_round_trip.rs`, anchoring on the **mask**
  domain verb and the standard testing concept of a round-trip. The
  two auxiliary tests in the same file (`litmask.config` schema,
  `KeyProvider` object-safety) remain there until a third test in
  either category justifies splitting.

- **"Key"** — used for the **mask key**, the **unlock key**, the
  **seed**, and even for the AEAD-internal `Key` type. Always
  qualify: "mask key", "unlock key", "seed". Never just "key" in
  user-facing prose. _Code reflects this_: the types are `MaskKey`,
  `UnlockKey`, and the seed is bytes — none collide.

- **"Wrapper" vs "blob"** — both are AEAD ciphertext with a 12-byte
  nonce + tag. The **wrapper** is unique (one per binary, wraps the
  **mask key**, carries a header); a **blob** is per-call-site
  (wraps a string literal, no header). The header is the
  discriminator. Resolved by always using one word for each.

- **"Encrypt" vs "mask"** — outside the library, "mask" means to
  obfuscate a string via the library's facilities; "encrypt" is the
  underlying cryptographic operation. Inside the library, "encrypt"
  is used for the AEAD primitive and "mask" only for user-facing
  macro names and rustdoc.

- **"Dirty word" / "fixture"** — test-suite vocabulary, not domain.
  The **dirty-word scrub** is a regression test that scans compiled
  binaries for forbidden litmask-identifying substrings. A
  **fixture** is a high-entropy test string deliberately chosen to
  avoid `strings(1)` false positives.
