# litmask

A Rust library that obfuscates string literals at compile time and
decrypts them at runtime, defeating static binary analysis tools that
recover plaintext from a compiled program (`strings(1)`, disassemblers,
hex editors). The bounded goal is to raise the cost of static binary
analysis from minutes to hours; it is not a credential vault.

For how the pieces fit together, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
first — this file is the **glossary** that pins the canonical terms.

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
Trait that supplies the **unlock key** at runtime. Public built-in
implementations: [`EnvVarProvider`] (env var) and `FileProvider` (path).
The keyless default and the machine-ID binding are backed by `pub(crate)`
providers — `EmbeddedProvider` (recomputes the **unlock key** from the
wrapper's cleartext **nonce**) and the machine-ID provider — reachable
only through the tier machinery (`init!(bind_to_machine)`, or first-`mask!()`
lazy init for Embedded), never named in downstream code.
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
before the runtime is unlocked — e.g. the env-var names or file paths a
governing `init!(<provider>)` itself needs. The derivation uses only the
nonce.
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
macro generating a `serde::Serialize` impl whose type, field, and enum
variant names go through the same AEAD pipeline as `mask!` instead of
landing as cleartext in the binary. Output is byte-identical to the plain
serde derive; names decrypt once at first serialization and stay
cached (leaked) for the process lifetime. Semver-exempt until the
feature stabilizes as `serde`.
_Avoid_: "serde mask", "masked serde derive" (the derive masks names,
not serialized data).

**`MaskDeserialize`** (EXPERIMENTAL, `unstable-serde` feature): Derive
macro generating a `serde::Deserialize` impl whose type, field, and enum
variant names go through the same AEAD pipeline as `mask!` instead of
landing as cleartext in the binary. The plain serde derive leaks the
names more widely than serialize does — `FIELDS`/`VARIANTS` arrays,
field-visitor match arms, `expecting()` strings, and
`missing field`/`unknown variant` diagnostics all carry them. Behavior is
identical to the plain serde derive: same accepted inputs, equal values,
byte-identical error messages, for every serde format. Names decrypt once
at first deserialization and stay cached (leaked) for the process
lifetime. Semver-exempt until the feature stabilizes as `serde`.
_Avoid_: "serde unmask", "masked deserialize derive" (the derive masks
names, not deserialized data).

**`init!`**: Proc-macro that installs a process-global **governing
provider** and eagerly unlocks the host's own **wrapper** through it. It
has three forms, each cross-checked against the build's **seal tier** tag:
`init!(<provider>)` takes any [`KeyProvider`] and unlocks an **external**
seal; the `init!(bind_to_machine)` keyword form unlocks a **machine** seal;
`init!(bind_to_machine + <provider>)` unlocks the two-factor
**machine_external** seal. The keyless **embedded** seal self-initializes
on the first `mask!()`. Any form↔tier mismatch is a `compile_error!`.
Vocabulary: the build **seals** (fixes the tier and key material at
compile time); `bind_to_machine` **binds** (re-reads the host machine id
at runtime and succeeds only on the sealed machine); the host **governs**
(installs the **governing provider** for the graph). The verb triad is
**seal** · **bind** · **govern**.
_Avoid_: "lock to machine", "machine_id form".

### Build pipeline

**Build helper** (`litmask_build::emit()`): Invoked from the
downstream user's `build.rs`. Generates the **seed**, derives the
**mask key** and **nonces** from it, establishes the **unlock key** for
the build's **seal tier** (nonce-derived for Embedded, provider- or
machine-sourced above it), encrypts the **mask key** into the **wrapper**,
and writes the key/seed/wrapper artifacts to `OUT_DIR`. No **unlock key**
is written to disk — the runtime re-derives (Embedded) or re-sources
(keyed tiers) it.

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
unlock KDF over them. Validated material is an [`UnlockMaterial`]:
non-empty after the trailing-newline strip (an unpopulated secret is
rejected), the one form the unlock KDF accepts.

**`litmask show-machine-id`**: Prints this host's **machine-id token** to
stdout, with usage prose on stderr. The token is the value a consumer
feeds to `LITMASK_MACHINE_ID` to seal the **machine** tier.

**Machine-id token** (self-checking token): The host **machine id**
followed by `.` and a short checksum — `raw_id "." base64url(BLAKE3(raw_id)
[..5])`. The in-band checksum lets `emit()` reject an id mistyped or
mangled in transit _before_ it seals a binary nobody can open.
`LITMASK_MACHINE_ID` requires this token form; `emit()` decodes and
validates it, then derives the **machine** key from the bare raw id. A
decoded id is a [`MachineId`] — non-empty by construction (an empty id is
a broken read, rejected at decode), so the machine KDF cannot be handed
one. _Avoid_: "machine-id checksum", "fingerprint".

### Usage patterns

How litmask is consumed across a dependency graph. **Self-masking**,
**transparent masking**, and **governed masking** — backed by the
**mask-key cache**, the **governing provider**, the **uniform seal**, and
the **govern** verb — are all implemented (ADR-0001).

**Masking crate**:
Any crate (lib or bin) with `mask!()` call sites and its own build
**seal** — its own `build.rs`/`emit()`, **seed**, **mask key**, and
**wrapper**. Masking is per-crate because every artifact is per-`OUT_DIR`.
_Avoid_: "mask unit", "masked crate".

**Masking library**:
A **masking crate** shipped as a library dependency — the transitive form
a **host binary** links. Relies on lazy unlock only, never calling
`init!()` (ADR-0001).

**Host binary**:
The final linked artifact carrying one or more **masking crates**. A role,
not a kind: it may itself be a masking crate (**self-masking**) or merely
link **masking libraries** (**transparent masking**).
_Avoid_: "consumer binary" (overloads the general "consumer crate").

**Self-masking**:
The **host binary** is itself the sole **masking crate**, masking its own
strings.

**Transparent masking**:
A **host binary** links **masking libraries** and is unaware litmask is a
transitive dependency; each masking crate unlocks itself at the keyless
Embedded floor via lazy init.
_Avoid_: "autonomous masking" (considered, rejected — see flagged ambiguities).

**Governed masking**:
A **host binary** installs one **governing provider** that opens every
masking crate's **wrapper** across the graph, overriding their default
Embedded lazy unlock; requires a **uniform seal**.

**Mask-key cache**:
The process-global store of decrypted **mask keys**, one entry per
**masking crate** keyed by its **wrapper** — replacing the single
set-once mask-key cell so multiple masking crates coexist in one binary.
_Avoid_: "key registry".

**Governing provider**:
A **key provider** the **host binary** installs process-globally; when one
is installed the lazy unlock path consults it for every **wrapper**
regardless of tier, otherwise only Embedded wrappers self-unlock keyless.
The mechanism behind **governed
masking**.
_Avoid_: "ambient provider", "host provider".

**Uniform seal**:
A build in which every **masking crate** in the graph is sealed under the
same external **unlock key** (one `LITMASK_UNLOCK_KEY` in the build
environment reaches every crate's `emit()`), so one **governing provider**
opens all their **wrappers**.
_Avoid_: "graph seal", "shared seal".

**Govern** (verb):
What a **host binary** does in **governed masking** — install the
**governing provider** for the whole graph. Sits alongside **seal** (build
fixes the key regime) and **bind** (machine factor).

## Relationships

- One **seed** per build → derives one **mask key** and all **nonces**.
  The **unlock key** is nonce-derived (Embedded tier) or provider-supplied,
  not seed-derived.
- One **mask key** per build → encrypts every per-call-site **blob**
  AND is itself encrypted into the **wrapper** under the **unlock
  key**.
- The **unlock key** lives outside the binary; the **wrapper** lives
  inside it, sealed under the **unlock key** at build time.
- A **key provider** supplies the **unlock key** at runtime; the host's
  governing `init!(...)` — or, on an Embedded-sealed build, the first
  `mask!()` call (lazy init) — invokes it.
- A **host binary** links zero or more **masking libraries**; in
  **self-masking** it is itself the sole **masking crate**. Each masking
  crate carries its own **seed → mask key → wrapper**.
- The **mask-key cache** holds one decrypted **mask key** per masking
  crate. **Transparent masking**: each self-unlocks at the Embedded floor.
  **Governed masking**: one **governing provider** + **uniform seal** open
  every **wrapper** in the graph.

## Flagged ambiguities

- **"transparent" vs "autonomous" masking** — for the
  host-unaware-transitive pattern (UC2), "autonomous masking" was
  considered (it names the mechanism: each masking crate self-unlocks)
  but **"transparent masking"** was chosen (it names the host's
  obliviousness and reads friendlier in docs). The distinguishing axis
  from **governed masking** is unlock governance — autonomous-self vs
  host-governed — not transitivity (both are transitive).

- **"host binary" is a role, not a kind** — a **self-masking** host is
  simultaneously a **host binary** and a **masking crate**; in
  **transparent masking** the host is _not_ a masking crate (it only
  links **masking libraries**). Always say which hat is meant.

- **"Walking skeleton"** — previously used to name an integration test
  file. The term is a software-development metaphor (Cockburn,
  _Agile Software Development_), referring to a thin end-to-end
  implementation that proves the architecture. It is **not** a litmask
  domain term and carries no meaning for a future reader. The file
  was renamed to `mask_round_trip.rs`, anchoring on the **mask**
  domain verb and the standard testing concept of a round-trip.

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
