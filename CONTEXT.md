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
the binary. Sourced at runtime from a [**key provider**](#keys).
Never embedded in the binary in the default deployment.
_Avoid_: "user key", "external key", "configuration key".

**Seed**:
A 32-byte build-time random value. The **mask key**, **unlock key**,
and every **nonce** derive from it. Persisted at `target/<profile>/litmask-seed.bin`
so two cargo invocations in the same target directory produce
matching artifacts.
_Avoid_: "rng seed" in code (it's just "seed"); reserve "RNG seed" for the
`LITMASK_RNG_SEED` env var name.

### Cryptographic artifacts

**Wrapper**:
The 62-byte envelope around the encrypted **mask key**: 1-byte format
version + 1-byte cipher id + 12-byte nonce + 32-byte ciphertext + 16-byte
authentication tag. Embedded in the user binary's `.rodata`.
_Avoid_: "envelope", "container", "encrypted mask_key" (the wrapper IS
the encrypted mask key plus its header).

**Blob** (per-string ciphertext blob):
The encrypted form of a single masked literal: 12-byte nonce + ciphertext +
16-byte tag. One blob per `mask!()` call site.
_Avoid_: "ciphertext" alone (ambiguous with the wrapper's ciphertext field);
"encrypted literal".

**Locator**:
The first 12 bytes of the **wrapper** (coincides with the version byte,
cipher-id byte, and the first 10 bytes of the **nonce**). Used by
`litmask bind` and `litmask inspect` to find the wrapper inside a
binary by scanning. Stored in `litmask.config`. Compilers may
duplicate `include_bytes!` data, producing multiple identical copies;
the scanner treats byte-identical copies as a single logical match.
_Avoid_: "wrapper prefix", "header".

**Weak key**:
A 64-byte XOR key derived deterministically from the wrapper **nonce**:
32 bytes of position-dependent bit rotations of the nonce, concatenated
with 32 bytes from `BLAKE3::keyed_hash(rotated, nonce)`. Used by
`weak_mask!` to obfuscate literals. The derivation uses no string
literals (avoiding binary fingerprints) and depends only on the nonce
(stable across **bind**), so `weak_mask!` literals survive wrapper
re-encryption.
_Avoid_: "XOR key", "obfuscation key".

**Nonce**:
A 12-byte AEAD nonce. Two kinds, deterministically derived via BLAKE3:
the **wrapper nonce** (one per build, from the seed and a fixed
domain separator) and the **call-site nonce** (one per `mask!()`
call site, from the seed and the site's identity).

### API surface

**Key provider** ([`KeyProvider`]):
Trait that supplies the **unlock key** at runtime. Built-in
implementations: [`EnvVarProvider`] (env var), `FileProvider` (path),
`MachineIdProvider` (machine ID), `StaticProvider` (in-memory).
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
before `init!()` runs (env-var names, default file paths). Because
the derivation uses only the nonce (stable across **bind**),
`weak_mask!` literals survive wrapper re-encryption.
_Avoid_: "soft mask", "light mask".

**`init!` / `init_with!`**: Declarative macros that decrypt the
**wrapper** with the **unlock key** and populate the process-global
**mask key** cell.

### Build pipeline

**Build helper** (`litmask_build::emit()`): Invoked from the
downstream user's `build.rs`. Generates the **seed**, derives both
keys, encrypts the **mask key** into the **wrapper**, writes
artifacts to `OUT_DIR` and `litmask.config`.

**`litmask.config`**: Deployer-facing TOML written at build time.
Contains the **unlock key**, the **locator**, and the wrapper length.
Secret; do not commit. Consumed by the runtime (via env var) and by
`litmask`.

**Bind** (verb): Rebind a binary to a new **unlock key**, typically
derived from the target host's machine ID. Performed by
`litmask bind`. Patches all identical wrapper copies in the binary.
On macOS, re-signs with an ad-hoc code signature (the patch
invalidates the existing signature, and ARM64 macOS kills unsigned
binaries); warns to stderr on failure.

## Relationships

- One **seed** per build → derives one **mask key**, one **unlock
  key**, all **nonces**.
- One **mask key** per build → encrypts every per-call-site **blob**
  AND is itself encrypted into the **wrapper** under the **unlock
  key**.
- The **unlock key** lives outside the binary; the **wrapper** lives
  inside it. **Bind** swaps the **wrapper** under a new **unlock
  key** without touching the **mask key**.
- A **key provider** supplies the **unlock key** at runtime; the
  user's `init!()` or first `mask!()` call invokes it.
- The **locator** is a 12-byte prefix of the **wrapper**, recorded in
  `litmask.config` so binding tools can find the wrapper without a
  named symbol.

## Example dialogue

> **Dev:** "If two builds use the same **seed**, do they produce the
> same **wrapper**?"
>
> **Maintainer:** "Yes — the **seed** determines the **mask key**, the
> **unlock key**, and the wrapper **nonce**. AEAD with the same key,
> nonce, and plaintext is deterministic, so the **wrapper** bytes are
> byte-identical. Same for per-call-site **blobs**, given the same
> source layout."
>
> **Dev:** "And if I run `litmask bind` against the binary?"
>
> **Maintainer:** "The **mask key** doesn't change — bind decrypts the
> **wrapper** with the current **unlock key**, derives a new **unlock
> key** from the target machine, re-encrypts the same **mask key** under
> the new **unlock key**, and patches the **wrapper** in place. The
> **nonce** is reused (safe because the key changed), so the
> **locator** stays the same and `weak_mask!` literals still decode
> correctly. If the compiler duplicated the wrapper, bind patches
> every copy. On macOS, bind re-signs the binary with an ad-hoc
> code signature."
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
