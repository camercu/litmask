# litmask Specification

A Rust crate for compile-time string literal obfuscation with runtime decryption,
designed to defeat static binary analysis while preserving developer ergonomics.

Target Rust version: 1.88 (subject to review before v1.0; may drop to 1.81 if 1.88
features are not load-bearing in implementation).

**Cross-reference convention:** Section numbers are globally hierarchical. §1.X
identifies sections within Part I (Architecture); §2.X identifies sections within
Part II (Requirements). Cross-references use bare numbers (e.g., §1.5.2 or
§2.3.2.1).

**Canonical source convention:** Each piece of normative content has a single
canonical home. Architecture (Part I) is canonical for design decisions,
rationale, and protocol specifications. Requirements (Part II) is canonical for
testable behavioral assertions. Cross-references point to the canonical source
rather than restating content.

**Status and source of truth:** This document captures requirements, the wire
format, cross-cutting invariants, and the _why_ behind the design. **Runtime
behavior is owned by the code, its rustdoc, and the tests** — they are
authoritative and executable; this prose can lag. Where the spec and the code
disagree, the code wins and the spec entry is a bug to fix. For the mental
model of how the pieces fit, start at [ARCHITECTURE.md](ARCHITECTURE.md).

---

## Part I — Architecture

### §1.1 Purpose and Threat Model

`litmask` exists to raise the cost of static binary analysis for string literals.
It is obfuscation tooling, not a credential vault. Its honest value proposition is
"raises the cost of static binary analysis from minutes to hours" — not "protects
secrets from determined attackers."

#### §1.1.1 Target user

A security-conscious application developer protecting sensitive string constants
from casual binary inspection. Typical concerns: API endpoints, license check
strings, internal service names, proprietary algorithm parameters or model
references, binary protocol magic numbers. Not a cryptographer, not a malware
author. Someone who knows `strings myapp` is a real attack surface and wants to
close it with minimal friction.

`litmask` MUST NOT be presented as a substitute for proper secrets management
(vaults, KMS, OS credential stores). Documentation MUST direct users with
credential-protection use cases toward dedicated tooling.

#### §1.1.2 Attacker capabilities (in scope)

`litmask` is designed against a **Level 2** attacker as the baseline guarantee
and provides meaningful **Level 3** resistance via the layered key strategy:

- **Level 1**: Runs `strings` or opens a hex editor. Stopped by any encryption.
- **Level 2**: Uses a disassembler (Ghidra, IDA), identifies decryption routines,
  manually decrypts. Stopped by per-string unique nonces, AEAD ciphers, and the
  absence of plaintext key material in the binary.
- **Level 3**: Writes an automated unpacker that emulates decryption stubs.
  Resistance comes from: (a) `mask_key` being encrypted with `unlock_key` that
  is never embedded in the binary in the layered (default) configuration, and
  (b) per-build key uniqueness defeating generic unpackers built against one
  binary. `litmask` does not promise complete Level 3 resistance — a determined
  attacker who runs the binary or controls its environment can still observe
  decryption.
- **Level 4**: Dumps process memory at runtime. **Out of scope.**

#### §1.1.3 Explicitly out of scope

- Runtime memory inspection
- Debugger attachment after key derivation
- Compromised runtime environments
- Side-channel attacks (timing, power analysis)
- Control-flow obfuscation or anti-debugging
- Protection of dynamically generated strings
- Perfect secrecy under any threat model

#### §1.1.4 Security guarantees

Configurations and what each defeats:

| Configuration | Defeats |
|---|---|
| Zero-config build (keyless Embedded tier, no `init!`) | `strings`, casual binary inspection (Level 1) only — the `unlock_key` is recomputed from the wrapper's cleartext nonce, so it is recoverable from the artifact |
| `FileProvider` + filesystem permissions | Above with OS-enforced access control |
| `init!(bind_to_machine)` (build-sealed) | Above + binary moved to a different machine |
| `init!(bind_to_machine + <provider>)` (two-factor) | Above + the external factor (env/file/vault) the binary alone never carries |
| Custom `KeyProvider` (network call, vault) | Above + offline attackers |

The "zero-config" descriptor refers to absence of project configuration, not to
absence of runtime key provisioning. For providers that source `unlock_key` from
external runtime state (`EnvVarProvider`, `FileProvider`, custom providers), the
deployer MUST provision that state at runtime. A binary configured with such a
provider but without the corresponding state will fail at init. Two configurations
need no operator provisioning: the keyless Embedded floor stores no key and
recomputes `unlock_key` from the public wrapper nonce (Level 1 only — the nonce
ships in the binary, so the key is honestly recoverable from the artifact); and
the machine tier (`init!(bind_to_machine)`) re-sources its factor from the host's own
machine id at startup, so it requires no delivered secret — but it does require
running on the host the build was sealed for, and fails at init anywhere else.

#### §1.1.5 Deliberate understatement

Documentation and error messages MUST err toward understating guarantees. False
confidence is the most common failure mode of obfuscation libraries; users
deploy them in scenarios they don't actually protect against. Every public-facing
description of security properties must be conservative.

#### §1.1.6 Value proposition vs. existing crates

The feature-by-feature comparison against `obfstr` and `litcrypt`/`litcrypt2`
lives canonically in the README's "Why litmask" table; the crate rustdoc and
this section reference it rather than duplicating it (one table to keep honest,
not three).

The cipher upgrade (XOR → AEAD) is the primary technical advance. Everything
else is operational maturity (key management, deployment story, tooling).

### §1.2 Workspace Structure

`litmask` is a Cargo workspace. The user-facing surface is three crates:

| Crate | Type | Purpose |
|---|---|---|
| `litmask` | library | Runtime, proc-macro re-exports, key provider trait and built-ins |
| `litmask-build` | library (build-dep) | `build.rs` helper for compile-time key generation and tier sealing; writes the seed/key/wrapper blobs to `$OUT_DIR` |
| `litmask-cli` | binary | `keygen` (random unlock key / seed) and `show-machine-id` (self-checking host-id token) — generate/read-only tools for build-time sealing |

The user-facing API ships as a single `litmask` crate. Internally, Rust
forbids exporting non-macro items from a `proc-macro = true` crate, so the
workspace contains a hidden `litmask-macros` proc-macro crate whose macros
`litmask` re-exports. All members share one workspace version, bumped in
lockstep and released together so the binary format never desyncs;
crates.io publishing is disabled workspace-wide (`publish = false`) and the
inter-crate dependencies are path-only. `litmask-macros` is documented as
"internal — do not depend on directly."

An additional internal crate, `litmask-internal`, holds shared wire-format
constants and crypto primitives used across the workspace (the runtime,
build helper, proc-macro, and CLI crates).

### §1.3 Build Pipeline

#### §1.3.1 Build-time flow

1. User adds `litmask` as a regular dependency and `litmask-build` as a
   build-dependency.
2. User adds a one-line `build.rs`: `litmask_build::emit();`.
3. `build.rs` runs:
   - Sources `RNG_SEED` from `LITMASK_RNG_SEED` env var, then (debug builds
     only) from `target/<profile>/litmask_seed.bin`, then generates a fresh
     seed.
   - Generates `mask_key` (32 bytes) and the **nonces** deterministically
     from the seed.
   - Derives `unlock_key` (32 bytes) for the default **Embedded** seal tier
     as `BLAKE3::derive_key("litmask-embedded-v1", wrapper_nonce)` — from the
     cleartext wrapper nonce alone, independent of the seed's key stream, so
     build and runtime recompute it identically with nothing stored between
     them. Higher seal tiers replace this with a provider-supplied key.
   - Encrypts `mask_key` with `unlock_key` using the configured cipher,
     producing the encrypted `mask_key` wrapper described in §1.7.3.
   - Writes `mask_key` and `RNG_SEED` to files in `OUT_DIR`
     (`$OUT_DIR/litmask_key.bin` and `$OUT_DIR/litmask_seed.bin`). The
     proc-macro reads these via `include_bytes!`. The plaintext `mask_key`
     is NEVER emitted via `cargo:rustc-env` because such directives are
     recorded in `target/<profile>/build/<pkg>/output` and printed verbatim
     under `cargo build -vv`, leaking the key to terminal, CI logs, and
     build-cache snapshots.
   - Emits Cargo directives:
     - `cargo:rerun-if-env-changed=LITMASK_RNG_SEED`
     - `cargo:rerun-if-changed=build.rs`
     - `cargo:rustc-env=LITMASK_SEAL_TIER=<tier>` — the build-authoritative,
       non-secret seal-tier tag (`embedded` for the default tier), read by
       `init!` to cross-check form↔tier. This is the sole `LITMASK*` value
       whitelisted onto `rustc-env`; no secret is ever emitted this way.
     - `cargo:rerun-if-env-changed` for the tier's key-source env vars
       (`LITMASK_UNLOCK_KEY`, `LITMASK_MACHINE_ID`).
   - Never writes the derived `unlock_key` to disk (§1.7.4).
   - In debug profile, writes `target/<profile>/litmask_seed.bin` for
     incremental build stability.
   - Never prints the seed, `unlock_key`, `mask_key`, or any secret to the
     build log (§D.1.2): no key material reaches the terminal, CI logs, or
     build-cache snapshots.
4. Proc-macro expansions read `mask_key` and `RNG_SEED` from `OUT_DIR` files
   and emit encrypted ciphertext for each `mask!` invocation, using the
   nonce derivation in §1.5.2 and the per-string blob format in §1.7.2.

#### §1.3.2 Profile-dependent behavior

| Profile | Seed source priority |
|---|---|
| debug | `LITMASK_RNG_SEED` env → `target/<profile>/litmask_seed.bin` → fresh + persist |
| release | `LITMASK_RNG_SEED` env → fresh, no persistence |

`build.rs` detects profile via the `PROFILE` env var that Cargo sets. The
seed itself is never echoed to the build log (§D.1.2). The one sanctioned
release-profile `cargo:warning=` is the **Embedded-floor notice**: when a
release build resolves to the keyless Embedded tier — no seal key in the
build environment, so no governing `init!` applies — `emit()` warns that
the wrapper key is recoverable from the artifact and points at
`LITMASK_UNLOCK_KEY` / `LITMASK_MACHINE_ID` for a stronger tier. The notice
is presence-driven (keyed off the resolved tier), carries no secret,
and rides the build-log channel only — nothing is baked into the shipped
binary (§D.2.2).

#### §1.3.3 Reproducibility

A build is reproducible given:

- Same source code
- Same Rust toolchain version
- Same dependency versions (`Cargo.lock` pinned)
- Same `LITMASK_RNG_SEED` value
- Same build path (or `--remap-path-prefix` applied consistently)

`litmask` does not guarantee bit-identity beyond these conditions.

#### §1.3.4 No project configuration file

`litmask` v1 does NOT use a project-level configuration file. Cipher selection
is via Cargo feature flags (see §1.5.1). The key strategy is fixed at
`layered`. Runtime behavior (which `KeyProvider` is used, env var names, file
paths) is configured in application code, not in a config file.

### §1.4 Runtime Architecture

#### §1.4.1 Initialization

The runtime maintains a per-wrapper **mask-key cache** of decrypted
`mask_key`s (one entry per masking crate, keyed by its wrapper nonce;
`std::sync::Mutex<HashMap>` under `std`, a single `once_cell::race::OnceBox`
cell under `no_std`; §2.10.6) and a process-global, install-once
**governing provider** (ADR-0001). Initialization happens via:

```rust
litmask::init!(provider)?;                       // External tier: provided KeyProvider
litmask::init!(bind_to_machine)?;                // Machine tier
litmask::init!(bind_to_machine + provider)?;     // MachineExternal two-factor
```

There is no bare `init!()`: the keyless Embedded tier self-initializes
lazily on the first `mask!()`. Every surviving form **governs** — it
installs the governing provider for the whole dependency graph and eagerly
unlocks the host's own wrapper through it.

`init!` is not a regular function: it expands at the call site so it can
`include_bytes!(concat!(env!("OUT_DIR"), "/litmask_wrapper.bin"))` against
the **caller's** crate `OUT_DIR` (where the user's `build.rs` ran
`litmask_build::emit()`). A regular function in the `litmask` runtime crate
cannot reach a downstream crate's `OUT_DIR`. `init!` is a proc-macro so it
can read the build-authoritative `LITMASK_SEAL_TIER` tag and
`compile_error!` when the form and the sealed tier disagree (`init!(provider)`
requires the `external` tier; `init!(bind_to_machine)` the `machine` tier;
the two-factor form `machine_external`). It delegates to a private
`litmask::__internal::__govern_*` seam that installs the governor and runs
the shared unlock path.

**Lazy unlock.** On the first `mask!()` for a wrapper not yet cached: if a
governing provider is installed, it supplies the `unlock_key` for that
wrapper regardless of tier (governed masking under a uniform seal);
otherwise only the keyless Embedded floor self-unlocks via
`EmbeddedProvider::new(&wrapper)`, and a `mask!()` carrying a non-Embedded
`LITMASK_SEAL_TIER` tag with no governor installed panics with an
init-ordering diagnostic rather than deriving the wrong key (§2.1.1.12a).
Governing init is therefore required above the floor — and recommended even
at the floor, since it surfaces unlock failures at startup with structured
errors rather than panics deep in execution.

Each cache entry is initialized exactly once per process; key rotation at
runtime is not supported in v1.

#### §1.4.2 Decryption flow

Each `mask!()` call:

1. Retrieves the cached `mask_key` from the per-wrapper mask-key cache
   (lazy-init if needed).
2. Reads its locally-embedded encrypted blob (format: §1.7.2).
3. Decrypts using the configured cipher.
4. Returns the result (`String`, `Vec<u8>`, or `CString` based on literal type).

Decryption failures at this stage indicate ciphertext tampering and panic per
§1.9.5.

#### §1.4.3 Concurrency

The mask-key cache initializes each wrapper's key at most once
(`Mutex<HashMap>` under `std`, a `OnceBox` cell under `no_std`). `mask!()`
calls from multiple threads contend only on that one-shot insert, then each
call decrypts into its own owned return value.

### §1.5 Cryptographic Design

#### §1.5.1 Cipher choices and feature selection

- **Default**: ChaCha20-Poly1305 (AEAD, 256-bit key, 96-bit nonce, 128-bit tag)
- **Optional**: AES-256-GCM (AEAD, 256-bit key, 96-bit nonce, 128-bit tag),
  selected by enabling the `aes-gcm` feature

Exactly one cipher (`CURRENT_CIPHER`) seals and opens each build of the
`litmask` runtime crate and `litmask-build`. The selection rule is:

| `aes-gcm` feature | `CURRENT_CIPHER` |
|---|---|
| disabled | ChaCha20-Poly1305 |
| enabled | AES-256-GCM (takes precedence) |

`litmask-internal` resolves `CURRENT_CIPHER` by feature: `aes-gcm` enabled
selects AES-256-GCM, otherwise ChaCha20-Poly1305. Every wrapper and blob is
sealed and opened with that one cipher, which is never written to the wire
(§1.7.3). Each backend is an optional dependency pulled in only by its own
feature, so a normal single-feature build compiles just the selected crate.
Cargo feature unification (e.g. `--all-features`) can compile both backends
at once — the AEAD dispatch then handles either `CipherId` — but
`CURRENT_CIPHER` still resolves to a single cipher per build, so there is no
ambiguity about which cipher sealed the artifacts.

`litmask-cli` does not decrypt wrappers (its v1 subcommands, `keygen` and
`show-machine-id`, are generate/read-only), so it links no cipher and the
single-cipher rule does not apply to it.

Rejected ciphers: AES-CTR (no authentication), Salsa20 (superseded by
ChaCha20), RC4 (cryptographically broken).

Cipher selection is fixed at build time; runtime cipher switching is not
supported.

#### §1.5.2 Per-string nonce derivation

Every encrypted blob in the binary uses a unique nonce. Nonces for per-string
blobs are derived deterministically inside the `mask!` proc-macro as:

```text
nonce = first_12_bytes(BLAKE3-keyed-hash(
    seed,
    CALL_SITE_TAG
    || file_len_le || file
    || line_le
    || column_le
    || plaintext
))
```

`CALL_SITE_TAG` and `WRAPPER_TAG` (§1.7.3) are implementation-defined
byte strings that MUST differ from each other so the call-site and wrapper
nonce spaces remain disjoint under the same seed.

`file` is the call-site source path
(`proc_macro::Span::file()` canonicalized to a `CARGO_MANIFEST_DIR`-
relative form so reproducibility doesn't depend on the absolute
checkout location), `line` and `column` are the 4-byte
little-endian source coordinates (`Span::line()` / `Span::column()`
truncated to `u32`), `plaintext` is the bytes being masked, and
`file_len_le` is the 8-byte little-endian byte count of the `file`
field.

**Correctness scope.** ChaCha20-Poly1305 (and AES-256-GCM) require the
`(key, nonce)` pair to be unique per **distinct plaintext** under a
given key. Encrypting the same plaintext twice with the same
`(key, nonce)` is harmless (produces identical ciphertext); encrypting
two _different_ plaintexts with the same `(key, nonce)` is the
security failure — their XOR leaks the plaintext XOR. Therefore the
invariant the derivation must preserve is **nonce uniqueness across
distinct plaintexts within a single rustc invocation that encrypts
under one `mask_key`**.

That scope is narrower than it looks. Each crate that uses `mask!`
must have its own `build.rs` calling `litmask_build::emit()` (§1.4),
which writes a fresh `litmask_key.bin` into that crate's `OUT_DIR`.
Two crates that both depend on `litmask` therefore encrypt under two
_different_ `mask_key` values, so a nonce collision across crates is
harmless — collisions only matter inside the set of blobs sharing one
`mask_key`, i.e., the blobs produced by one rustc process expanding
one crate.

**Why (file, line, column).** Span coordinates are
expansion-order-independent: two `mask!()` calls at distinct source
positions receive distinct nonces regardless of which rustc thread or
macro-expansion pass visited first. This matters for two reasons:

1. **Reproducibility (§2.1.1.8).** Identical source + identical seed
   must produce byte-identical ciphertext across builds. A counter-
   based scheme is sensitive to expansion order; a Span-based scheme
   is not.
2. **Future parallel macro expansion.** Rustc currently expands proc-
   macros sequentially, but `-Z threads=N` parallelizes other parts
   of compilation and may eventually parallelize macro expansion. A
   counter would race; Span coordinates do not.

`proc_macro::Span::file()`, `Span::line()`, and `Span::column()` were
stabilized in Rust 1.88, the workspace's pinned toolchain.

**Why plaintext is also keyed.** `mask_format!` synthesizes multiple
`mask!()` calls inside a single `quote!{}` expansion — one per
template fragment — and `quote!`'s default span propagation makes
those calls share a `(file, line, column)` triple. Distinct
plaintexts at the same triple **must** get distinct nonces for AEAD
security. Including the plaintext bytes in the keyed hash makes that
property invariant-by-construction: two `mask!()` calls with the
same plaintext at the same span share a nonce (and produce identical
ciphertext — harmless); two `mask!()` calls with different plaintexts
at the same span receive different nonces (no XOR leak).

**Encoding (canonical, unambiguous).** `file` is the only
non-trailing variable-length field, so its 8-byte length prefix is
load-bearing: without it, `(file = "ab", line = 0x01, …)` could
share its byte representation with `(file = "a", line = 0x6201, …)`
because the boundary between file and line bytes would shift.
`plaintext` is the trailing field, so any change to its bytes
changes the hash output directly — a length prefix would be
defensively redundant.

**File-path canonicalization.** `proc_macro::Span::file()` returns
whatever path rustc received from cargo, which can be absolute or
relative depending on workspace layout, `--remap-path-prefix`, and
CWD. Two checkouts of the same source at different filesystem
locations would otherwise produce different nonces. Before hashing,
the proc-macro strips a leading `CARGO_MANIFEST_DIR` prefix from
`Span::file()` so the keyed bytes describe a manifest-relative
path. Falls back to the raw path when no prefix match exists; the
nonce stays correct but the path-stability property is forfeited.

**Seed keying.** The seed-keyed hash is hardening, not a security
boundary — the nonce ships in plaintext at the head of every blob.
Keying on the seed prevents source coordinates and plaintext-length
patterns from appearing as recognizable structure in `.rodata`.

**Threat model: seed compromise.** Because `plaintext` is mixed
into the keyed hash, an attacker who recovers `seed` (via
`LITMASK_RNG_SEED` env leakage, the debug-profile
`target/<profile>/litmask_seed.bin` persistence file, or any
side-channel that exposes the build seed) can compute the expected
nonce for a guessed plaintext at known `(file, line, column)` and
compare to the observed nonce in the binary. A match confirms the
guess.

This is a known-plaintext **confirmation oracle**, not an AEAD
break: the ciphertext + tag still resist forgery and decryption
under the `mask_key` (which is independent of `seed`). The oracle
is low-bandwidth — the attacker needs a plausible plaintext
candidate set AND already knows `(file, line, column)`. It only
matters when the seed has leaked; the seed-confidentiality
requirement in §1.3 is what blocks this attack, and this note
reinforces why §1.3 matters.

Properties:

- **Uniqueness per (key, plaintext)**: distinct `(file, line, column,
  plaintext)` tuples produce distinct nonces (BLAKE3 collision
  resistance plus canonical encoding).
- **Determinism across builds**: same source layout + same seed →
  same nonces → same ciphertext, independent of expansion order.
- **Independence from the wrapper nonce**: the call-site domain
  separator MUST differ from the wrapper's domain separator, so the
  nonce spaces are disjoint at the same seed.

The wrapper around the encrypted `mask_key` uses a separate nonce derivation
documented in §1.7.3.

#### §1.5.3 Key strategy: layered

`mask_key` is encrypted with `unlock_key` and embedded in the binary.
`unlock_key` is supplied at runtime through a `KeyProvider`. This is the only
key strategy in v1.

#### §1.5.4 Authentication

All cipher choices are AEAD. Tampering with any ciphertext (including the
encrypted `mask_key` wrapper) produces an authentication failure during
decryption. The runtime panics with a tampering-detected error when this
occurs at a `mask!()` call site (per §1.9.5), or returns
`InitError::Decryption` when it occurs during `init!()` (per §1.9.2).

#### §1.5.5 Per-string KDF — rejected

A per-string key derivation strategy (each string encrypted with
`K_i = BLAKE3-keyed-hash(mask_key, salt_i)`) was evaluated. It is rejected
for v1 and v2 because:

1. The threats it would defend against (key recovery from one ciphertext,
   side-channel attacks) are not in `litmask`'s threat model and are not
   weaknesses of ChaCha20-Poly1305 or AES-256-GCM.
2. It does not raise the bar against Level 3 automated unpackers, which
   would simply run the KDF step per string.
3. It costs ~16 bytes per string in binary size for the salt.
4. It introduces binary format variance (a feature flag would split the
   ecosystem into incompatible binary formats).

If a real-world weakness in ChaCha20-Poly1305 emerges, the correct response
is changing ciphers, not stacking additional KDFs on top of the existing
cipher.

### §1.6 Key Management

#### §1.6.1 KeyProvider trait

```rust
pub trait KeyProvider: Send + Sync {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError>;
}
```

The `&self` receiver allows stateful providers (cached lookups, network
clients); the `Send + Sync` bound lets one be installed as the
process-global governing provider across threads. `UnlockKey` is a 32-byte
newtype that zeroes on drop.

The trait is intentionally minimal. It has no `deployment_hint()` method or
similar — the goal of minimizing library-side plaintext (see §1.9.3)
precludes English-language strings on the trait. Deployment guidance lives in
`DEPLOYMENT.md`, not in the binary.

#### §1.6.2 Built-in providers

| Provider | Feature gate | Visibility | Description |
|---|---|---|---|
| `EnvVarProvider` | `std` (default) | `pub` | Reads from a configurable env var (default `LITMASK_UNLOCK_KEY`) |
| `FileProvider` | `std` (default) | `pub` | Reads from a filesystem path |
| `MachineIdProvider` | `machine-id` (opt-in) | `pub(crate)` | Derives the machine-tier `unlock_key` from the host machine id (`machine-uid`) + the build's wrapper nonce |
| `EmbeddedProvider` | always available | `pub(crate)` | Keyless floor (internal); recomputes the Embedded-tier `unlock_key` from the wrapper's cleartext nonce |

Default provider for the keyless Embedded tier, used by the lazy
self-init path (no `init!` call): `EmbeddedProvider::new(&wrapper)` —
recomputes the Embedded-tier `unlock_key` from the wrapper's public nonce
(no stored key material).

`MachineIdProvider` is **not** part of the public API: it is `pub(crate)` and
reachable only through the `init!(bind_to_machine)` keyword form, which constructs
it from the embedded wrapper nonce via a `#[doc(hidden)]` seam fn in
`litmask::__internal` (§2.5.4). The macro never names the type — expansion lands
in the consumer crate, which cannot reach a `pub(crate)` symbol — so there is no
public constructor and no runtime salt parameter. The machine factor is sealed
at build time from `LITMASK_MACHINE_ID` and re-sourced at runtime from the host;
see §2.5.4.

#### §1.6.3 Key encoding

`unlock_key` and `mask_key` are 32 raw bytes internally. Where a key is
encoded for transport — `litmask keygen`'s output and the canonical
high-entropy form of `LITMASK_UNLOCK_KEY` material — it uses **base64url
without padding** (RFC 4648 §5); 32 bytes encodes to 43 characters, which
is what `UnlockKey::from_base64url` parses. No derived key is written to
disk (§1.7.4).

External-tier unlock **material** is different: the `EnvVarProvider` /
`FileProvider` value is **arbitrary-length raw bytes**, not an encoded
key. A provider strips a single trailing newline (so editor- and
shell-appended newlines do not fork the secret) and normalizes the bytes
through `UnlockKey::derive` — `unlock_key = KDF("litmask-unlock-v1",
material)`. There is no encoding step and no length constraint on the
material.

#### §1.6.4 UnlockKey lifecycle

`UnlockKey` is constructed by `KeyProvider::unlock_key()`, used to decrypt
`mask_key` during `init!()`, and dropped immediately after. The decrypted
`mask_key` is held in the per-wrapper mask-key cache for the program
lifetime.

`UnlockKey` and `MaskKey` (internal type) both implement `Drop` with `zeroize`
to clear their contents from memory when dropped.

#### §1.6.5 Cross-compilation note for the machine tier

The machine factor is recomputed on the **target** host at runtime (via the
`init!(bind_to_machine)` seam), not on the build host. `machine-uid` supports all
standard `std` targets (Linux, macOS, Windows). On constrained or unusual
targets where `machine-uid` cannot read a stable machine identifier (some
container runtimes, certain embedded Linux variants without `/etc/machine-id`,
OpenBSD by default), the seam's `unlock_key()` returns
`Err(KeyError::Provider(...))` and `init!(bind_to_machine)` fails. Builds targeting
such environments MUST verify behavior on the target before relying on the
machine tier. The same constraint applies at **build** time: sealing reads the
host id from `LITMASK_MACHINE_ID` (typically captured via `litmask
show-machine-id`, §2.9.3), which the CLI cannot produce on those hosts. The
platform CI matrix (§1.10.5) explicitly exercises this failure path on OpenBSD.

### §1.7 Binary Format and Build-Time Sealing

#### §1.7.1 No-signature design rationale

The binary contains no identifying patterns, named sections, or magic bytes
attributable to `litmask`. Every encrypted blob is pure ciphertext that looks
like ordinary random data in `.rodata`, indistinguishable from precomputed
tables, embedded test vectors, or compressed assets.

The encrypted `mask_key` wrapper is embedded at a fixed address via
`include_bytes!`, so the runtime reads it by reference rather than scanning for
it. There is no stored locator and no byte-pattern search. The wrapper's only
cleartext field is its 12-byte AEAD nonce at offset 0; because that nonce is
uniformly random per build, the wrapper contributes no fixed cross-build
pattern.

Generalizing this property: litmask MUST NOT contribute fixed byte signatures
to user binaries. Any ancillary literal that the library needs to embed (the
default env-var name, future default file paths for `FileProvider`, etc.) MUST
be obfuscated via the public `weak_mask!()` macro (§1.8.1), which XORs the
literal against a 64-byte key derived from the wrapper nonce (bit rotation +
BLAKE3 keyed hash). The derivation uses no string literals and depends only on
the nonce, so the resulting `.rodata` representation varies per build with the
nonce's random bytes, leaving no grep-across-binaries fingerprint.

#### §1.7.2 Per-string ciphertext blob format

Each per-string encrypted blob is a contiguous byte sequence:

```text
<nonce: 12 bytes><ciphertext: variable length><authentication tag: 16 bytes>
```

There is NO format version byte, NO cipher identifier byte, and NO other
identifying header in per-string blobs. Format is a global property of the
build, authenticated inside the wrapper around the encrypted `mask_key` (see
§1.7.3), not duplicated per-string. Cipher is selected at compile time
(`CURRENT_CIPHER`) and never written to the wire at all.

The nonce is derived per §1.5.2.

#### §1.7.3 Encrypted mask_key wrapper format

The encrypted `mask_key` wrapper carries its format version inside the AEAD
plaintext, so no fixed-value structural byte appears at a known offset. Its
layout:

```text
<nonce: 12 bytes><AEAD(format version: 1 byte ‖ mask_key: 32 bytes): 33 bytes ciphertext><authentication tag: 16 bytes>
```

Total length: 61 bytes (`nonce 12 ‖ ciphertext 33 ‖ tag 16`).

- Nonce: the only cleartext field, at offset 0. Derived deterministically
  (see below).
- Format version: the first byte of the AEAD _plaintext_ (`version_byte ‖
  mask_key`). It is authenticated, never carried in cleartext, and validated
  only after the AEAD tag verifies. The runtime rejects unknown versions per
  §1.9.2 (`InitError::UnsupportedFormat`). Current version is `0x01`.
- Cipher: NOT present on the wire. Every wrapper and blob in a binary is
  encrypted with the single cipher the build was compiled for; the runtime
  dispatches on the compile-time `CURRENT_CIPHER` constant (§1.5.1), so there
  is no cipher-id byte and no runtime cipher-mismatch error.

The wrapper's nonce is derived deterministically as:

```text
wrapper_nonce = first_12_bytes(BLAKE3-keyed-hash(
    seed,
    WRAPPER_TAG
))
```

#### §1.7.4 Unlock-key persistence

The derived `unlock_key` is **never written to disk**. The Embedded tier
recomputes it from the public wrapper nonce at runtime; the External and
Machine tiers re-source their material (operator channel / host machine id)
and re-run the KDF. Persisting a derived key would write a secret to an
artifact nothing consumes (§D.1.2). Callers needing arbitrary unlock
material (tests, demos) mint it with `litmask keygen`.

#### §1.7.5 Build artifact location

`litmask-build::emit()` writes the seed/key/wrapper blobs to `$OUT_DIR`
(`litmask_seed.bin`, `litmask_key.bin`, `litmask_wrapper.bin`), consumed by
the proc-macro at expansion and the runtime via `include_bytes!`. Under the
debug profile it also persists the seed to `target/<profile>/litmask_seed.bin`
for reproducible incremental builds. `build.rs` derives the profile directory
from `OUT_DIR` (`target/<profile>/` three ancestors up).

#### §1.7.6 Keying workflow

The keying tier is sealed at build time, selected by which build inputs are
present (presence-driven, §2.4); there is no post-build rebind step and no
`litmask bind` command. Each tier re-establishes its `unlock_key` at runtime
without a stored key:

- **Embedded** (no build inputs): the runtime recomputes the nonce-derived
  `unlock_key` from the embedded wrapper nonce. No provisioning.
- **External** (`LITMASK_UNLOCK_KEY` set at build): the operator provisions the
  same material at runtime via `EnvVarProvider` / `FileProvider`, which re-runs
  the KDF over it.
- **Machine** (`LITMASK_MACHINE_ID` set at build): `init!(bind_to_machine)` recomputes
  the host machine id locally and re-derives the key. No provisioning, but the
  binary opens only on the host it was sealed for.
- **MachineExternal** (both `LITMASK_MACHINE_ID` and `LITMASK_UNLOCK_KEY` set at
  build): the two-factor tier. `init!(bind_to_machine + <provider>)` finishes the
  machine factor key (host id) and the external factor key (operator material)
  independently, then composes them — `unlock_key = KDF("litmask-2fa-v1",
  len_prefixed(machine_key) ‖ len_prefixed(external_key))`, machine-first. The
  binary opens only on the sealed host **and** with the sealed material; either
  factor wrong fails the wrapper's AEAD check.

The design rationale and accepted residuals behind the build-sealed model are
folded into Appendix D.

### §1.8 API Surface

#### §1.8.1 Macros

```rust
mask!(literal)              // dispatches on literal kind
mask_format!(template, args...) // masked format string
mask_print!(template, args...)  // masked print to stdout (std)
mask_println!(template, args...)// masked println to stdout (std)
mask_eprint!(template, args...) // masked print to stderr (std)
mask_eprintln!(template, args...)// masked println to stderr (std)
mask_write!(dst, template, args...)  // masked write to any writer
mask_writeln!(dst, template, args...)// masked writeln to any writer
unmasked!(literal)          // explicit opt-out, returns literal unchanged
weak_mask!(literal)         // XOR-with-nonce-derived-key obfuscation; weaker than mask!
mask_include_str!("path")   // file contents → masked String
mask_include_bytes!("path") // file contents → masked Vec<u8>
mask_concat!(args...)       // compile-time concat → masked String
mask_env!("VAR")            // build-time env var → masked String
mask_option_env!("VAR")     // build-time env var → masked Option<String>
mask_file!()                // current source path → masked String
#[mask_all]                 // module-level deep rewriting
#[mask_all(strict)]         // upgrades skip warnings to errors
```

`weak_mask!` is the **only** masking macro that works before the runtime
mask key is unlocked. It MUST be used exclusively for strings needed
during the bootstrap window — env var names, default file paths, and
other non-secret metadata that a governing `init!(<provider>)` needs in
order to locate the unlock key. The threat model is
strictly weaker than `mask!`: the literal is XOR-ed against a 64-byte
key derived from the wrapper nonce (position-dependent bit rotation +
BLAKE3 keyed hash). The nonce lives in the user binary, so an attacker
with a disassembler derives the same key and recovers the plaintext
trivially. The derivation uses no string literals (no binary
fingerprint) and depends only on the wrapper nonce, which is fixed for a
given build. `weak_mask!`
defends against `strings(1)` and Level 1 inspection only. Real secrets
always use `mask!` once the runtime is unlocked. Decode happens once
per call site (cached in a once-cell).

`weak_mask!` accepts the same three literal kinds as `mask!`:

- `weak_mask!("text")` → `&'static str`
- `weak_mask!(b"\x...")` → `&'static [u8]`
- `weak_mask!(c"text")` → `&'static CStr` (requires `std` feature)

`mask!` accepts only the three literal kinds:

- String literal (`"text"`, raw, Unicode-escape) → returns `String`
- Byte string literal (`b"\x..."`, raw byte) → returns `Vec<u8>`
- C string literal (`c"text"`, Rust 1.77+) → returns `CString`

`mask!` SHALL NOT accept macro invocations as input. Any
`mask!(<macro>!(...))` form is rejected with the standard non-literal
error from §1.9.6.

`mask_stack!` (the experimental `unstable-stack` feature, §2.1.9) is the
zero-allocation variant: it accepts the same three literal kinds but
decrypts into an inline stack buffer — `MaskStr<N>` / `MaskBytes<N>` /
`MaskCStr<N>` — that zeroizes on drop, instead of a heap `String` /
`Vec<u8>` / `CString`.

A dedicated family of compile-time-resolving masking macros handles
stdlib equivalents. Each macro takes the same input as its stdlib
counterpart but encrypts the result before emission:

- `mask_include_str!("path")` → `String` — §2.1.3
- `mask_include_bytes!("path")` → `Vec<u8>` — §2.1.4
- `mask_concat!(args...)` → `String` — §2.1.5
- `mask_env!("VAR")` → `String` (compile_error if unset) — §2.1.6
- `mask_option_env!("VAR")` → `Option<String>` — §2.1.7
- `mask_file!()` → `String` — §2.1.8

`#[mask_all]`'s substitution table (§2.3.2) rewrites the unmasked
stdlib forms (`include_str!`, `include_bytes!`, `concat!`, `env!`,
`option_env!`, `file!`) to their dedicated `mask_*!` counterparts.

Not included: `mask_cfg!` (stdlib `cfg!()` resolves to a compile-time
bool with no `.rodata` residue — masking adds runtime cost for zero
metadata reduction) and `mask_module_path!` (`proc_macro::Span` does
not expose a `module_path()` accessor on stable Rust, making
proc-macro-time resolution unreachable).

`mask_format!` accepts string literal templates only. Non-literal templates produce
a compile error directing users toward `mask!` for runtime-decrypted strings.

`mask_print!` and `mask_println!` are declarative-macro wrappers around
`mask_format!` that print the decrypted result to stdout via `print!` /
`println!`. Gated behind the `std` feature. `mask_println!()` with no
arguments prints a bare newline (no masking involved). The decrypted
text is written in the clear to stdout — litmask protects literals at
rest in the binary; once printed, the output is unprotected.

`mask_eprint!` and `mask_eprintln!` are the stderr counterparts, wrapping
`eprint!` / `eprintln!`. Same `std` gating, same bare-newline form
(`mask_eprintln!()`), same security note. They exist as standalone
convenience wrappers so a consumer can mask a diagnostic written to
stderr without entering a `#[mask_all]` module; `#[mask_all]` already
rewrites bare `eprint!` / `eprintln!` calls (§2.3.2) for code inside its
scope.

`mask_write!` and `mask_writeln!` are declarative-macro wrappers around
`mask_format!` that write to an arbitrary destination via `write!` /
`writeln!`. Work with any `core::fmt::Write` or `std::io::Write`
implementor (the caller must have the appropriate trait in scope).
`mask_writeln!(dst)` with no format arguments writes a bare newline.
Available in `no_std` + `alloc` builds. Same security note: once
written, the destination controls confidentiality, not litmask.

`unmasked!` accepts any of the above literal kinds and returns them unchanged
(preserving original type: `&str`, `&[u8; N]`, or `&CStr`). It exists to mark
literals as intentionally unmasked, particularly for `#[mask_all(strict)]`
audit purposes.

#### §1.8.2 Init macros

```rust
litmask::init!(provider)?;            // External tier: any KeyProvider expression
litmask::init!(bind_to_machine)?;          // Machine tier: host-id-sealed (machine-id feature)
litmask::init!(bind_to_machine + provider)?; // MachineExternal tier: two-factor (machine-id feature)
```

`init!` is a proc-macro (form↔tier cross-check; see §1.4.1 for rationale).
The form is selected by its argument: empty → a `grammar` `compile_error!`
(bare `init!()` was removed; the Embedded tier self-initializes lazily on
the first `mask!()`), the bare keyword `bind_to_machine` → Machine,
`bind_to_machine + <expr>` → MachineExternal (two-factor), any other
expression → External (a provider value). A `bind_to_machine +` with no
following provider expression is also a `grammar` `compile_error!`. Each
surviving form unlocks exactly one sealed tier; the macro reads the build's
`LITMASK_SEAL_TIER` tag at expansion and emits a `compile_error!` on a
form↔tier mismatch (§1.9.6).

Every surviving form **governs**: it installs the process-global governing
provider (ADR-0001) and eagerly unlocks the host's own wrapper through it,
so the lazy path then opens every transitive crate's wrapper under a uniform
seal. `init!(provider)` delegates to the private
`litmask::__internal::__govern_external` seam, passing wrapper bytes read via
`include_bytes!` at the call site. `init!(bind_to_machine)` routes through the
`__govern_machine_call!` seam macro (so a `machine`-sealed build with the
`machine-id` feature disabled gets a directed `compile_error!` rather than a
missing-symbol error); the governor constructs the `pub(crate)`
`MachineIdProvider` from each wrapper's nonce in-crate at consult time
(§2.5.4). `init!(bind_to_machine + <provider>)` routes through the analogous
`__govern_machine_external_call!` seam: per wrapper the governor composes the
machine factor with the external factor via `UnlockKey::compose` (§2.3). The
effective signature of every expansion result is `Result<(), InitError>`.

#### §1.8.3 Public types

```rust
pub trait KeyProvider: Send + Sync { ... }
pub struct UnlockKey([u8; 32]);

pub struct EnvVarProvider { ... }
pub struct FileProvider { ... }
// EmbeddedProvider is pub(crate) — the internal keyless floor (§2.5.5).

#[non_exhaustive] pub enum InitError { ... }
#[non_exhaustive] pub enum KeyError { ... }
```

`MachineIdProvider` is intentionally **absent** from the public types: under
the `machine-id` feature it is `pub(crate)`, reachable only through the
`init!(bind_to_machine)` seam (§1.6.2, §2.5.4), so it carries no semver surface.

#### §1.8.4 Internal types (not stable API)

The following exist but are explicitly internal — `#[doc(hidden)]` or
`pub(crate)`, not subject to semver guarantees:

- `MaskKey` — `#[doc(hidden)]` runtime container for the decrypted mask key
- The `litmask::__internal` re-export module and the `#[doc(hidden)]
  #[macro_export]` plumbing macros (`__wrapper_bytes!`, `__seal_tier!`, the
  decrypt / govern seam macros) emitted into macro-generated code
- Nonce derivation helpers (`nonce_for_call_site`, `nonce_for_wrapper`) in
  `litmask-internal`

User code MUST NOT depend on these.

### §1.9 Error Handling

#### §1.9.1 Two-layer error model

- **Init layer** (fallible, structured): `init!(...)` and
  `KeyProvider::unlock_key()` return `Result`. Application code can handle
  initialization errors gracefully (display message, exit cleanly, fall back
  to alternate mode).
- **Decryption layer** (panicking): individual `mask!()` calls return their
  decrypted value or panic. Per-call `Result` returns are rejected as
  user-hostile — if `mask_key` is valid, individual decryption only fails on
  tampering, which is unrecoverable by design.

#### §1.9.2 Error variants

```rust
#[non_exhaustive]
pub enum InitError {
    KeyProvider(KeyError),       // Provider failed to retrieve unlock_key
    Decryption,                  // mask_key decryption failed (wrong unlock_key
                                 // or tampered mask_key wrapper — these are
                                 // cryptographically indistinguishable)
    UnsupportedFormat,           // authenticated format-version byte unknown
}

#[non_exhaustive]
pub enum KeyError {
    NotFound,                    // Key source unavailable (env var unset, etc.)
    Permission,                  // Key source unreadable (file permissions)
    InvalidFormat,               // Key data malformed (wrong length, bad encoding)
    Provider(Box<dyn Error + Send + Sync>),  // Custom provider failure
}
```

Error variants are stable; new variants in minor versions are non-breaking
due to `#[non_exhaustive]`.

`InitError::Decryption` covers both "wrong unlock_key supplied" and "mask_key
wrapper tampered with"; AEAD authentication failure does not distinguish
these cases. The variant is mapped to EX_DATAERR in §1.9.7.

#### §1.9.3 Error display policy

`litmask` aims to minimize plaintext content the library contributes to a
linked binary, but the goal is "minimal, non-identifying plaintext," not
absolute zero. Two unavoidable sources of identifier-like strings exist:

1. Auto-derived `Debug` impls for `InitError` and `KeyError` produce variant
   name strings (`"NotFound"`, `"Permission"`, etc.) when materialized.
2. `Display` impls produce short `category:variant` tags for users who format
   errors directly.

Both are short ASCII identifiers, not English explanations. They reveal the
existence of variant-named error states but do not identify `litmask`
specifically (every Rust crate using auto-derived `Debug` has comparable
strings) and do not describe what the program does.

For users requiring minimal plaintext, the recommended pattern is to use
`InitError::sysexit_code()` (see §1.9.7) and exit without invoking `Display`
or `Debug`. Variant strings may be eliminated by Rust's optimizer in some
cases when no code path materializes them, but this elimination is not
guaranteed and depends on optimization level, `#[non_exhaustive]`
interactions, and dyn dispatch usage. Users who require provable absence of
these strings should verify with `strings` on their built binary.

`Display` implementations for `InitError` and `KeyError` produce only short
variant tags:

```text
InitError::KeyProvider(KeyError::NotFound)   → "key_provider:not_found"
InitError::KeyProvider(KeyError::Permission) → "key_provider:permission"
InitError::Decryption                        → "decryption_failed"
InitError::UnsupportedFormat                 → "unsupported_format"
```

These tags are short, ASCII-only, and provide no semantic guidance — they are
identifiers, not explanations. Application code is responsible for any
human-readable messaging:

```rust
match litmask::init!(provider) {
    Ok(()) => {}
    Err(InitError::KeyProvider(KeyError::NotFound)) => {
        eprintln!("Configuration error: missing unlock key");
        std::process::exit(1);
    }
    Err(InitError::Decryption) => {
        eprintln!("Integrity check failed");
        std::process::exit(1);
    }
    // ...
}
```

#### §1.9.4 Init-failure plaintext limitation

After init failure, `mask!()` cannot be used because `mask_key` is
undecrypted. Application code displaying init errors thus cannot use `mask!()`
for those specific messages — it must use plaintext strings (or opaque codes,
or sysexits).

This is an inherent property: any decryption mechanism for init-failure
messages would require an additional always-available key, which would itself
need to be embedded in plaintext. The honest answer is to acknowledge the
limitation rather than paper over it with a weakened secondary obfuscation
layer.

`THREAT_MODEL.md` MUST document this limitation explicitly.

#### §1.9.5 Tampering panic policy

When `mask!()` detects ciphertext tampering at runtime, it SHALL panic
without contributing any litmask-specific message text to the **release**
binary.

The principle: the library MUST NOT contribute string content that uniquely
identifies the operation as litmask-related to a shipped artifact. Strings
from `std` and from dependency crates are acceptable because they exist in
many Rust programs and do not single out litmask.

**Profile split.** This hygiene protects shipped binaries, so the
MUST-NOTs below apply under `cfg(not(debug_assertions))` (release). Under
`cfg(debug_assertions)` (debug), the failure arms instead route to the
`#[cfg(debug_assertions)]`-gated `litmask::diagnostics` module, which panics
with loud, actionable, litmask-identifying text so the developer sees the
failure on their own machine. That module is never compiled into a release
artifact, and a debug binary is self-decrypting at the Embedded floor — so
it MUST NOT be distributed (§D.2.1). The cfg-split lives at each failure arm
(`#[cfg(debug_assertions)] Err(..) => diagnostics::…` vs
`#[cfg(not(debug_assertions))] Err(_) => panic!()`).

The release-build library implementation:

- MAY use `panic!()` (no message) — preferred for absolute minimum string
  count
- MAY use `.unwrap()` on `Result` values from std or dependency crates. The
  resulting panic emits std's `"called \`Result::unwrap()\` on an \`Err\`
  value"` plus the `Debug` of the underlying error (e.g., chacha20poly1305's
  `Error`). These strings are present in many Rust binaries and do not
  identify litmask.
- MUST NOT use `.expect("...")` with any custom message, because the message
  text becomes a litmask-specific string.
- MUST NOT use `panic!("...")` with any custom message, for the same reason.
- MUST NOT use `.unwrap_or_else(|_| panic!("..."))` or any other pattern
  that injects litmask-specific text into the panic.

The recommended pattern is:

```rust
match cipher.decrypt(&blob) {
    Ok(plaintext) => plaintext,
    Err(_) => panic!(),
}
```

`.unwrap()` is acceptable when the surrounding code is more naturally
expressed that way:

```rust
let plaintext = cipher.decrypt(&blob).unwrap();
```

The Rust standard library still emits `panicked at <file>:<line>` via the
default panic handler regardless of which form is used. Applications that
want a more informative tampering panic may set a panic hook
(`std::panic::set_hook`) that detects panics in `litmask`-affected locations
and emits their own message.

Even with the recommended deployment profile (`strip = "symbols"`,
`debug = false`, `panic = "abort"`, `lto = true`), the `&'static str`
produced by `core::panic::Location::caller()` for every `panic!()` call site
remains in the binary's `.rodata`. The string has the shape
`<crate-name>/src/<path>.rs` and is recoverable via `strings(1)`. For
`litmask` panic sites this leaks the substring "litmask" into user binaries.
This is unavoidable on stable Rust 1.88: `strip` removes symbols and debug
info but not `.rodata` string literals; `panic = "abort"` swaps out the
unwinder but still references the `Location` value when aborting. Removal
options:

- Compile with `RUSTFLAGS="-Z location-detail=none"` on the nightly
  toolchain. This is the upstream-blessed way to strip panic location strings.
- Move every panicking call site into a workspace crate with a
  non-identifying name. The location string then references the helper
  crate's path instead of `litmask/...`.

The dirty-word regression scrub at `litmask/tests/example_scrub.rs` filters
substrings matching the shape `<crate>/src/<path>.rs` before looking for
forbidden identifiers, so this leak does not flag a CI failure on stable.
`THREAT_MODEL.md` MUST surface this caveat to users who require a
zero-identifier binary; the operationally-correct recommendation is to add
the nightly `-Z` flag or accept the leak.

#### §1.9.6 Compile-time error message requirements

Compile-time errors from the proc-macro do NOT appear in the compiled binary
and MAY use full English text. Every compile error emitted by a litmask
proc-macro SHALL include both:

1. The invoking macro's name with `!` suffix (`mask!`, `mask_format!`,
   `mask_include_str!`, `mask_include_bytes!`, `mask_concat!`, `mask_env!`,
   `mask_option_env!`, `mask_file!`, `unmasked!`, `weak_mask!`, `init!`, and
   the derives `MaskDebug!` / `MaskSerialize!` / `MaskDeserialize!`).
2. One of the closed failure tags below, identifying the rejection reason.
   The tag SHALL appear verbatim as a hyphen-separated lowercase substring
   (`<macro>! <tag>`); the `tests/compile/*.stderr` snapshots pin it so a
   wording edit is caught, and a consumer may pattern-match on it.

| Tag | Situation |
|---|---|
| `non-literal` | Argument required to be a string literal was not one. Covers `mask!`'s non-literal input, `mask_format!`'s non-literal template, `mask_include_str!` / `mask_include_bytes!` non-literal path, `mask_env!` / `mask_option_env!` non-literal name. |
| `read-failure` | Path-taking macro (`mask_include_str!`, `mask_include_bytes!`) could not read the referenced file. |
| `unset` | `mask_env!` was given a name that resolves to no environment variable. (`mask_option_env!`'s unset case is a runtime `None`, not a compile error.) |
| `unicode-failure` | Environment-variable value is set but not valid UTF-8. |
| `invalid-arg` | `mask_concat!` was passed an argument that is not a string literal or a compile-time-resolvable string macro. |
| `args-not-allowed` | `mask_file!` was given any argument (the macro takes none). |
| `tier-mismatch` | An `init!` form was invoked against a build whose sealed `LITMASK_SEAL_TIER` does not match that form (§1.8.2's 4-way matrix), or that set no tier at all (no `litmask_build::emit()` in `build.rs`). |
| `grammar` | `init!`'s argument failed to parse as any of the four forms — e.g. `bind_to_machine +` with no following provider expression. |
| `duplicate-name` | `mask_format!` was given the same named argument twice. |
| `positional-after-named` | `mask_format!` was given a positional argument after a named one. |
| `positional-unused` | `mask_format!` was given a positional argument never referenced by any placeholder. |
| `named-unused` | `mask_format!` was given a named argument never referenced by any placeholder (mirrors `format!`'s "named argument never used"). |
| `positional-out-of-range` | `mask_format!` template references positional index `N` but fewer than `N + 1` positional arguments were provided. |
| `invalid-placeholder` | `mask_format!` placeholder header is not a valid Rust identifier (e.g. starts with a digit). |
| `template-syntax` | `mask_format!` template has malformed `{...}` syntax (unmatched brace, nested `{`, unclosed placeholder, etc.). |

Implementations MAY add adjacent context (paths, values, hints) to the
emitted text — only the macro name and the tag are normative. Specific
message wording is implementation-defined and MAY evolve across releases
without a spec amendment, provided every emitted error continues to carry
both the macro name and one of the tags above.

Trybuild fixtures snapshot the exact text emitted by the current
implementation; they are the implementation's regression net, not a
re-statement of this spec rule. Snapshot regeneration on wording changes
is mechanical (`TRYBUILD=overwrite`) and does not require a spec PR.

`mask!` rejections in `const` / `static` initializer and pattern
positions fall through to rustc's natural diagnostics
(`E0015: cannot call non-const function ...` and
`expected pattern, found {` respectively); the proc-macro emits no
custom substring for these positions. See §2.1.1.9 and §2.1.1.10
for the behavioral contract. Rationale: detecting both positions from
inside the proc-macro is not directly possible — const/static
initializers would require the proc-macro to inspect the surrounding
item, which `proc_macro::Span` does not expose, and pattern positions
invoke macros in pattern context, which rustc rejects before the
proc-macro runs at all. Trybuild fixtures lock the rejection by
snapshotting the natural diagnostic.

#### §1.9.7 Sysexits.h exit code mapping

`InitError` SHALL provide a method that maps each variant to a sysexits.h
(BSD `<sysexits.h>`) exit code:

```rust
impl InitError {
    /// Returns a sysexits.h-compatible exit code.
    /// Use to terminate the process without invoking Display/Debug,
    /// achieving minimal plaintext in the binary.
    pub fn sysexit_code(&self) -> i32 {
        match self {
            InitError::KeyProvider(KeyError::NotFound)      => 78,  // EX_CONFIG
            InitError::KeyProvider(KeyError::Permission)    => 77,  // EX_NOPERM
            InitError::KeyProvider(KeyError::InvalidFormat) => 65,  // EX_DATAERR
            InitError::KeyProvider(KeyError::Provider(_))   => 69,  // EX_UNAVAILABLE
            InitError::Decryption                           => 65,  // EX_DATAERR
            InitError::UnsupportedFormat                    => 70,  // EX_SOFTWARE
        }
    }
}
```

The numeric constants are defined inline (no `sysexits` crate dependency).
Numeric exit codes do NOT add plaintext to the binary — they compile to
immediate values, not `.rodata` strings.

The mapping rationale:

| Variant | Code | Reasoning |
|---|---|---|
| `KeyProvider(NotFound)` | EX_CONFIG (78) | Missing required configuration |
| `KeyProvider(Permission)` | EX_NOPERM (77) | OS-level access denied |
| `KeyProvider(InvalidFormat)` | EX_DATAERR (65) | Malformed key data |
| `KeyProvider(Provider(_))` | EX_UNAVAILABLE (69) | Custom provider failure (network, service, etc.) |
| `Decryption` | EX_DATAERR (65) | AEAD authentication failure (see §1.9.2) |
| `UnsupportedFormat` | EX_SOFTWARE (70) | Format version mismatch — software issue |

Recommended usage pattern:

```rust
if let Err(e) = litmask::init!(provider) {
    std::process::exit(e.sysexit_code());
}
```

Operators looking up sysexits.h documentation see the meaning of each code
without litmask-specific knowledge required.

The same sysexits values are used for `litmask-cli` exit codes per §2.9.

### §1.10 Testing Strategy

`litmask` employs five testing tiers. This section describes the purpose and
scope of each tier; canonical testable assertions are enumerated in §2.12 and
§2.13.

#### §1.10.1 Unit tests

Per-module tests for runtime components (cipher wrappers, `KeyProvider`
implementations, error handling, base64url encoding, nonce derivation,
sysexits mapping). Run via `cargo test`. Located in `src/<module>.rs`
`#[cfg(test)] mod tests` blocks following standard Rust convention.

#### §1.10.2 Compile tests

Verify that the proc-macro accepts valid input, rejects invalid input with
messages matching §1.9.6, and produces expected token streams. Implemented
with `trybuild`. Located in `litmask/tests/compile/` directory.

#### §1.10.3 Integration tests

Build small example binaries with various configurations to verify end-to-end
behavior, including the security property the library exists to provide. The
`strings`-output check that confirms no plaintext leakage into the binary is
the most security-critical assertion in the entire test suite — it can only
be performed by building a binary and inspecting it.

Located in `tests/` directory of the `litmask` crate, following standard Rust
convention. No separate workspace crate.

#### §1.10.4 Fuzzing

One fuzz target covers the proc-macro format parser — a component whose
input domain is large enough that exhaustive testing is impractical but
where defects could be security-relevant. Implemented in `litmask/fuzz/`
using `cargo-fuzz`. Run in CI for a bounded time budget per PR.

#### §1.10.5 Platform CI matrix

The CI matrix exercises security and operational properties across a
representative set of operating systems. Each platform job runs the
integration tests from §1.10.3 plus a machine-tier seal/run smoke test specific
to that platform's machine ID mechanism.

| Platform | Mechanism | Coverage |
|---|---|---|
| ubuntu-latest | GitHub Actions native | Debian/Ubuntu glibc family, `/etc/machine-id` |
| almalinux:9 | GitHub Actions Docker job | RHEL-family, SELinux defaults |
| macos-latest | GitHub Actions native | Darwin, IOPlatformSerialNumber |
| windows-latest | GitHub Actions native | Windows registry MachineGuid, NTFS atomic rename |
| FreeBSD 14.2 | `cross-platform-actions/action` (QEMU VM) | BSD-family, `kern.hostuuid` |
| OpenBSD 7.8 | `cross-platform-actions/action` (QEMU VM) | OpenBSD specifically (no `/etc/machine-id` by default; tests the machine-tier failure path) |

The smoke test sequence and per-platform requirements (including the
intentional failure-path validation on stock OpenBSD) are specified in §2.13.

OpenBSD installations that have provisioned a machine ID via third-party
means may pass the full smoke test sequence; the job tolerates either
outcome but requires consistency (decryption succeeds OR `init!(bind_to_machine)`
fails cleanly, never partial success).

NetBSD, DragonFly BSD, Illumos, and other distributions are not in v1's CI
matrix — they may work but are not validated.

### §1.11 Documentation Plan

#### §1.11.1 Required documentation artifacts

| Artifact | Purpose |
|---|---|
| `README.md` | Project overview, security posture, "what does NOT protect against" callout, the canonical value-proposition comparison table, quick start |
| `lib.rs` crate docs | API overview, security posture, value-proposition comparison table (references the canonical README copy) |
| `THREAT_MODEL.md` | Formal threat model including in-scope and out-of-scope attacker capabilities and the init-failure plaintext limitation from §1.9.4 |
| `DEPLOYMENT.md` | Operational guide per keying tier, recommended release profile, build-time `machine`-tier sealing workflow, sysexits.h code reference |
| Per-API rustdoc | Standard rustdoc on every public item with examples |
| `MIGRATION.md` | Coverage of moving from `litcrypt` (v1 and v2) and `obfstr`, with side-by-side API comparisons |

#### §1.11.2 Required content

Every user-facing documentation surface MUST surface the out-of-scope
limitations — at minimum the "What `litmask` does NOT protect against" points —
inline or by a clear reference to `THREAT_MODEL.md`, which is canonical for the
security ladder (§1.1.4) and the out-of-scope list (§1.1.3).

`DEPLOYMENT.md` MUST include the recommended release profile snippet:

```toml
[profile.release]
strip = "symbols"
debug = false
panic = "abort"
lto = true
```

with rationale for each setting.

`DEPLOYMENT.md` MUST include a sysexits.h code reference table mirroring
§1.9.7 so operators can interpret exit codes from binaries that use
`sysexit_code()`.

#### §1.11.3 Tone

Documentation SHALL err toward understatement of security guarantees per
§1.1.5. Documentation SHALL NOT promise resistance to attacker capabilities
listed as out-of-scope in §1.1.3.

### §1.12 Stability and MSRV

#### §1.12.1 Stability commitments

Stable surface (semver-protected):

- `mask!`, `mask_format!`, `unmasked!` macros
- `#[mask_all]` attribute and substitution table (additions allowed; removals
  breaking)
- `KeyProvider` trait
- `UnlockKey` type
- `EnvVarProvider`, `FileProvider` (public providers; `EmbeddedProvider`
  and `MachineIdProvider` are `pub(crate)` and NOT part of the stable surface)
- `init!(<provider>)`, `init!(bind_to_machine)`, `init!(bind_to_machine + <provider>)` macro forms
- `InitError::sysexit_code()` method and the sysexits mapping in §1.9.7
- Error type variants (new variants non-breaking via `#[non_exhaustive]`)
- Default cipher (ChaCha20-Poly1305)
- Keyless Embedded floor as the no-`init!` default (backed internally by
  the `pub(crate)` `EmbeddedProvider`)
- `LITMASK_RNG_SEED`, `LITMASK_UNLOCK_KEY`, `LITMASK_MACHINE_ID` env var names
  and the `LITMASK_SEAL_TIER` build tag

Unstable / internal:

- Ciphertext binary format (versioned via format version byte in wrapper)
- Specific `Display` tag strings (only error variants are stable)
- Generated code shape from `mask!` expansion
- `litmask-build`'s internal API
- `MaskKey` and other internal types

#### §1.12.2 Format versioning

The encrypted `mask_key` wrapper includes a 1-byte format version (§1.7.3).
Runtime checks the version on decryption and produces
`InitError::UnsupportedFormat` on mismatch. Future format changes can
break-and-error with a clear signal rather than silently corrupting.

#### §1.12.3 Internals marking

Public items required by macro expansion but not part of the stable API are
marked `#[doc(hidden)]` and documented as "internal — used by macro
expansion, do not call directly."

#### §1.12.4 MSRV

Minimum supported Rust version: **1.88**.

Subject to review before v1.0 release. If `let` chains and the new
`proc_macro::Span` API are not load-bearing in the implementation, MSRV drops
to **1.81** (the version that stabilized `core::error::Error`, which is
required for `no_std` error type implementations).

MSRV increases are minor-version bumps following the Rust Project's
recommended convention. Consumers concerned about MSRV stability may pin to
specific versions.

### §1.13 Feature Flags

| Feature | Default | Purpose |
|---|---|---|
| `std` | yes | Standard library support; disabling = `no_std + alloc` |
| `chacha20-poly1305` | yes | Default cipher |
| `aes-gcm` | no | Use AES-256-GCM instead of ChaCha20-Poly1305 (takes precedence when both cipher features are enabled) |
| `alloc` | no | Marks the `no_std + alloc` build target (pulls in the default cipher) |
| `machine-id` | no | `init!(bind_to_machine)` machine-ID binding (pulls in `machine-uid`; implies `std`) |

`std` and `no_std` are not mutually exclusive features (Cargo can't enforce
that); disabling `std` enables `no_std + alloc` mode. Pure `core` (no
allocator) is not supported in v1. Because Cargo unifies features, the
single-cipher (`CURRENT_CIPHER`) selection of §1.5.1 resolves to `aes-gcm`
whenever that feature is enabled; for a strict single-cipher dependency
tree (no ChaCha20-Poly1305 crate linked), build with
`--no-default-features --features aes-gcm`.

### §1.14 Dependencies

Internal crate (`litmask-internal`) — the shared wire format and crypto
primitives the other crates build on:

- `chacha20poly1305` / `aes-gcm` (RustCrypto AEAD, selected by cipher feature)
- `base64ct` (constant-time base64url)
- `blake3` (key + nonce derivation)
- `zeroize` (key zero-on-drop)

Runtime crate (`litmask`):

- `litmask-internal` (wire format, AEAD, KDF), `litmask-macros` (the
  re-exported proc-macros)
- `zeroize` (`UnlockKey`/`MaskKey` zero-on-drop)
- `once_cell` (`race`/`alloc` features, backing the `no_std` once-cell)
- `machine-uid` (behind `machine-id`), `serde` (behind `unstable-serde`)

Proc-macro crate (`litmask-macros`, re-exported by `litmask`):

- `proc-macro2`, `quote`, `syn` (proc-macro authoring)
- `litmask-internal`, `blake3`, `zeroize` (AEAD-encrypt each literal at
  expansion, derive the weak key, wipe build-time key material)

Build crate (`litmask-build`):

- `litmask-internal` (AEAD, KDF, wire format)
- `rand_chacha` / `rand_core` (seedable ChaCha20 CSPRNG for the mask key)
- `getrandom` (OS entropy for the seed)
- `zeroize` (wipe derived secrets)

CLI crate (`litmask-cli`):

- `clap` (argument parsing)
- `machine-uid` (the `show-machine-id` command)
- `getrandom` (the `keygen` command's randomness)
- `litmask-internal` (base64url encoding; the machine-id token codec)

The CLI exposes `keygen` (§2.9.2) and `show-machine-id` (§2.9.3), both
generate/read-only. With `bind`/`inspect` removed there is no wrapper to
re-encrypt or config to read; the only crypto it touches is BLAKE3 (via
`litmask-internal`) for the machine-id token's check group.

The Rust crypto stack is RustCrypto, not `ring`. Rationale: pure-Rust modular
crates support `no_std`, are easier to audit per-component, and have no C
dependency. Performance differences are immaterial at the scale of
string-literal decryption.

### §1.15 Known Risk Areas

These are sharp edges in the design that the implementer should approach
carefully:

1. **`#[mask_all]` substitution table coverage.** The hardcoded list of macro
   names cannot cover user-defined or third-party macros. Default behavior on
   unrecognized macros (skip with warning) is the safest disposition;
   `(strict)` mode forces explicit handling. Format-family rewrites must be
   context-sensitive (literal templates only; non-literal templates are left
   unchanged with literal arguments masked recursively).

2. **`mask_format!` named-argument single-evaluation semantics.** Every named
   argument MUST be bound to a `let` in the rewritten code so that
   side-effecting expressions evaluate exactly once. This is the most subtle
   correctness requirement in the parser. Implicit captures (Rust 2021
   `{var}` syntax) do NOT require `let` bindings — the captured local
   variable already exists in scope and is referenced positionally without
   rebinding.

3. **Reproducible build scope.** Bit-identity requires controlling for build
   path, toolchain version, and dependencies. The spec scopes reproducibility
   to "same toolchain, same source, same seed" — not full bit-identical
   reproducibility across machines.

4. **Machine-tier portability.** `machine-uid` behavior in
   containers, VMs, and re-imaged systems varies. OpenBSD by default has no
   `/etc/machine-id`. The factor must be readable at both build time (via
   `LITMASK_MACHINE_ID` / `show-machine-id`) and runtime (via the seam), or the
   seal and runtime diverge. The platform CI matrix (§1.10.5) exercises both the
   success and failure paths.

5. **Library-contributed plaintext.** The library ships short identifier-like
   strings (`Debug` variant names, `Display` tags) but no English error
   explanations. The "no plaintext in binary" property is "minimal,
   non-identifying plaintext" — see §1.9.3.

6. **Cross-compilation correctness.** Proc-macro runs on build host;
   encrypted blob is consumed on target. Endianness of the blob is
   irrelevant (opaque bytes), but verify no host-specific assumptions creep
   in.

7. **`mask_key` transport during build.** `mask_key` is written to a file in
   `OUT_DIR` and read by the proc-macro via `include_bytes!`. The plaintext
   `mask_key` MUST NOT appear in `cargo:rustc-env` directives or any other
   mechanism that records to `target/<profile>/build/<pkg>/output` or to
   terminal output.

8. **Tampering panic message hygiene.** Implementation must not inject
   custom message strings via `.expect("...")`, `panic!("...")`, or similar
   forms. `.unwrap()` is acceptable because its panic message comes from
   `std`, not from litmask. See §1.9.5 for the full policy.

---

## Part II — Requirements

Requirements are grouped by capability into iterations. Each requirement
describes one observable behavior, constraint, or property. Requirements are
numbered hierarchically: §2.X.Y identifies a sub-area within iteration X;
§2.X.Y.Z identifies a specific requirement within that sub-area.

Requirements reference canonical sources in Part I rather than restating
design content.

### §2.1 Iteration 1 — Core masking primitives

#### §2.1.0 Design principle: mirror stdlib grammar

Each `mask_*!` macro introduced in §2.1.3–§2.1.8 SHALL accept the
same input grammar as its stdlib counterpart insofar as the
masking semantics permit. Grammar parity gives users a drop-in
substitution at the call site: rewriting `env!("FOO")` to
`mask_env!("FOO")` requires no other source change.

Return types SHALL shift from `&'static`-bound forms to runtime-
owned forms (`String`, `Vec<u8>`, `Option<String>`) because masked
values are decrypted at runtime and cannot inhabit `'static`
storage. This is the only intentional API divergence from the
stdlib counterparts; spec §2.3.2.5 documents the corresponding
type-shift caveat for `#[mask_all]` rewrites.

Extensions to the stdlib grammar (e.g., accepting non-string
literals in `mask_concat!`, accepting the optional second-arg
custom error message in `mask_env!`) are tracked in the per-macro
subsections and are justified by this principle: the goal is a
strict superset where possible, a strict subset only where masking
demands it.

#### §2.1.1 mask! macro

§2.1.1.1 — `mask!` SHALL accept a single string literal, byte string literal,
or C string literal as its sole argument.

§2.1.1.2 — When given a string literal (`"..."`, `r"..."`, `r#"..."#`),
`mask!` SHALL return a value of type `String` containing the literal's
content.

§2.1.1.3 — When given a byte string literal (`b"..."`, `br"..."`), `mask!`
SHALL return a value of type `Vec<u8>` containing the literal's bytes.

§2.1.1.4 — When given a C string literal (`c"..."`), `mask!` SHALL return a
value of type `CString` containing the literal's bytes followed by a NUL
terminator.

§2.1.1.5 — `mask!` SHALL produce a compile error when given a literal of any
other type (e.g., integer, float, bool, char), a non-literal expression, or
any macro invocation. Use the dedicated `mask_include_str!` / `mask_concat!` /
`mask_env!` macros for compile-time-resolving inputs.

§2.1.1.6 — Invalid literal types SHALL be rejected with the
`mask! non-literal` tag (§1.9.6).

§2.1.1.7 — Each `mask!` invocation SHALL produce ciphertext using a unique
nonce derived per §1.5.2.

§2.1.1.8 — Two builds with the same source code, same toolchain, same
dependencies, and same `LITMASK_RNG_SEED` SHALL produce byte-identical
ciphertext for each `mask!` invocation. The reproducibility holds across
filesystem checkouts at different absolute paths because the nonce
derivation hashes a `CARGO_MANIFEST_DIR`-relative file path (§1.5.2).

§2.1.1.9 — `mask!` SHALL NOT be usable in `const` or `static` initializers.
The compile error SHALL come from rustc's natural `E0015` diagnostic; the
proc-macro SHALL NOT emit its own substring for this position. See §1.9.6 for rationale.

§2.1.1.10 — `mask!` SHALL NOT be usable in pattern positions (match arms,
`if let`, `while let`). The compile error SHALL come from rustc's natural
`expected pattern, found {` diagnostic; the proc-macro SHALL NOT emit its
own substring for this position. See §1.9.6 for rationale.

§2.1.1.11 — Decryption failure on a `mask!` invocation SHALL panic per the
policy in §1.9.5.

§2.1.1.12 — Calling `mask!` before any `litmask::init!(...)`
on an **Embedded**-sealed build SHALL trigger lazy initialization using the
default keyless `EmbeddedProvider` (`unlock_key` recomputed from the wrapper's
cleartext nonce). The `mask!` expansion SHALL carry the build-sealed
`LITMASK_SEAL_TIER` tag into the runtime so the lazy path can gate on it.

§2.1.1.12a — On a build sealed above the Embedded floor (`external`, `machine`,
`machine_external`), a `mask!` reached with no governing provider installed
(i.e. before the matching `init!(...)`) SHALL NOT lazy-derive the Embedded
`unlock_key`. It SHALL panic per §1.9.5, naming the init-ordering cause (a
higher tier requires a governing `init!(...)` before the first `mask!()`). This
prevents the wrong-key lazy derive from surfacing as a generic
wrapper-decryption failure that hides the real cause. (Conversely, when a
governing provider IS installed, the lazy path unlocks every wrapper through it
regardless of tier — see §1.4.1.)

§2.1.1.13 — Lazy initialization failure SHALL panic per the policy in §1.9.5.

#### §2.1.2 unmasked! macro

§2.1.2.1 — `unmasked!` SHALL accept a single string, byte string, or C string
literal and SHALL expand to that literal unchanged.

§2.1.2.2 — `unmasked!` SHALL preserve the literal's original type:

- string literal → `&str`
- byte string literal → `&[u8; N]`
- C string literal → `&CStr`

§2.1.2.3 — `unmasked!` SHALL be recognized by `#[mask_all]` and
`#[mask_all(strict)]` as an explicit opt-out of masking.

§2.1.2.4 — `unmasked!` SHALL produce no runtime overhead beyond the literal it
contains.

#### §2.1.3 mask_include_str! macro

§2.1.3.1 — `mask_include_str!(<path>)` SHALL accept a single string-literal
argument naming a UTF-8 file path. The path SHALL be resolved exactly as
stdlib `include_str!` resolves it: relative to the directory of the source
file containing the invocation (via `proc_macro::Span::file()`), so
`mask_include_str!` is a drop-in replacement for `include_str!`.

§2.1.3.2 — The macro SHALL read the file at proc-macro time, AEAD-encrypt
its contents per §1.5.2, and expand to a runtime decrypt call returning a
value of type `String`.

§2.1.3.3 — Non-string-literal argument SHALL be rejected with the
`mask_include_str! non-literal` tag (§1.9.6).

§2.1.3.4 — File-read failure at proc-macro time SHALL be rejected with the
`mask_include_str! read-failure` tag (§1.9.6).

§2.1.3.5 — File contents SHALL be absent from the compiled binary's
plaintext (`strings` output) under the same scrub policy as bare
`mask!()` invocations.

#### §2.1.4 mask_include_bytes! macro

§2.1.4.1 — `mask_include_bytes!(<path>)` SHALL accept a single string-
literal argument naming a file path. Path resolution mirrors §2.1.3.1.

§2.1.4.2 — The macro SHALL read the file at proc-macro time as raw
bytes (no UTF-8 validation), AEAD-encrypt the bytes per §1.5.2, and
expand to a runtime decrypt call returning a value of type `Vec<u8>`.

§2.1.4.3 — Non-string-literal argument SHALL be rejected with the
`mask_include_bytes! non-literal` tag (§1.9.6).

§2.1.4.4 — File-read failure at proc-macro time SHALL be rejected with the
`mask_include_bytes! read-failure` tag (§1.9.6).

§2.1.4.5 — File contents SHALL be absent from the compiled binary's
plaintext under the standard scrub policy.

#### §2.1.5 mask_concat! macro

§2.1.5.1 — `mask_concat!(<args>...)` SHALL accept a comma-separated
list of arguments. The grammar mirrors stdlib `concat!` per §2.1.0:
each argument MUST be one of:

- A string literal (`"…"`, `r"…"`, `r#"…"#`) — value used verbatim.
- An integer literal (`42`, `7u32`) — stringified via `base10_digits()`.
- A float literal (`2.5`, `0.0f64`) — stringified via `base10_digits()`.
- A bool literal (`true`, `false`) — stringified to `"true"` /
  `"false"`.
- A char literal (`'a'`, `'\n'`) — stringified to the character's
  UTF-8 form.
- A unary-negated numeric literal (`-3`, `-2.5`) — stringified with a
  leading `-`.
- A further `concat!(<args>...)` invocation — recursively resolved.
- An `include_str!(<path>)` invocation — file contents.
- An `env!(<name>)` invocation — build-time-required env var.

Byte-string (`b"..."`), C-string (`c"..."`), and byte (`b'X'`)
literals SHALL be rejected, mirroring stdlib `concat!`'s grammar.

§2.1.5.2 — The macro SHALL recursively resolve all arguments at
proc-macro time, concatenate the resulting strings, AEAD-encrypt the
concatenated value per §1.5.2, and expand to a runtime decrypt call
returning a value of type `String`.

§2.1.5.3 — Arguments not matching §2.1.5.1 — including
`unmasked!(...)` (which by intent opts OUT of masking, the logical
opposite of `mask_concat!`'s job) — SHALL be rejected with the
`mask_concat! invalid-arg` tag (§1.9.6).

§2.1.5.4 — An empty argument list (`mask_concat!()`) SHALL yield the
empty string `""`, mirroring stdlib `concat!()`. It SHALL NOT be a
compile error.

§2.1.5.5 — A nested `env!` SHALL surface its own failure to the user —
both the unset-variable case and the set-but-not-valid-UTF-8 case — per
§1.9.6.

#### §2.1.6 mask_env! macro

§2.1.6.1 — `mask_env!` SHALL accept one or two string-literal
arguments, mirroring stdlib `env!`'s grammar per §2.1.0:

- `mask_env!("NAME")` — read env var `NAME` at proc-macro time.
- `mask_env!("NAME", "custom error message")` — same as above; the
  second arg is used as the compile-error text when `NAME` is
  unset. When `NAME` is set, the second arg is ignored.

§2.1.6.2 — At proc-macro time, the macro SHALL read the named env var
from the build environment. When set, the macro SHALL AEAD-encrypt
the value and expand to a runtime decrypt call returning a value of
type `String`.

§2.1.6.3 — When the named env var is unset at proc-macro time, the
macro SHALL produce a compile error. The error text SHALL be the
custom second-arg message verbatim when provided; otherwise the macro
SHALL be rejected with the `mask_env! unset` tag (§1.9.6).

§2.1.6.4 — When the named env var is set but its value is not valid
UTF-8, the macro SHALL be rejected with the `mask_env! unicode-failure`
tag (§1.9.6), distinct from §2.1.6.3 so users can tell the two failure
modes apart.

§2.1.6.5 — Non-string-literal argument (or extra arguments beyond
the two-arg form) SHALL be rejected with the `mask_env! non-literal`
tag (§1.9.6).

#### §2.1.7 mask_option_env! macro

§2.1.7.1 — `mask_option_env!(<name>)` SHALL accept a single string-
literal argument naming a build-time environment variable.

§2.1.7.2 — At proc-macro time, the macro SHALL read the named env var.
When set, expand to a runtime expression returning `Some(<masked
String>)`. When unset, expand to a runtime expression returning
`None::<String>` with no embedded ciphertext.

§2.1.7.3 — `mask_option_env!` SHALL NOT produce a compile error for an
unset env var. The unset case is a legitimate runtime `None`, mirroring
stdlib `option_env!`'s contract.

§2.1.7.4 — Non-string-literal argument SHALL be rejected with the
`mask_option_env! non-literal` tag (§1.9.6).

#### §2.1.8 mask_file! macro

§2.1.8.1 — `mask_file!()` SHALL accept no arguments. Any input tokens
SHALL be rejected with the `mask_file! args-not-allowed` tag (§1.9.6).

§2.1.8.2 — At proc-macro time, the macro SHALL read
`proc_macro::Span::call_site().file()`, AEAD-encrypt that value
unchanged, and expand to a runtime decrypt call returning a value of
type `String`. The returned value SHALL equal stdlib `file!()` at the
same call site, so `mask_file!` is a drop-in replacement. (The
`CARGO_MANIFEST_DIR`-stripping of §1.5.2 applies only to nonce
derivation, never to the value handed back to the caller.)

§2.1.8.3 — The raw source path SHALL be absent from the compiled
binary's plaintext under the standard scrub policy. (Caveat:
`core::panic::Location::caller()` independently embeds source paths at
panic sites; `mask_file!` masks only its own explicit user-written
invocations, not the implicit panic-site embedding.)

#### §2.1.9 mask_stack! macro (`unstable-stack` feature)

Status: **EXPERIMENTAL**. Gated by the `unstable-stack` feature; the
`unstable-` prefix is the semver-exemption signal (this surface may change
or be removed in any release). Deliberately undocumented in the README and
ARCHITECTURE until a real use case promotes it; stabilization renames the
feature to `stack` (a breaking change by design). Its headline no-alloc
property is not yet realized — the crate still links `alloc` unconditionally,
so a fully heapless build does not exist today. Promotion to stable is
governed by the shared bar in
[ADR-0002](adr/0002-experimental-feature-promotion.md); the support matrix
for this feature lives here and is its exit checklist.

§2.1.9.1 — `mask_stack!` SHALL accept the same three literal kinds as
`mask!` (§2.1.1.1) and SHALL be gated behind the `unstable-stack` cargo
feature.

§2.1.9.2 — Rather than the heap owned values of §2.1.1.2–§2.1.1.4,
`mask_stack!` SHALL expand to a guard owning an inline `[u8; N]` whose
length `N` is fixed at expansion: `MaskStr<N>` (derefs to `str`) for a
string literal, `MaskBytes<N>` (derefs to `[u8]`) for a byte-string
literal, and `MaskCStr<N>` (derefs to `core::ffi::CStr`) for a C-string
literal. The decrypted plaintext SHALL NOT be heap-allocated, and the
buffer SHALL be zeroized when the guard drops.

§2.1.9.3 — Decryption SHALL reuse the §2.1.1 governed/lazy unlock path;
`mask_stack!` and `mask!` differ only in the final decrypt-and-construct
step, so a build's seal tier governs both identically.

§2.1.9.4 — A literal whose inline buffer would exceed the
`LITMASK_STACK_LIMIT` byte cap (default 4096; overridable via that
environment variable) SHALL be rejected at proc-macro time with a
`compile_error!`. The cap guards against unbounded stack growth; large
literals belong on the heap `mask!`.

§2.1.9.5 — `MaskCStr` SHALL borrow `core::ffi::CStr` from its own buffer
(with the NUL terminator the blob omits restored at decrypt time) rather
than constructing a `CString`, so `mask_stack!(c"...")` needs no allocator
_at the call site_ — unlike heap `mask!(c"...")`, which requires `CString`
(§2.1.1.4). This is an API-shape property only: the `litmask` crate still
links `alloc` unconditionally today (see §2.1.9 status), so it does NOT yet
yield a fully heapless build.

### §2.2 Iteration 2 — Format string masking (mask_format!)

`mask_format!` mirrors the `mask_<stdlib_macro>` naming convention per
§2.1.0: stdlib's macro is `format!`, so the masked counterpart spells
out `format`. The bare `mask_fmt!` name SHALL NOT exist in the public
API.

#### §2.2.1 Acceptance criteria

§2.2.1.1 — `mask_format!` SHALL accept a string literal template as its first
argument, followed by zero or more format arguments matching `format!`'s
signature.

§2.2.1.2 — `mask_format!` SHALL return a value of type `String`.

§2.2.1.3 — `mask_format!` SHALL produce a compile error when its first argument is
not a string literal.

§2.2.1.4 — The compile error for non-literal templates SHALL include the
substring required by §1.9.6.

#### §2.2.2 Rewriting behavior

§2.2.2.1 — The literal template fragments (text between placeholders) SHALL be
masked individually using the same encryption as `mask!`.

§2.2.2.2 — Placeholder names (named arguments, implicit captures) SHALL NOT
appear in the compiled binary; the rewrite SHALL convert all named/implicit
references to positional references.

§2.2.2.3 — Named arguments (`format!("{x}", x = expr)` form) SHALL be
evaluated exactly once. The rewritten code MUST introduce a `let` binding for
each named argument before the `format!` invocation, capturing `expr`'s
result once.

§2.2.2.4 — Implicit-capture format placeholders (Rust 2021 `{var}` syntax
with no corresponding named argument) SHALL be rewritten to positional
references to the existing `var` local variable. No new `let` binding is
introduced for implicit captures because the variable already exists in
scope, and a variable reference is naturally evaluation-once.

§2.2.2.5 — Format specifications (`{:>10}`, `{:.3}`, `{:#x}`, etc.) SHALL be
preserved verbatim in the rewritten format string.

§2.2.2.6 — Dynamic width and precision (`{:>width$}`, `{:.prec$}`) SHALL be
supported with positional rewriting.

§2.2.2.7 — Debug formatting (`{:?}`, `{:#?}`) SHALL be supported.

§2.2.2.8 — The output of `mask_format!(template, args...)` SHALL be identical to
the output of `format!(template, args...)` for all supported format
features.

#### §2.2.3 Equivalent format! semantics

§2.2.3.1 — `mask_format!` SHALL NOT introduce observable differences from
`format!` in argument evaluation order, evaluation count, or panicking
behavior.

§2.2.3.2 — `mask_format!` SHALL pass through `format!`'s compile-time format
argument checking (placeholder count vs. argument count, type compatibility).

### §2.3 Iteration 3 — Module-level masking

#### §2.3.1 #[mask_all] attribute

§2.3.1.1 — `#[mask_all]` SHALL be applicable to module items
(`mod foo { ... }`).

§2.3.1.2 — When applied, `#[mask_all]` SHALL recursively rewrite string
literal, byte string literal, and C string literal expressions within the
module according to the substitution table in §2.3.2.

§2.3.1.3 — `#[mask_all]` SHALL skip literals in the following positions
without modification:

- Pattern positions (match arms, `if let`, `while let`)
- `const` and `static` initializers
- Attribute strings (`#[doc = "..."]`, `#[cfg(...)]`, etc.)
- Inside `mask!`, `mask_format!`, or `unmasked!` invocations

§2.3.1.4 — `#[mask_all]` SHALL emit a compile-time warning for each literal
it skips, identifying the file, line, and reason for the skip.

Until `proc_macro::Diagnostic::emit` stabilizes on stable Rust, the warning
emission mechanism is the **ghost-deprecation hack**. For each skip, the
proc-macro SHALL inject an unused item of the form

```rust
#[deprecated(note = "litmask: skipped literal at <file>:<line>: <reason>")]
#[allow(dead_code)]
const _LITMASK_SKIP_<n>: () = ();
let _ = _LITMASK_SKIP_<n>;
```

into the rewritten output, where `<n>` is a per-module monotonic counter
ensuring uniqueness and `<reason>` is a short ASCII tag (e.g.,
`pattern_position`, `const_initializer`, `unrecognized_macro`). The `let _`
reference triggers rustc's `deprecated` lint, which surfaces as a normal
`warning: use of deprecated constant _LITMASK_SKIP_<n>: litmask: skipped
literal at ...` in cargo output. Under `#[mask_all(strict)]`, the proc-macro
SHALL substitute `compile_error!("litmask: ...")` for the ghost-item pattern
so the same skip becomes a hard error. Migration to `Diagnostic::emit` is a
v2 candidate; the warning text format above is normative and is pinned by
the `tests/compile/mask_all_*_warning.stderr` snapshots, so a wording edit
is caught and surfaces as a deliberate, reviewed change.

§2.3.1.5 — `#[mask_all]` SHALL recurse into nested modules, functions,
blocks, and closures within the attributed module.

§2.3.1.6 — `#[mask_all]` SHALL NOT see code emitted by other macros
expanding within its module (proc-macro expansion is outside-in; derives
expand after attribute proc-macros).

#### §2.3.2 Substitution table

§2.3.2.1 — Bare string literal expressions SHALL be rewritten to
`mask!(literal)`.

§2.3.2.2 — `format!(template, args...)` SHALL be rewritten as follows:

- If `template` is a string literal: rewrite to `mask_format!(template, args...)`.
- If `template` is not a string literal: leave `format!` unchanged;
  recursively mask any string-literal arguments in `args...`. Emit a
  compile-time warning identifying the unmasked template.

§2.3.2.3 — Output macros (`println!`, `eprintln!`, `print!`, `eprint!`,
`write!`, `writeln!`) SHALL be rewritten as follows:

- If their template is a string literal: rewrite to
  `{ let __s = mask_format!(template, args...); <original_macro>("{}", __s) }`,
  preserving the original return type and side effects.
- If their template is not a string literal: leave the macro unchanged;
  recursively mask any string-literal arguments. Emit a compile-time warning.

§2.3.2.4 — Panic macros (`panic!`, `todo!`, `unimplemented!`,
`unreachable!`, and `assert!`/`assert_eq!`/`assert_ne!` with custom message
form) SHALL be rewritten analogously to §2.3.2.3, wrapping the masked format
result in a literal `"{}"` template when the original template is a literal;
otherwise left unchanged with literal arguments masked recursively.

§2.3.2.5 — The following
stdlib macros SHALL be rewritten to their dedicated `mask_*!`
counterparts (§2.1.3–§2.1.8):

| Original | Rewritten to |
|---|---|
| `include_str!(<path>)` | `mask_include_str!(<path>)` |
| `include_bytes!(<path>)` | `mask_include_bytes!(<path>)` |
| `concat!(<args>...)` | `mask_concat!(<args>...)` |
| `env!(<name>)` | `mask_env!(<name>)` |
| `option_env!(<name>)` | `mask_option_env!(<name>)` |
| `file!()` | `mask_file!()` |

`#[mask_all]` SHALL emit these rewrites directly; no intermediate
`mask!(...)` wrapping is required.

Excluded from rewriting:

- `cfg!(<predicate>)` — stdlib `cfg!()` resolves to a compile-time
  `bool` with no `.rodata` residue, so masking adds runtime cost
  for zero metadata reduction.
- `module_path!()` — `proc_macro::Span` does not expose a
  `module_path()` accessor on stable Rust, so proc-macro-time
  resolution is unreachable; the macro is left as-is. The
  `core::panic::Location::caller()` machinery embeds source paths
  at panic sites by rustc's own emission, outside the proc-macro's
  reach — `mask_file!` documents this caveat (§2.1.8.3).

§2.3.2.6 — `dbg!`, `stringify!`, `debug_assert!`/`debug_assert_eq!`/`debug_assert_ne!`,
`assert_eq!`/`assert_ne!` (without custom message) SHALL be skipped without
modification. The `debug_assert` family is excluded because release builds
dead-code-eliminate the body, so masking would add runtime cost for no
release-binary benefit.

§2.3.2.7 — User-defined or unrecognized macros SHALL have their literal
arguments left unmasked, with a compile-time warning per skipped literal.

#### §2.3.3 Strict mode

§2.3.3.1 — `#[mask_all(strict)]` SHALL upgrade all warnings emitted by
§2.3.1.4, §2.3.2.2 (non-literal template), §2.3.2.3 (non-literal template),
§2.3.2.4 (non-literal template), and §2.3.2.7 to compile errors.

§2.3.3.2 — Under `#[mask_all(strict)]`, every string literal in the
attributed module MUST be either masked by the substitution table or
explicitly marked with `unmasked!()`.

### §2.4 Iteration 4 — Build pipeline

#### §2.4.1 build.rs integration

§2.4.1.1 — `litmask-build::emit()` SHALL be invocable as a one-line
`build.rs`.

§2.4.1.2 — `emit()` SHALL determine the build profile from the `PROFILE`
environment variable.

§2.4.1.3 — In debug profile, `emit()` SHALL source `RNG_SEED` in priority
order: `LITMASK_RNG_SEED` env var, then `target/<profile>/litmask_seed.bin`,
then generate fresh and persist to `target/<profile>/litmask_seed.bin`.

§2.4.1.4 — In release profile, `emit()` SHALL source `RNG_SEED` from
`LITMASK_RNG_SEED` env var if set; otherwise generate fresh and NOT persist.

§2.4.1.5 — `emit()` SHALL NOT print the seed, `unlock_key`, `mask_key`, or
any other secret to the build log (§D.1.2). Reproducible rebuilds rely on
the operator pinning `LITMASK_RNG_SEED` up front; there is no post-hoc
seed-recovery channel. The only sanctioned release-profile
`cargo:warning=` is the Embedded-floor notice (§1.3.2), which carries no
secret.

§2.4.1.6 — `emit()` SHALL generate `mask_key` deterministically from
`RNG_SEED` using `rand_chacha::ChaCha20Rng`. (`unlock_key` is not
seed-derived — it is nonce-derived for the Embedded tier and
provider/machine-sourced above it, per §1.3.1.)

§2.4.1.7 — `emit()` SHALL write the plaintext `mask_key` to a binary file at
`$OUT_DIR/litmask_key.bin` and the `RNG_SEED` to
`$OUT_DIR/litmask_seed.bin`, to be consumed by the proc-macro via
`include_bytes!`.

§2.4.1.8 — `emit()` SHALL NOT emit `mask_key` or `RNG_SEED` via
`cargo:rustc-env` directives, for the leakage reasons documented in §1.3.1.

§2.4.1.9 — `emit()` SHALL emit only the following Cargo directives:

- `cargo:rerun-if-env-changed=LITMASK_RNG_SEED`
- `cargo:rerun-if-env-changed=LITMASK_UNLOCK_KEY`
- `cargo:rerun-if-env-changed=LITMASK_MACHINE_ID`
- `cargo:rerun-if-changed=build.rs`
- `cargo:rustc-env=LITMASK_SEAL_TIER=<tier>` (the sole `LITMASK*`
  rustc-env value, §1.3.1)
- (release Embedded tier only) the `cargo:warning=` floor notice per §1.3.2

§2.4.1.10 — `emit()` SHALL NOT write the derived `unlock_key` (or any
secret key material) to disk; only the seed/key/wrapper blobs go to
`$OUT_DIR` and, under the debug profile, the persisted seed (§1.7.4,
§1.7.5).

#### §2.4.2 Configuration validation

§2.4.2.1 — `emit()` SHALL succeed without a project-level configuration
file; no `litmask.toml` or equivalent is read in v1.

### §2.5 Iteration 5 — Key providers

#### §2.5.1 KeyProvider trait

§2.5.1.1 — `KeyProvider` SHALL be a public trait with method
`unlock_key(&self) -> Result<UnlockKey, KeyError>`.

§2.5.1.2 — `KeyProvider` SHALL be object-safe (usable as
`Box<dyn KeyProvider>`) and `Send + Sync`, so a provider can be installed
as the process-global governing provider.

§2.5.1.3 — `UnlockKey` SHALL be a newtype wrapping `[u8; 32]` with `Drop`
zeroing its contents.

§2.5.1.4 — `UnlockKey` SHALL provide a `derive(material: &[u8])`
constructor that normalizes arbitrary-length material via
`KDF("litmask-unlock-v1", material)`, plus a constructor from `[u8; 32]`.
External-tier providers SHALL build their key through `derive`, never by
treating the material as an encoded key.

§2.5.1.5 — `KeyProvider` SHALL NOT have a `deployment_hint()` method or any
other method whose return value would embed English-language strings in
binaries that depend on `litmask`.

#### §2.5.2 EnvVarProvider

§2.5.2.1 — `EnvVarProvider::new(var_name: &'static str)` SHALL construct a
provider that reads from the named environment variable.

§2.5.2.2 — `EnvVarProvider::default()` SHALL read from `LITMASK_UNLOCK_KEY`.

§2.5.2.3 — `EnvVarProvider::unlock_key()` SHALL return:

- `Err(KeyError::NotFound)` if the env var is unset
- `Ok(UnlockKey)` otherwise, deriving the key from the variable's raw
  bytes via `UnlockKey::derive` after stripping a single trailing
  newline. Any byte sequence is accepted as material, so there is no
  `InvalidFormat` outcome.

#### §2.5.3 FileProvider

§2.5.3.1 — `FileProvider::new(path: impl Into<PathBuf>)` SHALL construct a
provider that reads the file's bytes as raw unlock material.

§2.5.3.2 — `FileProvider::unlock_key()` SHALL return:

- `Err(KeyError::NotFound)` if the file does not exist
- `Err(KeyError::Permission)` if the file exists but cannot be read
- `Ok(UnlockKey)` otherwise, deriving the key from the file's raw bytes
  via `UnlockKey::derive` after stripping a single trailing newline.
  File contents are material of any length, so there is no
  `InvalidFormat` outcome and no length check.

§2.5.3.4 — `FileProvider` SHALL zero its in-memory copy of file contents
immediately after extracting the key.

#### §2.5.4 MachineIdProvider (gated by `machine-id` feature)

§2.5.4.1 — `MachineIdProvider` SHALL be `pub(crate)`, with no public
constructor and no public type alias. A machine-sealed binary reaches it
only through the `init!(bind_to_machine)` seam (§2.6.1.8), which constructs it
in-crate from the embedded wrapper. The macro never names the type —
expansion lands in the consumer crate, which cannot reach a `pub(crate)`
symbol — so it is absent from the public API surface (§1.12.1).

§2.5.4.2 — `MachineIdProvider::new(wrapper: &[u8; WRAPPER_LEN])` SHALL
construct a provider capturing only the wrapper's cleartext nonce. The
machine salt is **not** caller-supplied: it is derived from this nonce on
demand (§2.5.4.3), so there is no `with_salt` constructor or runtime salt
parameter.

§2.5.4.3 — `MachineIdProvider::unlock_key()` SHALL:

- Read the machine ID via `machine-uid::get()`, holding it in a zeroizing
  buffer so the heap copy of the host identifier wipes on return
- Derive a 32-byte key via `derive_machine_id_key(context, salt_context,
  machine_id, wrapper_nonce)`, where the salt is
  `BLAKE3::derive_key(salt_context, wrapper_nonce)` and the key is
  `BLAKE3::derive_key(context, len(machine_id) || machine_id || salt)` with
  `len` an 8-byte little-endian length prefix preventing concatenation
  ambiguity. `context` and `salt_context` are passed through `weak_mask!`
  at the call site to keep both literals out of `strings(1)`; they MUST
  decode to `MACHINE_ID_DERIVATION_CONTEXT` and
  `MACHINE_ID_SALT_DERIVATION_CONTEXT` byte-for-byte.
- Return `Err(KeyError::Provider(...))` if `machine-uid` fails, lifting the
  upstream error's `Display` text into a `Send + Sync` wrapper
- Return `Ok(UnlockKey(derived_bytes))` otherwise

#### §2.5.5 EmbeddedProvider

`EmbeddedProvider` is `pub(crate)` — the internal mechanism behind the
keyless Embedded floor, not a consumer-facing provider. No `init!` form
takes it, and the lazy self-init path is its only caller (the wrapper bytes
it needs are internal).

§2.5.5.1 — `EmbeddedProvider::new(wrapper: &[u8; WRAPPER_LEN])` SHALL construct
the keyless floor provider, capturing only the wrapper's cleartext nonce
(no key material is stored).

§2.5.5.2 — `EmbeddedProvider::unlock_key()` SHALL recompute and return the
Embedded-tier `unlock_key` as `derive_embedded_unlock_key(context, nonce)` —
the same derivation `litmask-build` runs at seal time — so it always returns
`Ok(_)`. The BLAKE3 derivation `context` is passed through `weak_mask!` at the
call site to keep the literal out of `strings(1)` output; it MUST decode to
`EMBEDDED_UNLOCK_DERIVATION_CONTEXT` byte-for-byte.

### §2.6 Iteration 6 — Runtime initialization

#### §2.6.1 init functions

§2.6.1.1 — `litmask::init!(...)` SHALL install a process-global **governing
provider** (ADR-0001) and eagerly unlock the host's own wrapper through it,
returning `Result<(), InitError>`. As a proc-macro, `init!` SHALL select its
form from the macro argument: empty → a §1.9.6 `grammar` `compile_error!`
(bare `init!()` is removed; the Embedded tier self-initializes lazily), the
bare keyword `bind_to_machine` → Machine (§2.6.1.8), `bind_to_machine + <expr>`
→ MachineExternal, any other argument → External provider expression
(§2.6.1.2). It SHALL read the build's `LITMASK_SEAL_TIER` tag and emit a
§1.9.6 `init! tier-mismatch` `compile_error!` when the selected form's tier
does not match the sealed tier (or the tag is absent).

§2.6.1.2 — `litmask::init!(provider)` SHALL install the given External-tier
provider as the governor, returning `Result<(), InitError>`.

§2.6.1.8 — `litmask::init!(bind_to_machine)` SHALL install a machine
governor backed by the `pub(crate)` `MachineIdProvider` (§2.5.4),
constructed in-crate from each wrapper's nonce at consult time — the macro
never names the provider type. The expansion SHALL route through the
`__govern_machine_call!` macro, which carries a `machine-id`-feature-off
variant emitting a directed `compile_error!` (a `machine`-sealed build can
reach this arm with the feature disabled), satisfying §1.9.6.

Each form expands at the call site to read wrapper bytes via `include_bytes!`
from the caller's `OUT_DIR`, then forwards to a private
`__govern_*(provider, &wrapper_bytes)` seam in `litmask::__internal` whose
behavior matches the requirements below verbatim.

§2.6.1.3 — The govern seam SHALL install the governor (first install wins),
retrieve `unlock_key` for the host's wrapper via the governor, decrypt the
embedded `mask_key` wrapper (format per §1.7.3), and store the result in the
per-wrapper mask-key cache.

§2.6.1.4 — Successive calls to `init!(...)` after a successful one SHALL
return `Ok(())` without re-running the provider (idempotent; the first
installed governor wins and the host's wrapper is already cached).

§2.6.1.5 — Successive calls after a failed initialization SHALL retry the
provider call.

§2.6.1.6 — Lazy initialization (first `mask!()` for an uncached wrapper)
SHALL apply the lazy-unlock rule (§1.4.1): if a governing provider is
installed it supplies `unlock_key` for that wrapper regardless of tier;
otherwise the keyless Embedded floor self-unlocks, and a higher-tier seal
with no governor SHALL refuse per §2.1.1.12a. Lazy init failures result in panic per §2.1.1.13
rather than `Result` return.

§2.6.1.7 — Initialization failures SHALL return the `InitError` variants
defined in §1.9.2 according to their documented semantics.

#### §2.6.2 InitError methods

§2.6.2.1 — `InitError` SHALL provide a method
`pub fn sysexit_code(&self) -> i32` returning a sysexits.h-compatible exit
code per the mapping in §1.9.7.

§2.6.2.2 — Numeric constants used in `sysexit_code` SHALL be inline literals;
no external `sysexits` crate dependency is permitted.

### §2.7 Iteration 7 — Cipher implementations

§2.7.1 — Cipher selection SHALL follow the rules in §1.5.1: exactly one
cipher (`CURRENT_CIPHER`) seals and opens each build, selected by the
`aes-gcm` Cargo feature.

§2.7.2 — Encryption and decryption operations SHALL use the cipher
implementation crate specified in §1.5.1 (`chacha20poly1305` or `aes-gcm`)
without modification or wrapper.

§2.7.3 — Per-string ciphertext blob format SHALL match §1.7.2.

§2.7.4 — Encrypted `mask_key` wrapper format SHALL match §1.7.3.

§2.7.5 — Per-string nonces SHALL be derived per §1.5.2.

§2.7.6 — The encrypted `mask_key` wrapper nonce SHALL be derived per §1.7.3.

§2.7.7 — Decryption operations MUST verify the AEAD authentication tag and
return an error on verification failure.

§2.7.8 — Format version byte in the wrapper SHALL be `0x01` for v1.

§2.7.9 — No cipher identifier SHALL appear on the wire (§1.7.3): the cipher
is a compile-time property (`CURRENT_CIPHER`), and every wrapper and blob in
a binary uses the single cipher the build was compiled for.

§2.7.10 — Nonce derivation SHALL NOT depend on global state shared between
proc-macro expansions; each invocation derives its nonce solely from its
source location and the build seed.

### §2.8 Iteration 8 — Binary embedding format

#### §2.8.1 Binary embedding

§2.8.1.1 — The encrypted `mask_key` wrapper SHALL be embedded in the
compiled binary as an ordinary `[u8; 61]` static, with no `#[link_section]`,
no `#[no_mangle]` marker, and no symbol name suggesting `litmask`.

§2.8.1.2 — The runtime SHALL obtain the wrapper bytes from a fixed,
compiler-known location (`include_bytes!` over the build's `OUT_DIR`
artifact), not by scanning the binary; there is no in-binary locator.

§2.8.1.3 — Per-string encrypted blobs (output of `mask!` invocations) SHALL
be embedded similarly as ordinary statics with no identifying markers, no
fixed header bytes, and no symbol naming convention attributable to
`litmask`.

#### §2.8.2 No persisted key material

§2.8.2.1 — No build SHALL persist the derived `unlock_key` (or any secret
key) to disk for any tier (§1.7.4). The Embedded tier recomputes it from
the wrapper nonce; the keyed tiers re-source their material at runtime.

### §2.9 Iteration 9 — CLI tooling

CLI exit codes follow the sysexits.h mapping documented in §1.9.7. The CLI's
own non-litmask-specific failures follow standard sysexits conventions:
argument-parsing errors exit EX_USAGE (64). The v1 subcommands read no input
files, so no file-I/O exit code (e.g. EX_NOINPUT) arises.

#### §2.9.1 CLI surface

§2.9.1.1 — In v1 the CLI SHALL expose exactly two subcommands, `keygen`
(§2.9.2) and `show-machine-id` (§2.9.3). There is no `bind` or `inspect`
subcommand: machine-tier keying is established at build time via
`init!(bind_to_machine)` (§2.5.4, §2.6.1.8), not by patching a finished binary,
so no post-build rebind tool exists. Both subcommands are generate/read-only;
neither mutates a binary.

§2.9.1.2 — The CLI is a build/deployment tool and is never shipped in a
release binary, so the no-identifying-strings rule (§1.9) does NOT apply to
it.

#### §2.9.2 litmask keygen

§2.9.2.1 — `litmask keygen` SHALL print exactly 32 bytes of
cryptographically secure randomness, base64url-encoded without padding
(43 characters), to stdout followed by a single newline, and exit EX_OK (0).
It SHALL write nothing to stdout other than the key and SHALL write nothing
to stderr on success, so `litmask keygen | <consumer>` yields a clean,
pipeable value.

§2.9.2.2 — The value serves equally as a `LITMASK_UNLOCK_KEY` for the
external tier (§1.6) or as a per-customer build seed; the role is usage, not
format. The external tier accepts arbitrary material via
`KDF("litmask-unlock-v1", material)` (§1.6.3), so a keygen value is usable
without further encoding.

§2.9.2.3 — If the OS randomness source is unavailable, `keygen` SHALL print
a human-readable diagnostic to stderr (leaving stdout empty) and exit
EX_UNAVAILABLE (69).

§2.9.2.4 — `keygen` SHALL take no arguments and SHALL NOT modify any file.

#### §2.9.3 litmask show-machine-id

§2.9.3.1 — `litmask show-machine-id` SHALL print this host's machine ID as a
**self-checking token** to stdout and exit EX_OK (0). The token is
`raw_id ‖ "." ‖ check`, where `check` is the base64url encoding of the first
five bytes of `BLAKE3(raw_id)`. The raw id is the exact bytes the machine
tier feeds into its key derivation (§1.7.5) — a non-secret host identifier
that lets an operator seal a binary against this host (`LITMASK_MACHINE_ID`
at build time, §1.6).

§2.9.3.2 — The check group rides **in-band** in the stdout token, never on a
separate stream: an operator copies stdout, so a stderr checksum would be
dropped by the copy channel. Any human guidance SHALL be written to stderr
only, keeping a piped capture limited to the token itself.

§2.9.3.3 — `litmask-build::emit()` SHALL accept the token form on
`LITMASK_MACHINE_ID`, validating the check group and recovering the raw id
before deriving the machine key. A value whose check group does not match,
or that carries no check group, SHALL be rejected at build time — turning a
mistyped id into an actionable build error rather than an opaque runtime
`init` failure on the deploy host. A single trailing newline is stripped
before validation, so a token sourced through a newline-bearing channel
still validates.

§2.9.3.4 — If the machine ID cannot be read, `show-machine-id` SHALL print a
human-readable diagnostic to stderr (leaving stdout empty) and exit
EX_UNAVAILABLE (69).

§2.9.3.5 — `show-machine-id` SHALL take no arguments and SHALL NOT modify any
file.

### §2.10 Iteration 10 — no_std support

§2.10.1 — The `litmask` crate SHALL be `#![no_std]`-compatible when the
`std` feature is disabled, requiring only `alloc`.

§2.10.2 — The proc-macro itself SHALL be unconditionally `std` (it runs on
the build host).

§2.10.3 — Pure `core` (no allocator) is NOT supported in v1.

§2.10.4 — `EnvVarProvider` and `FileProvider` SHALL be gated behind the
`std` feature.

§2.10.5 — `std::error::Error` impls SHALL be gated behind `std`.
`core::error::Error` impls SHALL be available unconditionally; this is the
trait stabilized in Rust 1.81.

§2.10.6 — `OnceLock`-equivalent functionality on `no_std` SHALL use
`once_cell::race::OnceBox` or equivalent.

### §2.11 Iteration 11 — Documentation

§2.11.1 — Documentation artifacts listed in §1.11.1 SHALL be present in v1
release.

§2.11.2 — Documentation content SHALL meet the requirements in §1.11.2,
including the security level table from §1.1.4 and the "what does NOT
protect against" section.

§2.11.3 — `THREAT_MODEL.md` SHALL document the in-scope and out-of-scope
attacker capabilities from §1.1.2 and §1.1.3, and the init-failure plaintext
limitation from §1.9.4.

§2.11.4 — `DEPLOYMENT.md` SHALL include a sysexits.h code reference table
mirroring §1.9.7.

§2.11.5 — Every public API item SHALL have rustdoc with at least one usage
example.

§2.11.6 — `MIGRATION.md` SHALL cover migration from `litcrypt` (v1 and v2)
and `obfstr`, with side-by-side API comparisons.

§2.11.7 — All documentation SHALL meet the tone requirements in §1.11.3.

### §2.12 Iteration 12 — Testing infrastructure

#### §2.12.1 Test tier coverage

§2.12.1.1 — The implementation SHALL provide tests in all five tiers
described in §1.10.

§2.12.1.2 — Unit tests (§1.10.1) SHALL cover: cipher wrappers, all built-in
`KeyProvider` implementations, `KeyError` handling, base64url encoding,
nonce derivation per §1.5.2 and §1.7.3, and the sysexits mapping in §1.9.7.

§2.12.1.3 — Compile tests (§1.10.2) SHALL cover all macro families in the
substitution table of §2.3.2, including both literal-template and
non-literal-template variants where applicable, and SHALL verify the error
message text required by §1.9.6.

§2.12.1.4 — Integration tests (§1.10.3) SHALL build example binaries and
verify the following testable assertions:

- `strings` output of compiled binaries contains no high-entropy plaintext
  used in test fixtures (the canonical security-property check)
- All built-in `KeyProvider`s succeed end-to-end against valid configurations
- Tampering with any ciphertext byte causes AEAD authentication failure
- Reproducible builds with fixed `LITMASK_RNG_SEED` produce byte-identical
  artifacts under the conditions in §1.3.3
- A machine-tier build (`LITMASK_MACHINE_ID` set, `init!(bind_to_machine)`) runs
  correctly on the sealed host and the wrong-host failure path surfaces as
  an `InitError`
- `InitError::sysexit_code()` returns the values specified in §1.9.7 for
  each variant

§2.12.1.5 — Integration tests SHALL include at least one example binary per
`KeyProvider`.

§2.12.1.6 — Fuzz targets (§1.10.4) SHALL include `parse_format_template`
(mask_format parser). CI SHALL run it for at least 10 seconds per PR. Fuzz
corpora SHALL be committed to the repository and grow from CI findings.

### §2.13 Iteration 13 — Platform support and CI

#### §2.13.1 CI matrix

§2.13.1.1 — CI SHALL execute the per-platform smoke test sequence (§2.13.2)
on each platform listed in §1.10.5.

§2.13.1.2 — All platform jobs SHALL run on every PR. Failure of any platform
job SHALL block PR merge unless the failure is attributed to CI provider
flakiness and subsequently re-runs successfully.

§2.13.1.3 — Platforms NOT in the §1.10.5 CI matrix are not formally supported
in v1. They may work but are not validated.

#### §2.13.2 Per-platform smoke test requirements

§2.13.2.1 — Each platform smoke test SHALL build a test binary embedding at
least one high-entropy unique marker (e.g., a UUID-formatted string)
embedded via `mask!`.

§2.13.2.2 — Each platform smoke test SHALL run `strings` (or equivalent) on
the test binary and assert that no embedded marker appears in the output. If
any marker is found, the job SHALL fail.

§2.13.2.3 — On platforms where `machine-uid` produces a stable identifier
(Ubuntu, AlmaLinux, macOS, Windows, FreeBSD, and OpenBSD instances with
provisioned machine ID), a machine-tier binary (built with
`LITMASK_MACHINE_ID` equal to the host's `show-machine-id` and initialized
via `init!(bind_to_machine)`) SHALL execute correctly with output matching
expected plaintext.

§2.13.2.4 — On platforms where `machine-uid` does NOT produce a stable
identifier (stock OpenBSD without provisioned machine ID), `show-machine-id`
SHALL exit EX_UNAVAILABLE (69), and a machine-tier binary's
`init!(bind_to_machine)` SHALL fail at runtime with EX_UNAVAILABLE (69) — the
`KeyProvider(Provider(_))` → 69 mapping of §1.9.7 — with the marker absent
from output. The test SHALL assert this failure mode rather than treating it
as a test failure. This validates §1.6.5's documented portability behavior.

§2.13.2.6 — Platform smoke tests SHALL be written in a CI-portable shell
script invocable from the GitHub Actions YAML for native platforms and from
the `cross-platform-actions/action` `run:` block for VM platforms.

---

### §2.14 Iteration 14 — Debug derive (MaskDebug)

`#[derive(Debug)]` embeds the type name, every field name, and every
enum variant name as cleartext `&'static str` in `.rodata` (via
`Formatter::debug_struct(name)` / `.field(name, value)` /
`write_str(name)`). For the §1.1.1 target user this leaks type
vocabulary to `strings(1)` even when every field _value_ is masked.
`MaskDebug` closes that channel with the same AEAD pipeline as
`mask!`.

`MaskDebug` is an ungated, always-available surface: unlike
`MaskSerialize` (Appendix E, which needs the `unstable-serde` feature and `std`),
the `core::fmt` builder API takes `&str` rather than
`&'static str`, so no decrypt-once leak — and therefore no `std`
requirement — exists. The derive works in every build configuration,
including `no_std` + `alloc`.

#### §2.14.1 Acceptance criteria

§2.14.1.1 — `#[derive(MaskDebug)]` SHALL generate a `core::fmt::Debug`
impl whose `{:?}` and `{:#?}` output is byte-identical to plain
`#[derive(Debug)]` for the same type.

§2.14.1.2 — The type name, every field name, and every enum variant
name SHALL be AEAD-encrypted at expansion time using the §1.5.2
call-site nonce derivation and SHALL NOT appear as plaintext in the
compiled binary.

§2.14.1.3 — Names SHALL be decrypted on each `fmt` call and released
afterwards; the expansion SHALL NOT cache or leak decrypted names.

§2.14.1.4 — The derive SHALL accept structs (named-field, tuple, and
unit) and enums (all variant field shapes, including uninhabited
enums). Unions SHALL fail with `MaskDebug! grammar` (§1.9.6).

§2.14.1.5 — Raw identifiers SHALL render unraw'd (`r#type` → `type`),
matching the plain derive.

§2.14.1.6 — Each type parameter SHALL receive a `Debug` where-clause
bound, mirroring the plain derive's bound model.

§2.14.1.7 — Name decryption SHALL follow `mask!`'s runtime policy:
lazy Embedded-floor initialization, §1.9.5 profile-split panic on
decrypt failure. On seal tiers above Embedded, `init!` MUST run
before the first formatting.

§2.14.1.8 — The expansion SHALL be hygienic against user identifiers:
field names that collide with generated locals (e.g. `__f`,
`__builder`) SHALL NOT alter or break the expansion.

§2.14.1.9 — `#[repr(packed)]` structs SHALL be supported by copying
each field before formatting — references to packed fields are
undefined behavior (E0793) — mirroring the plain derive, including
its effective `Copy`-field requirement.

#### §2.14.2 Residual exposure

- A plain `#[derive(Debug)]`, `#[derive(serde::Serialize)]`, or
  `#[derive(serde::Deserialize)]` on the same type re-embeds every
  name in the binary and defeats the masking.
- Formatted output prints decrypted names at runtime — at-rest
  protection only, per §1.1.

### §2.15 Iteration 15 — Output zeroization (zeroize-on-drop)

A masked macro decrypts to an owned heap value (`String`, `Vec<u8>`,
`CString`) which, by default, is freed without overwriting — its
plaintext lingers in residual memory until the allocator reuses the
pages, and so survives in a memory artifact captured after the value is
no longer needed. This iteration lets a consumer opt masked
`String`/`Vec<u8>` outputs into zeroize-on-drop, and makes litmask's own
internal transient plaintext (`mask_format!` fragments, `MaskDebug`
names) self-wipe.

Scope is **memory-remanence hygiene**: it shrinks the window in which a
dropped secret's cleartext is recoverable from residual memory after the
value is no longer needed. This covers the common remanence artifacts —
**core/crash dumps, swap files, hibernation images, and freed-heap
reuse**. It is **NOT** a defense against runtime memory inspection
(§1.1's threat model and THREAT_MODEL Level 4 remain out of scope — a
live attacker reads the value between decrypt and drop; swap and
hibernation may likewise capture a page while the value is still live)
nor against re-derivation (the `mask_key` is process-resident by design
and ciphertext blobs live in `.rodata`, so an attacker with any such
artifact can re-derive regardless of output wiping). The byte-clearing
primitive is the `zeroize` crate's contract and is relied upon, not
re-specified.

#### §2.15.1 Acceptance criteria

§2.15.1.1 — litmask SHALL re-export a zeroize-on-drop string wrapper as
public API such that a consumer can wrap a masked output (e.g.
`Zeroizing::new(mask!("…"))`) and obtain a value whose plaintext buffer
is overwritten when it drops, **without** the default return type of
`mask!` and its string-producing siblings changing.

§2.15.1.2 — For a single-allocation masked output (`mask!` string/byte
literals, `mask_include_str!`, `mask_include_bytes!`, `mask_env!`,
`mask_option_env!`, `mask_file!`, `mask_concat!`), the wrapped value
SHALL wipe the complete decrypted footprint on drop — no un-wiped
intermediate plaintext copy SHALL be produced by the decrypt path.

§2.15.1.3 — `mask_format!` SHALL overwrite each decrypted literal
fragment's plaintext after it is written into the result, before that
fragment's buffer is freed.

§2.15.1.4 — `mask_format!` SHALL reserve result capacity equal to the
sum of its compile-time literal fragment lengths, so that literal-driven
assembly performs no reallocation. Reallocation caused by
runtime-argument growth beyond that reserve is a documented residual
(§2.15.2).

§2.15.1.5 — `#[derive(MaskDebug)]` SHALL overwrite each decrypted
type/field/variant name after formatting, and its `{:?}` / `{:#?}`
output SHALL remain byte-identical to plain `#[derive(Debug)]`
(strengthening §2.14.1.3).

§2.15.1.6 — `mask!(c"…")` (CString output) SHALL be explicitly
**excluded** from zeroize-on-drop coverage; the documentation SHALL
state the exclusion and the escape hatch (`mask!("secret")` → wrap the
`String` → construct a transient `CString` at the FFI boundary).

§2.15.1.7 — No documentation, error text, or comment SHALL claim that
output zeroization defeats runtime memory inspection or re-derivation.
Claims SHALL be confined to memory-remanence hygiene per §1.1's
understatement rule.

§2.15.1.8 — The feature SHALL introduce no new cargo feature flag
(`zeroize` is already a required dependency) and SHALL NOT use `unsafe`.

#### §2.15.2 Residual exposure

- The decrypted `mask_key` is process-resident (`'static`) and
  ciphertext blobs are in `.rodata`; an attacker with a memory artifact
  can re-derive every masked literal regardless of output wiping. Output
  zeroization defeats only the trivial cleartext-grep, not structural
  analysis.
- A live debugger or `/proc/pid/mem` read captures the value between
  decrypt and drop — unaffected.
- Swap and hibernation may capture a memory page while the value is
  **still live** (before drop); that copy is unaffected, same as the
  live-debugger case.
- Any `.clone()`, `format!`, or write of a masked output into another
  buffer (including `mask_print!` / `mask_write!` emitting to a sink)
  copies plaintext that escapes the wrapped value and is not wiped.
- `mask_format!` results that grow past the reserved capacity
  (runtime-argument expansion) may leave un-wiped intermediate buffers
  from reallocation.
- `CString` output (§2.15.1.6) is not covered.

## Appendix A — Open Items for Implementation

These are decisions deferred to implementation that are not constrained by
the spec:

- Specific identifiers for internal `#[doc(hidden)]` items
- Internal layout of `litmask-build` modules
- Specific argument syntax of `litmask-cli` beyond the requirements in §2.9
- Exact wording of `Display` tag strings (§1.9.3 specifies form
  `category:variant` but not the precise strings)
- Specific shell scripting language and structure for §2.13.2.6 smoke
  tests; portability across platform shells is the only constraint

## Appendix B — Deferred to v2

- Pure `core` (no allocator) support
- Runtime template formatting
- Caching of decrypted strings
- Zero-copy `&'static str` returns
- Key rotation at runtime
- Programmatic config parsing (`unstable-serde` feature)
- Control-flow obfuscation
- NetBSD, DragonFly BSD, Illumos platform CI

Per-string key derivation is rejected, not deferred — see §1.5.5.

## Appendix C — Glossary

The canonical glossary is [`CONTEXT.md`](../CONTEXT.md) — the project's
ubiquitous-language reference for `mask_key`, `unlock_key`, the seal tiers,
the `wrapper`, and the other domain terms. Spec-only terms are defined at
their point of use (e.g. the `sysexits` exit-code mapping in §1.9.7).

## Appendix D — Build-sealed keying: rationale & residuals

This appendix folds the design rationale and accepted residuals behind the
build-sealed keying model (Part I §1.6–§1.7, Part II §2.4–§2.6). The normative
requirements live in Parts I and II.

### §D.1 Build-time guarantees (no runtime self-assertion)

- **§D.1.1 — Round-trip is a unit-test invariant, not a per-build step.**
  Seal/unseal correctness is a litmask unit test
  (`build_artifacts_wrapper_round_trips_under_unlock_key`), not a
  per-consumer-build runtime assertion in `emit()`. A build-time machine-tier
  round-trip would only prove `emit()` can reopen with the _same_ id it just
  sealed under — not that the deploy host emits that id (the case that matters;
  see §D.3 I-R2).
- **§D.1.2 — No secret echo.** `emit()` MUST NOT print the seed, unlock key,
  machine-id, or any secret input to `cargo:warning=` or any build log. The only
  sanctioned release `cargo:warning=` is the §1.3.2 Embedded-floor notice, which
  carries no secret. Reproducible rebuild relies on the operator pinning the seed
  via `keygen` (§1.3.3); there is no post-hoc seed-recovery channel.

### §D.2 Threat-model deltas

`THREAT_MODEL.md` is canonical for the trust boundaries; this records the
deltas the build-sealed model introduced.

- **§D.2.1 — Debug self-decrypts _and_ diagnoses.** Debug builds seal like
  release (no pass-through plaintext) but **fail loud**: init failures carry
  identifying, actionable messages (§1.9.5). A debug binary is self-decrypting at
  the Embedded floor _and_ prints litmask-identifying diagnostics, so it **MUST
  NOT be distributed**.
- **§D.2.2 — Opacity unchanged or improved.** The model stores no derived locator
  in the artifact; the wrapper is indistinguishable `.rodata`, still gated by the
  §1.9 dirty-word scrub.
- **§D.2.3 — Host compromise unchanged.** Machine-id binding defends only the
  "exfiltrate the binary, analyze it elsewhere" path; a rooted deploy host has the
  live process and decrypted `mask_key` regardless. Defense-in-depth, not a wall.

### §D.3 Honest residuals

- **I-R1 (no self-service rebind).** Machine changes require a builder rebuild
  (+ re-sign + notarize). Machine-id is a **stable-host** factor; churning fleets
  (VMs, cloud, hardware swaps) are directed to an external orchestrator-delivered
  factor instead.
- **I-R2 (no off-box assurance).** No way to confirm a sealed binary unlocks on a
  target except by running it there (the build-time round-trip proves
  crypto-correctness, not target-openability — §D.1.1). Mitigated by deterministic
  tier derivation, the §1.3.2 floor warning, and loud debug diagnostics (§1.9.5);
  there is no consumer-callable tier query and no release warning string (opacity
  preserved).
- **I-R3 (build-env key exposure).** The build host is trusted with the key;
  untrusted build deps are out of scope. Not a new boundary — the build host
  already holds the seed + `mask_key`.
- **I-R4 (per-customer build cost).** The seed is pinned **per customer**, so each
  gets a distinct `mask_key` and blob pool (literal isolation). A per-customer
  build re-encrypts literals (cheap AEAD), re-seals, re-links, and re-signs; the
  blob cache survives only across same-customer patch-rebuilds (same pinned seed).
- **I-R6 (cross-crate build channel).** The tier tag and `OUT_DIR` reach only the
  crate that owns `emit()`'s `build.rs`; `init!`/`mask!` MUST co-locate there
  (§2.6.1). A workspace split is rejected at compile time (absent-tag
  `compile_error!`), never silently downgraded.
- **I-R7 (build-warning re-display).** The §1.3.2 floor warning rides cargo's
  `cargo:warning=` channel, which cargo re-displays only when `build.rs` re-runs.
  `rerun-if-env-changed` on the factor vars covers tier flips, and a fresh/release
  build always shows it.

## Appendix E — Experimental: masked serde integration (`unstable-serde`)

Status: **EXPERIMENTAL**. Gated by the `unstable-serde` feature on the
`litmask` crate. The `unstable-` prefix is the semver-exemption signal: this
surface may change or be removed in any release. Stabilization renames the
feature to `serde` (a breaking change by design) and is governed by the
shared bar in
[ADR-0002](adr/0002-experimental-feature-promotion.md) — most critically,
a complete serde-attribute support matrix (every row a passing test or an
explicit rejection). The matrix is filled; the open gate is real-world
validation (ADR-0002 gate 1): no genuine consumer has exercised the
surface yet, so promotion is deferred.

### §E.1 Motivation

`#[derive(serde::Serialize)]` embeds the container name and every field name
as cleartext `&'static str` in `.rodata` (via
`serialize_struct(name, len)` / `serialize_field(name, value)`).
`#[derive(serde::Deserialize)]` is the larger leak surface: the
`FIELDS`/`VARIANTS` arrays, the field-visitor match-arm literals, the
`expecting()` texts (`"struct Config"`), and the
`missing_field`/`unknown_variant` diagnostics all carry the names. For the
§1.1.1 target user, serde-derived (de)serialization therefore leaks schema
vocabulary — field names, internal service terminology, protocol shape — to
`strings(1)` even when every field _value_ is masked. `MaskSerialize` and
`MaskDeserialize` close both channels with the same AEAD pipeline as
`mask!`.

### §E.2 Surface and normative behavior

`#[derive(MaskSerialize)]` generates a `serde::Serialize` impl, and
`#[derive(MaskDeserialize)]` a `serde::Deserialize` impl, for any
struct (named-field, tuple, newtype, unit) or enum.

- **§E.2.1 Wire-format identity.** Serialized output MUST be byte-identical
  to the plain serde derive for every serde format. The expansion mirrors
  serde's own shape dispatch — each shape calls the dedicated `Serializer`
  entry point the plain derive would (`serialize_struct`,
  `serialize_tuple_struct`, `serialize_newtype_struct`,
  `serialize_unit_struct`, and the four `*_variant` forms) — never
  `serialize_map`, because non-self-describing formats (bincode, postcard)
  serialize structs positionally and enums by declaration-order variant
  index; a map-based impl would change their wire shape and re-introduce
  names on the wire.
- **§E.2.2 Name masking.** The container name, every field name, and every
  enum variant name MUST be AEAD-encrypted at expansion time using the
  §1.5.2 call-site nonce derivation and MUST NOT appear as plaintext in the
  compiled binary. Raw identifiers serialize unraw'd (`r#type` → `"type"`),
  matching serde.
- **§E.2.3 Decrypt-once caching.** Each name is decrypted on first use,
  leaked, and cached in a `std::sync::OnceLock` — serde's entry points
  require `&'static str` (`serialize_struct` / `serialize_field` /
  `missing_field`) and `&'static [&'static str]` (`deserialize_struct` /
  `deserialize_enum` `FIELDS`/`VARIANTS`), which runtime-decrypted names
  can only satisfy by leaking. The leak is bounded (one allocation per name
  per process, plus one slice per name group) and consistent with the §1.1
  threat model (binary at rest, not process memory). `unstable-serde`
  therefore requires `std`.
- **§E.2.4 Init semantics.** Name decryption follows `mask!`'s runtime
  policy: lazy Embedded-floor initialization, §1.9.5 profile-split panic on
  decrypt failure. On seal tiers above Embedded, `init!` MUST run before the
  first serialization or deserialization.
- **§E.2.5 Supported `#[serde(...)]` subset, reject-loud rest.** Unions
  fail with `<macro>! grammar` (§1.9.6), matching the plain derives'
  refusal. The masking derives honor the following attribute subset,
  staying wire/behavior-identical to the plain derive (§E.2.1/§E.2.6) by
  applying the same transformation before masking the resolved name:

  | Attribute | Scope | Notes |
  |---|---|---|
  | `rename` / `rename(serialize=,deserialize=)` | container, variant, field | masks the renamed string, not the ident |
  | `rename_all` (+ split) | container, variant | all eight serde case rules, ported byte-for-byte |
  | `skip` / `skip_serializing` / `skip_deserializing` | named field | skipped-de fields fill from `Default`; reject-loud on tuple fields |
  | `skip_serializing_if = "path"` | named field | runtime length pre-count |
  | `default` / `default = "path"` | named field | fills a missing or skipped-de field |
  | `alias` | named field, variant | extra accepted deserialize names |
  | `deny_unknown_fields` | container | unknown string key → `unknown_field` error |
  | `bound` / `bound(serialize=,deserialize=)` | container | replaces the default per-param trait bound |
  | `transparent` | container | single-field struct (de)serializes as that field |
  | `with` / `serialize_with` / `deserialize_with` | named field | routes through user fns; supported on a generic type (the adapter carries the impl's bounds) |

  Every other key — notably `flatten`, the enum representations `tag` /
  `untagged` / `content`, container `getter` / `into` / `from` /
  `try_from`, and explicit `borrow` — fails with
  `<macro>! invalid-arg`, naming the key, rather than silently ignoring it
  (which would break §E.2.1/§E.2.6). Generic types are otherwise
  supported; each type parameter receives a `Serialize` (resp.
  `Deserialize<'de>`) where-clause bound unless `bound` overrides it.
- **§E.2.6 Deserialize behavior identity.** `MaskDeserialize` MUST accept
  exactly the inputs the plain derive accepts, produce equal values, and
  produce byte-identical error messages, for every serde format. The
  expansion mirrors serde's shape dispatch (`deserialize_struct`,
  `deserialize_tuple_struct`, `deserialize_newtype_struct`,
  `deserialize_unit_struct`, `deserialize_enum`) and visitor surface:
  named-field visitors implement both `visit_map` and `visit_seq`
  (non-self-describing formats deserialize structs positionally), and the
  identifier visitors implement `visit_u64`/`visit_str`/`visit_bytes`
  (`visit_u64` is how non-self-describing formats select enum variants by
  declaration-order index). Unknown fields are skipped, unknown variants
  fail with `unknown_variant`, duplicate and missing fields fail with the
  plain derive's diagnostics, and a missing `Option<T>` field deserializes
  to `None`. Identifier matching compares against runtime-decrypted names,
  never cleartext match arms. `&str`/`&[u8]` fields (optionally
  `Option`-wrapped) borrow from the input via a `'de: 'a` bound, mirroring
  serde's implicit-borrow rule. The expansion MUST NOT reference
  `serde::__private` (semver-exempt); the pieces of the plain expansion
  that live there are replicated against public API in the `#[doc(hidden)]`
  `litmask::__serde_support` module.

### §E.3 Residual exposure, unsupported attributes, and stabilization

Residuals (documented, not defects):

- A plain serde derive or `#[derive(Debug)]` on the same type re-embeds
  every name in the binary and defeats the masking. Pair the three masking
  derives instead (`MaskSerialize`, `MaskDeserialize`, `MaskDebug` §2.14).
- Self-describing formats print decrypted names in runtime output and
  runtime error messages — at-rest protection only, per §1.1.
- serde's own crate-internal strings remain in the binary; the masking
  covers user schema vocabulary, not dependency text.

The supported `#[serde(...)]` subset is fixed by §E.2.5. Beyond it, the
deferred attributes — `flatten`, the enum representations `tag` /
`untagged` / `content`, and explicit `borrow` — are not yet supported and
stay reject-loud; they may land in a future minor release. `into` / `from` /
`try_from` / `getter` are out of scope, not deferred: they delegate
(de)serialization to a shadow type whose own derive embeds the names, so
masking cannot reach them; they stay permanently reject-loud.

Stabilization (the rename to `serde`) is governed by ADR-0002. The
support matrix is complete, but gate 1 (real-world validation by a
genuine consumer, not in-repo tests alone) is not yet met, so the
feature stays `unstable-serde`.
