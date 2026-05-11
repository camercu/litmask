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

**Amendment convention:** Inline amendments are marked with
`> **Amendment YYYY-MM-DD:**` blockquotes immediately following the
paragraph they modify. The blockquote contains the new normative text,
not a meta-description. The unmodified original text is retained above
each blockquote so the diff reads cleanly in source review and so
readers can see what was superseded.

## Revision history

- **2026-05-10 — Amendment 1:** `mask!` grammar extended to accept
  `include_str!(<path>)` and `concat!(<args>)` invocations as inputs,
  resolved at proc-macro time. Affects §1.8.1, §1.9.6, §2.1.1, §2.3.2.5.
- **2026-05-10 — Amendment 2:** `#[mask_all]` compile-time warning
  mechanism specified as the ghost `#[deprecated] const _` hack until
  `proc_macro::Diagnostic::emit` stabilizes. Affects §2.3.1.4 and the
  warning branches of §2.3.2.
- **2026-05-10 — Amendment 3:** `litmask-cli` compiles BOTH ciphers
  unconditionally and runtime-dispatches based on the wrapper's
  cipher-id byte; the "exactly one cipher per build" rule from §1.5.1
  is narrowed to the `litmask` runtime crate only. Affects §1.5.1,
  §1.7.3, §1.14, §2.9.1.
- **2026-05-10 — Amendment 4:** The "single crate" goal in §1.2 is
  clarified — Rust prohibits non-macro exports from a `proc-macro`
  crate, so the workspace MAY contain a hidden internal
  `litmask-macros` proc-macro crate that the user-facing `litmask`
  crate re-exports. Affects §1.2.

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
| Zero-config build (defaults to `EnvVarProvider`) | `strings`, casual binary inspection (Level 1); also Level 2 because `unlock_key` is not embedded |
| `FileProvider` + filesystem permissions | Above with OS-enforced access control |
| `HardwareIdProvider` | Above + binary moved to a different machine |
| Custom `KeyProvider` (network call, vault) | Above + offline attackers |

The "zero-config" descriptor refers to absence of project configuration, not to
absence of runtime key provisioning. For providers that source `unlock_key` from
external runtime state (`EnvVarProvider`, `FileProvider`, `HardwareIdProvider`,
custom providers), the deployer MUST provision that state at runtime. A binary
configured with such a provider but without the corresponding state will fail at
init. `StaticProvider` is an exception — it carries the key in the constructor
and requires no external provisioning, but the security level for `StaticProvider`
configured at compile time degrades to Level 1 since the key is in the binary.

#### §1.1.5 Deliberate understatement

Documentation and error messages MUST err toward understating guarantees. False
confidence is the most common failure mode of obfuscation libraries; users
deploy them in scenarios they don't actually protect against. Every public-facing
description of security properties must be conservative.

#### §1.1.6 Value proposition vs. existing crates

This table SHALL appear in the README and in the crate-level rustdoc:

| Property | `obfstr` | `litcrypt`/`litcrypt2` | `litmask` |
|---|---|---|---|
| Cipher | XOR | XOR | ChaCha20-Poly1305 (AEAD) or AES-256-GCM |
| Tamper detection | No | No | Yes (AEAD authentication) |
| Per-string nonces | Compile-time random (no auth) | None | Per-build deterministic, authenticated |
| Key model | Compile-time random per build | Single env var | Layered: `mask_key` + `unlock_key`, multiple providers |
| Format string masking | Separate `fmtools` crate | None | Built-in `maskfmt!` with single-evaluation semantics |
| Module-level masking | None | None | `#[mask_all]` with deep substitution |
| Hardware binding | None | None | Yes (post-build rebind via `litmask-cli`) |
| Multiple literal types (str/bytes/cstr) | str only | str only | All three |
| `no_std` support | Limited | No | Yes (with `alloc`) |
| Threat model documented | Minimal | Minimal | Explicit security ladder, honest scope |
| Reproducible builds | No | No | Yes (with `LITMASK_RNG_SEED`) |
| Fuzzing | No | No | Yes |

The cipher upgrade (XOR → AEAD) is the primary technical advance. Everything
else is operational maturity (key management, deployment story, tooling).

### §1.2 Workspace Structure

`litmask` is a Cargo workspace with three crates:

| Crate | Type | Purpose |
|---|---|---|
| `litmask` | proc-macro + library | Runtime, proc-macros, key provider trait and built-ins |
| `litmask-build` | library (build-dep) | `build.rs` helper for compile-time key generation, writes `litmask.config` |
| `litmask-cli` | binary | `bind` and `inspect` commands for hardware-bound deployment |

The proc-macro and runtime ship in a single crate (`litmask`) rather than
separate `litmask-macros` + `litmask-runtime` crates. This is unconventional
but intentional: the proc-macro and runtime share a binary format that must
evolve in lockstep, and splitting them adds version-skew risk without benefit.

> **Amendment 2026-05-10:** Rust forbids exporting non-macro items from a
> crate with `proc-macro = true`, so the "single crate" goal cannot be
> taken literally. The user-facing surface remains a single `litmask`
> crate; internally, the workspace MAY contain a hidden
> `litmask-macros` proc-macro crate that the public `litmask` crate
> re-exports via `pub use litmask_macros::*;`. The two MUST be pinned
> as `=x.y.z` exact-version dependencies and released together so the
> binary format never desyncs. `litmask-macros` SHALL be marked
> `publish = true` (so users can resolve the transitive dependency)
> but documented as "internal — do not depend on directly." The
> three-crate workspace table above lists user-facing crates; the
> internal `litmask-macros` is implementation detail. Add it to the
> workspace `members` array when Task 5 lands.

### §1.3 Build Pipeline

#### §1.3.1 Build-time flow

1. User adds `litmask` as a regular dependency and `litmask-build` as a
   build-dependency.
2. User adds a one-line `build.rs`: `litmask_build::emit();`.
3. `build.rs` runs:
   - Sources `RNG_SEED` from `LITMASK_RNG_SEED` env var, then (debug builds
     only) from `target/litmask-seed`, then generates a fresh seed.
   - Generates `mask_key` (32 bytes) and `unlock_key` (32 bytes)
     deterministically from the seed.
   - Encrypts `mask_key` with `unlock_key` using the configured cipher,
     producing the encrypted `mask_key` wrapper described in §1.7.3.
   - Computes the locator (first 12 bytes of the wrapper).
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
   - Writes `litmask.config` (schema in §1.7.4) to the build profile
     directory.
   - In debug profile, writes `target/litmask-seed` for incremental build
     stability.
   - In release profile, when the seed was freshly generated (not supplied
     via `LITMASK_RNG_SEED`), emits `cargo:warning=` directives printing the
     seed value to the terminal so the developer can capture it for
     reproducible debugging.
4. Proc-macro expansions read `mask_key` and `RNG_SEED` from `OUT_DIR` files
   and emit encrypted ciphertext for each `mask!` invocation, using the
   nonce derivation in §1.5.2 and the per-string blob format in §1.7.2.

#### §1.3.2 Profile-dependent behavior

| Profile | Seed source priority |
|---|---|
| debug | `LITMASK_RNG_SEED` env → `target/litmask-seed` → fresh + persist |
| release | `LITMASK_RNG_SEED` env → fresh, no persistence, print via `cargo:warning=` |

`build.rs` detects profile via the `PROFILE` env var that Cargo sets.

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

The runtime maintains a single `OnceLock<MaskKey>` for the decrypted `mask_key`.
Initialization happens via:

```rust
litmask::init()?;                              // Uses default EnvVarProvider
litmask::init_with(provider)?;                 // Uses provided KeyProvider
```

Either form is optional — first `mask!()` call performs lazy init with the
default provider. Explicit init is recommended so initialization failures
surface at startup with structured errors rather than panics deep in program
execution.

The `OnceLock` is initialized exactly once per process; key rotation at runtime
is not supported in v1.

#### §1.4.2 Decryption flow

Each `mask!()` call:
1. Retrieves the cached `mask_key` from the `OnceLock` (lazy-init if needed).
2. Reads its locally-embedded encrypted blob (format: §1.7.2).
3. Decrypts using the configured cipher.
4. Returns the result (`String`, `Vec<u8>`, or `CString` based on literal type).

Decryption failures at this stage indicate ciphertext tampering and panic per
§1.9.5.

#### §1.4.3 Concurrency

`OnceLock` provides thread-safe one-shot initialization. `mask!()` calls from
multiple threads do not contend beyond the `OnceLock` read; each call decrypts
into its own owned return value.

### §1.5 Cryptographic Design

#### §1.5.1 Cipher choices and feature selection

- **Default**: ChaCha20-Poly1305 (AEAD, 256-bit key, 96-bit nonce, 128-bit tag)
- **Optional**: AES-256-GCM (AEAD, 256-bit key, 96-bit nonce, 128-bit tag),
  selected by enabling the `aes-gcm` feature

Exactly one cipher is compiled into any given build. The selection rule is:

| `aes-gcm` feature | Compiled cipher |
|---|---|
| disabled | ChaCha20-Poly1305 |
| enabled | AES-256-GCM (replaces ChaCha20-Poly1305) |

The runtime crate uses `#[cfg(feature = "aes-gcm")]` to select the cipher
implementation. Both ciphers are NOT compiled simultaneously; the
`#[cfg(not(feature = "aes-gcm"))]` branch contains the ChaCha20-Poly1305
implementation. This avoids ambiguity about which cipher is in use and keeps
the binary footprint minimal.

Rejected ciphers: AES-CTR (no authentication), Salsa20 (superseded by
ChaCha20), RC4 (cryptographically broken).

Cipher selection is fixed at build time; runtime cipher switching is not
supported.

> **Amendment 2026-05-10:** The "exactly one cipher per build" rule
> applies to the `litmask` runtime crate (the code that ships in user
> binaries) and to `litmask-build`. It does NOT apply to `litmask-cli`.
> `litmask-cli` SHALL link BOTH `chacha20poly1305` and `aes-gcm`
> unconditionally and SHALL select between them at runtime based on
> the cipher-id byte in the wrapper it operates on (`0x01` →
> ChaCha20-Poly1305, `0x02` → AES-256-GCM, anything else → exit
> EX_DATAERR with the message `unsupported_cipher`). Rationale: a user
> who builds a binary `--features aes-gcm` and then runs `cargo install
> litmask-cli` (default features) would otherwise hit a silent bind
> failure because the default-built CLI cannot decrypt an AES-GCM
> wrapper. Runtime dispatch in the CLI is acceptable because the
> CLI's binary footprint and "single cipher in the binary"
> obfuscation property are not user-facing concerns — the CLI is a
> developer tool, not a deployed artifact.

#### §1.5.2 Per-string nonce derivation

Every encrypted blob in the binary uses a unique nonce. Nonces for per-string
blobs are derived deterministically as:

```
nonce = first_12_bytes(BLAKE3-keyed-hash(
    seed,
    "litmask-nonce" || file_path || ":" || line || ":" || column
))
```

Properties:

- **Uniqueness across call sites**: distinct file/line/column combinations
  produce distinct nonces with overwhelming probability.
- **Determinism across builds**: same source layout + same seed → same nonces
  → same ciphertext.
- **Independence from compilation order**: parallel proc-macro expansion does
  not affect derivation since each call site's nonce depends only on its own
  location.
- **Insensitivity to unrelated source changes**: adding code elsewhere in the
  file changes line numbers only for code after the addition; nonces for
  unaffected call sites remain stable.

Identical literals at different call sites receive different nonces (and
therefore different ciphertext) because they have different file/line/column
values.

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
`InitError::Decryption` when it occurs during `init()` (per §1.9.2).

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
pub trait KeyProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError>;
}
```

The `&self` receiver allows stateful providers (cached lookups, network
clients). `UnlockKey` is a 32-byte newtype that zeroes on drop.

The trait is intentionally minimal. It has no `deployment_hint()` method or
similar — the goal of minimizing library-side plaintext (see §1.9.3)
precludes English-language strings on the trait. Deployment guidance lives in
`DEPLOYMENT.md`, not in the binary.

#### §1.6.2 Built-in providers

| Provider | Feature gate | Description |
|---|---|---|
| `EnvVarProvider` | `std` (default) | Reads from a configurable env var (default `LITMASK_UNLOCK_KEY`) |
| `FileProvider` | `std` (default) | Reads from a filesystem path |
| `HardwareIdProvider` | `hw-id` (opt-in) | Derives from machine ID via `machine-uid` |
| `StaticProvider` | always available | Holds an `UnlockKey` directly; primarily for tests |

Default provider when `init()` is called without arguments:
`EnvVarProvider::new("LITMASK_UNLOCK_KEY")`.

#### §1.6.3 Key encoding

`unlock_key` and `mask_key` are 32 raw bytes internally. External
representations (env vars, config files, file contents) use **base64url
without padding** (RFC 4648 §5). 32 bytes encodes to 43 characters.

`FileProvider` defaults to base64url encoding but supports raw bytes via
`KeyEncoding::Raw`.

#### §1.6.4 UnlockKey lifecycle

`UnlockKey` is constructed by `KeyProvider::unlock_key()`, used to decrypt
`mask_key` during `init()`, and dropped immediately after. The decrypted
`mask_key` is held in the `OnceLock` for the program lifetime.

`UnlockKey` and `MaskKey` (internal type) both implement `Drop` with `zeroize`
to clear their contents from memory when dropped.

#### §1.6.5 Cross-compilation note for HardwareIdProvider

`HardwareIdProvider` runs on the **target** machine, not the build host.
`machine-uid` supports all standard `std` targets (Linux, macOS, Windows). On
constrained or unusual targets where `machine-uid` cannot read a stable
machine identifier (some container runtimes, certain embedded Linux variants
without `/etc/machine-id`, OpenBSD by default), `HardwareIdProvider::unlock_key()`
returns `Err(KeyError::Provider(...))`. Cross-compilation users targeting
such environments MUST verify behavior on the target before relying on
`HardwareIdProvider`. The platform CI matrix (§1.10.5) explicitly exercises
this failure path on OpenBSD.

### §1.7 Binary Format and Binding

#### §1.7.1 Locator-based design rationale

The binary contains no identifying patterns, named sections, or magic bytes
attributable to `litmask`. Every encrypted blob is pure ciphertext that looks
like ordinary random data in `.rodata`, indistinguishable from precomputed
tables, embedded test vectors, or compressed assets.

The encrypted `mask_key` wrapper's location is recorded by its first 12 bytes
(the "locator") in `litmask.config`. Since these 12 bytes are themselves real
ciphertext (uniformly random under the cipher), they constitute no fixed
pattern across builds — every build has different locator bytes due to seed
variation.

#### §1.7.2 Per-string ciphertext blob format

Each per-string encrypted blob is a contiguous byte sequence:

```
<nonce: 12 bytes><ciphertext: variable length><authentication tag: 16 bytes>
```

There is NO format version byte, NO cipher identifier byte, and NO other
identifying header in per-string blobs. Format and cipher are global
properties of the build, recorded in the wrapper around the encrypted
`mask_key` (see §1.7.3), not duplicated per-string.

The nonce is derived per §1.5.2.

#### §1.7.3 Encrypted mask_key wrapper format

The encrypted `mask_key` wrapper is the only blob in the binary that carries
metadata. Its format:

```
<format version: 1 byte><cipher id: 1 byte><nonce: 12 bytes><encrypted mask_key: 32 bytes><authentication tag: 16 bytes>
```

Total length: 62 bytes.

- Format version: currently `0x01`. Used for future migration; runtime
  rejects unknown versions per §1.9.2 (`InitError::UnsupportedFormat`).
- Cipher id: `0x01` for ChaCha20-Poly1305, `0x02` for AES-256-GCM. The
  `litmask` runtime crate rejects mismatch with its compiled cipher
  feature per §1.9.2 (`InitError::UnsupportedCipher`). `litmask-cli`,
  per the §1.5.1 amendment, instead dispatches at runtime on this byte
  to select between the two ciphers it always links.

The wrapper's nonce is derived deterministically as:

```
wrapper_nonce = first_12_bytes(BLAKE3-keyed-hash(
    seed,
    "litmask-mask-key-nonce"
))
```

This is the only place format version or cipher id metadata appears in the
binary. Per-string blobs defer to this wrapper for cipher and format
determination.

#### §1.7.4 litmask.config schema

```toml
# Build artifact — secret, do not commit
unlock_key = "<base64url>"        # 32 bytes, current unlock_key
locator = "<base64url>"           # first 12 bytes of encrypted mask_key wrapper
length = 62                       # bytes; full length of wrapper (constant in v1)
```

The `length` field is included for forward compatibility with future format
versions whose wrapper size may differ.

#### §1.7.5 Build artifact location

`litmask-build::emit()` writes `litmask.config` to the per-package build
directory: `target/<profile>/litmask.config` for the package being built. In
multi-package workspaces, each package that uses `litmask-build` gets its own
`litmask.config`; the file lives next to the binary it pertains to.

`build.rs` determines this path via `CARGO_TARGET_DIR` (if set) combined with
the build profile, falling back to `target/<profile>/` relative to
`CARGO_MANIFEST_DIR`.

#### §1.7.6 Binding workflow

The `litmask-cli bind` command rebinds a binary to a hardware-derived
`unlock_key`. v1 supports hardware-ID binding only. Other providers
(`EnvVarProvider`, `FileProvider`) do not require post-build rebinding —
their `unlock_key` is provisioned at deployment time using the value from
`litmask.config`.

The bind operation:
1. Reads current `litmask.config` (containing current `unlock_key` and
   `locator`).
2. Scans target binary for the locator.
3. Reads `length` bytes at the located offset → encrypted `mask_key` wrapper.
4. Decrypts wrapper with current `unlock_key` → recovered `mask_key`.
5. Derives new `unlock_key` from target machine's hardware ID (with optional
   user-supplied salt).
6. Re-encrypts `mask_key` with new `unlock_key` → new wrapper.
7. Atomically commits both binary patch and config update via the protocol
   in §1.7.7.

First-bind and subsequent rebinds use the same code path; the only difference
is that the "current `unlock_key`" on first bind is the build-time random
key, while on rebind it is the previous hardware-derived key.

#### §1.7.7 Atomic commit protocol for bind

To avoid leaving the binary and `litmask.config` in inconsistent states if a
write fails partway through, the bind operation MUST:

**On POSIX:**
1. Compute new `unlock_key`, new wrapper bytes, and new `litmask.config`
   contents in memory; do not write anything yet.
2. Write new `litmask.config` contents to a tempfile in the same directory.
3. `fsync` the tempfile.
4. Patch the binary at the located offset.
5. `fsync` the binary.
6. `rename` the tempfile to `litmask.config` (atomic on POSIX).
7. `fsync` the parent directory of `litmask.config`. This step is mandatory
   on POSIX — without it, the rename is not durable across crashes and may
   appear to revert after a system crash.

**On Windows:**
Same steps 1-5, but:
6. Use `MoveFileExW` with `MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH`
   flags to atomically replace `litmask.config` with the tempfile contents.
   `MOVEFILE_WRITE_THROUGH` ensures the rename is flushed to disk before
   returning, providing equivalent durability to POSIX step 7. No separate
   directory-level fsync is needed.
7. (no-op on Windows; durability is provided by step 6)

If any step fails, the binary and original `litmask.config` are left in the
most consistent recoverable state:
- Steps 1-3 fail: nothing modified.
- Step 4 fails before any write: nothing modified.
- Step 4 fails partway: binary is corrupted; original config is intact.
  Recovery requires rebuilding.
- Step 5 fails: binary is patched but not flushed; config not yet renamed.
  On crash, filesystem may persist either or neither.
- Step 6 fails: extremely rare; binary and old config diverge. Document
  recovery procedure (rebuild required).
- Step 7 fails (POSIX only): binary and config are written but rename may
  not survive a crash. On reboot, the original config may reappear; rebind
  will be needed.

### §1.8 API Surface

#### §1.8.1 Macros

```rust
mask!(literal)              // dispatches on literal kind
maskfmt!(literal_template, args...)
unmasked!(literal)          // explicit opt-out, returns literal unchanged
#[mask_all]                 // module-level deep rewriting
#[mask_all(strict)]         // upgrades skip warnings to errors
```

`mask!` accepts:
- String literal (`"text"`, raw, Unicode-escape) → returns `String`
- Byte string literal (`b"\x..."`, raw byte) → returns `Vec<u8>`
- C string literal (`c"text"`, Rust 1.77+) → returns `CString`

> **Amendment 2026-05-10:** `mask!` additionally accepts two specific
> built-in macro invocations as inputs and resolves them at proc-macro
> time before applying the normal masking pipeline:
> - `mask!(include_str!(<path>))` — the proc-macro reads `<path>` via
>   `std::fs::read_to_string` and registers the file as a build
>   dependency via `proc_macro::tracked_path::path(<path>)` so cargo
>   reruns the build when the file changes. The resulting `String` is
>   masked exactly as if it had been written as a bare string literal.
>   Return type is `String`.
> - `mask!(concat!(<args>...))` — the proc-macro recursively evaluates
>   each `<arg>`, which must itself be a string literal, byte literal,
>   C-string literal, or a further `concat!`/`include_str!` invocation.
>   The concatenation is computed at proc-macro time. Return type
>   matches the unified literal kind per Rust's normal `concat!`
>   inference rules; mixed kinds are rejected at proc-macro time with
>   the substring "concat! arguments inside mask! must be string,
>   byte string, or C string literals".
>
> All other non-literal inputs to `mask!` continue to fail with the
> §1.9.6 error message. Rationale: macro expansion in Rust is
> inside-out, so wrapping `mask!` around `include_str!` or `concat!`
> would otherwise leave `mask!` parsing the unexpanded inner token
> tree, which is not a literal — making the natural `#[mask_all]`
> rewrite (§2.3.2.5) impossible. Resolving these two specific
> built-ins at proc-macro time keeps the user-facing API a single
> `mask!` macro and lets `#[mask_all]` emit the natural form.

`maskfmt!` accepts string literal templates only. Non-literal templates produce
a compile error directing users toward `mask!` for runtime-decrypted strings.

`unmasked!` accepts any of the above literal kinds and returns them unchanged
(preserving original type: `&str`, `&[u8; N]`, or `&CStr`). It exists to mark
literals as intentionally unmasked, particularly for `#[mask_all(strict)]`
audit purposes.

#### §1.8.2 Functions

```rust
pub fn init() -> Result<(), InitError>;
pub fn init_with<P: KeyProvider>(provider: P) -> Result<(), InitError>;
```

#### §1.8.3 Public types

```rust
pub trait KeyProvider { ... }
pub struct UnlockKey([u8; 32]);

pub struct EnvVarProvider { ... }
pub struct FileProvider { ... }
#[cfg(feature = "hw-id")] pub struct HardwareIdProvider { ... }
pub struct StaticProvider { ... }

pub enum KeyEncoding { Base64Url, Raw }

#[non_exhaustive] pub enum InitError { ... }
#[non_exhaustive] pub enum KeyError { ... }
```

#### §1.8.4 Internal types (not stable API)

The following types exist but are explicitly internal — marked `#[doc(hidden)]`
and not subject to semver guarantees:

- `MaskKey` — runtime container for the decrypted master key
- `EncryptedBlob` and helper types used by macro-generated code
- `nonce_for_call_site(...)` and other derivation helpers

User code MUST NOT depend on these types.

### §1.9 Error Handling

#### §1.9.1 Two-layer error model

- **Init layer** (fallible, structured): `init()` and
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
    UnsupportedFormat,           // ciphertext format version mismatch
    UnsupportedCipher,           // wrapper specifies a cipher not compiled in
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

```
InitError::KeyProvider(KeyError::NotFound)   → "key_provider:not_found"
InitError::KeyProvider(KeyError::Permission) → "key_provider:permission"
InitError::Decryption                        → "decryption_failed"
InitError::UnsupportedFormat                 → "unsupported_format"
InitError::UnsupportedCipher                 → "unsupported_cipher"
```

These tags are short, ASCII-only, and provide no semantic guidance — they are
identifiers, not explanations. Application code is responsible for any
human-readable messaging:

```rust
match litmask::init() {
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
without contributing any litmask-specific message text to the binary.

The principle: the library MUST NOT contribute string content that uniquely
identifies the operation as litmask-related. Strings from `std` and from
dependency crates are acceptable because they exist in many Rust programs and
do not single out litmask.

The library implementation:
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

The Rust standard library still emits "panicked at <file>:<line>" via the
default panic handler regardless of which form is used. Applications that
want a more informative tampering panic may set a panic hook
(`std::panic::set_hook`) that detects panics in `litmask`-affected locations
and emits their own message.

#### §1.9.6 Compile-time error message requirements

Compile-time errors from the proc-macro do NOT appear in the compiled binary
and MAY use full English text. Specific situations require specific message
content. "Include the substring" in these requirements means substring
containment — implementations MAY add formatting, context, or adjacent
content, provided the required substring appears verbatim within the emitted
error message:

| Situation | Required content |
|---|---|
| `maskfmt!` non-literal template | "maskfmt! requires a string literal template at the call site; use `mask!` to decrypt a runtime string" |
| `mask!` invalid literal type | "mask! accepts string, byte string, or C string literals" |
| `mask!` in const/static initializer | "mask! cannot be used in const or static contexts; use OnceLock for lazy initialization" |
| `mask!` in pattern position | "mask! cannot be used in pattern position; pattern positions require literal values" |
| `mask!(concat!(...))` with non-literal arg | "concat! arguments inside mask! must be string, byte string, or C string literals" |

> **Amendment 2026-05-10:** The "mask! invalid literal type" message
> remains the rejection text for everything that is not a string /
> byte / cstr literal AND is not one of the two built-in macro
> invocations whitelisted in the §1.8.1 amendment
> (`include_str!(...)`, `concat!(...)`). Those two are silent successes
> at the grammar level. The new "concat! arguments inside mask!"
> message covers the case where `concat!`'s arguments are themselves
> non-literal.

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
            InitError::UnsupportedCipher                    => 70,  // EX_SOFTWARE
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
| `UnsupportedCipher` | EX_SOFTWARE (70) | Cipher feature mismatch — software issue |

Recommended usage pattern:

```rust
if let Err(e) = litmask::init() {
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

Two fuzz targets cover the proc-macro format parser and the CLI locator
scanner — components whose input domains are large enough that exhaustive
testing is impractical but where defects could be security-relevant.
Implemented in `litmask/fuzz/` using `cargo-fuzz`. Run in CI for a bounded
time budget per PR.

#### §1.10.5 Platform CI matrix

The CI matrix exercises security and operational properties across a
representative set of operating systems. Each platform job runs the
integration tests from §1.10.3 plus a hardware-binding smoke test specific to
that platform's machine ID mechanism.

| Platform | Mechanism | Coverage |
|---|---|---|
| ubuntu-latest | GitHub Actions native | Debian/Ubuntu glibc family, `/etc/machine-id` |
| almalinux:9 | GitHub Actions Docker job | RHEL-family, SELinux defaults |
| macos-latest | GitHub Actions native | Darwin, IOPlatformSerialNumber |
| windows-latest | GitHub Actions native | Windows registry MachineGuid, NTFS atomic rename |
| FreeBSD 14.2 | `cross-platform-actions/action` (QEMU VM) | BSD-family, `kern.hostuuid` |
| OpenBSD 7.8 | `cross-platform-actions/action` (QEMU VM) | OpenBSD specifically (no `/etc/machine-id` by default; tests `HardwareIdProvider` failure path) |

The smoke test sequence and per-platform requirements (including the
intentional failure-path validation on stock OpenBSD) are specified in §2.13.

OpenBSD installations that have provisioned a machine ID via third-party
means may pass the full smoke test sequence; the job tolerates either
outcome but requires consistency (decryption succeeds OR bind fails cleanly,
never partial success).

NetBSD, DragonFly BSD, Illumos, and other distributions are not in v1's CI
matrix — they may work but are not validated.

### §1.11 Documentation Plan

#### §1.11.1 Required documentation artifacts

| Artifact | Purpose |
|---|---|
| `README.md` | Project overview, security level table, "what does NOT protect against" callout, value proposition table from §1.1.6, quick start |
| `lib.rs` crate docs | API overview, security level table, value proposition table |
| `THREAT_MODEL.md` | Formal threat model including in-scope and out-of-scope attacker capabilities and the init-failure plaintext limitation from §1.9.4 |
| `DEPLOYMENT.md` | Operational guide per `KeyProvider`, recommended release profile, rebind workflow, `litmask.config` handling, sysexits.h code reference |
| Per-API rustdoc | Standard rustdoc on every public item with examples |
| `MIGRATION.md` | Coverage of moving from `litcrypt` (v1 and v2) and `obfstr`, with side-by-side API comparisons |

#### §1.11.2 Required content

Every documentation surface MUST include the security level table from §1.1.4
and a prominent "What `litmask` does NOT protect against" section.

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
- `mask!`, `maskfmt!`, `unmasked!` macros
- `#[mask_all]` attribute and substitution table (additions allowed; removals
  breaking)
- `KeyProvider` trait
- `UnlockKey` type
- `EnvVarProvider`, `FileProvider`, `HardwareIdProvider`, `StaticProvider`
- `init()`, `init_with()` functions
- `InitError::sysexit_code()` method and the sysexits mapping in §1.9.7
- Error type variants (new variants non-breaking via `#[non_exhaustive]`)
- `litmask.config` schema (additions allowed; removals breaking)
- Default cipher (ChaCha20-Poly1305)
- Default `KeyProvider` (`EnvVarProvider`)
- `LITMASK_RNG_SEED`, `LITMASK_UNLOCK_KEY` env var names

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
| `hw-id` | no | `HardwareIdProvider` (pulls in `machine-uid`) |
| `aes-gcm` | no | Use AES-256-GCM instead of ChaCha20-Poly1305 |

`std` and `no_std` are not mutually exclusive features (Cargo can't enforce
that); disabling `std` enables `no_std + alloc` mode. Pure `core` (no
allocator) is not supported in v1.

### §1.14 Dependencies

Runtime crate (`litmask`):
- `chacha20poly1305` (RustCrypto, `#[cfg(not(feature = "aes-gcm"))]`)
- `aes-gcm` (RustCrypto, `#[cfg(feature = "aes-gcm")]`)
- `base64ct` (constant-time base64)
- `proc-macro2`, `quote`, `syn` (proc-macro authoring)
- `blake3` (nonce derivation)
- `machine-uid` (behind `hw-id` feature)
- `zeroize` (`UnlockKey`/`MaskKey` zero-on-drop)
- `once_cell` (only on `no_std` builds, for `OnceBox`)

Build crate (`litmask-build`):
- `chacha20poly1305` (`#[cfg(not(feature = "aes-gcm"))]`)
- `aes-gcm` (`#[cfg(feature = "aes-gcm")]`)
- `base64ct`
- `rand_chacha` (seedable RNG)
- `blake3`
- `toml` (write `litmask.config`)

CLI crate (`litmask-cli`):
- `clap` (argument parsing)
- `chacha20poly1305` AND `aes-gcm` (BOTH always linked per the §1.5.1
  amendment; CLI dispatches at runtime on the wrapper's cipher-id byte
  rather than mirroring the runtime crate's feature flag)
- `base64ct`
- `blake3`
- `machine-uid`
- `toml` (read/write `litmask.config`, exact-version pinned per the
  Task 24 acceptance in `docs/TASKS.md`)

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

2. **`maskfmt!` named-argument single-evaluation semantics.** Every named
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

4. **`HardwareIdProvider` portability.** `machine-uid` behavior in
   containers, VMs, and re-imaged systems varies. OpenBSD by default has no
   `/etc/machine-id`. The platform CI matrix (§1.10.5) exercises both the
   success and failure paths.

5. **Locator collision.** A 12-byte locator has ~2^-66 collision probability
   in a 1 GB binary. The CLI MUST handle the multiple-match case explicitly
   (not pick the first; emit an "ambiguous binary" error).

6. **Library-contributed plaintext.** The library ships short identifier-like
   strings (`Debug` variant names, `Display` tags) but no English error
   explanations. The "no plaintext in binary" property is "minimal,
   non-identifying plaintext" — see §1.9.3.

7. **Cross-compilation correctness.** Proc-macro runs on build host;
   encrypted blob is consumed on target. Endianness of the blob is
   irrelevant (opaque bytes), but verify no host-specific assumptions creep
   in.

8. **`mask_key` transport during build.** `mask_key` is written to a file in
   `OUT_DIR` and read by the proc-macro via `include_bytes!`. The plaintext
   `mask_key` MUST NOT appear in `cargo:rustc-env` directives or any other
   mechanism that records to `target/<profile>/build/<pkg>/output` or to
   terminal output.

9. **Bind operation atomicity.** The atomic commit protocol in §1.7.7 must be
   implemented with platform-appropriate primitives — POSIX directory fsync
   on Unix-like systems, `MoveFileExW` with `MOVEFILE_WRITE_THROUGH` on
   Windows. Deviations risk leaving binaries unrecoverable.

10. **Tampering panic message hygiene.** Implementation must not inject
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
other type (e.g., integer, float, bool, char) or a non-literal expression,
EXCEPT for the two built-in macro invocations whitelisted in §2.1.1.14.

§2.1.1.6 — The compile error message for invalid literal types SHALL include
the substring "mask! accepts string, byte string, or C string literals".

§2.1.1.14 — *(added by Amendment 2026-05-10)* `mask!` SHALL additionally
accept the following two built-in macro invocations as inputs and resolve
them at proc-macro time before applying the masking pipeline:

- `mask!(include_str!(<path>))` — the proc-macro SHALL read `<path>` via
  `std::fs::read_to_string`, register the file as a build dependency via
  `proc_macro::tracked_path::path(<path>)`, and mask the resulting `String`
  exactly as if it had been written as a bare string literal at the call
  site. Return type is `String`. Path resolution follows the same rules as
  the standard `include_str!` macro (relative to the file containing the
  invocation).
- `mask!(concat!(<args>...))` — the proc-macro SHALL recursively evaluate
  each `<arg>`. Each argument MUST itself be a string literal, byte
  literal, C-string literal, or a further `concat!`/`include_str!`
  invocation. The concatenation SHALL be computed at proc-macro time.
  Return type follows Rust's normal `concat!` inference rules. Mixed
  literal kinds within a single `concat!` SHALL produce a compile error
  with the substring "concat! arguments inside mask! must be string,
  byte string, or C string literals".

These two whitelisted forms exist so that `#[mask_all]`'s rewrite of
`include_str!` and `concat!` (§2.3.2.5) is realizable; macro expansion
is otherwise inside-out and `mask!` would receive unexpanded token
trees rather than literals.

§2.1.1.7 — Each `mask!` invocation SHALL produce ciphertext using a unique
nonce derived per §1.5.2.

§2.1.1.8 — Two builds with the same source code, same toolchain, same
dependencies, and same `LITMASK_RNG_SEED` SHALL produce byte-identical
ciphertext for each `mask!` invocation.

§2.1.1.9 — `mask!` SHALL NOT be usable in `const` or `static` initializers;
the compile error SHALL include the substring "mask! cannot be used in const
or static contexts".

§2.1.1.10 — `mask!` SHALL NOT be usable in pattern positions (match arms,
`if let`); the compile error SHALL include the substring "mask! cannot be
used in pattern position".

§2.1.1.11 — Decryption failure on a `mask!` invocation SHALL panic per the
policy in §1.9.5.

§2.1.1.12 — Calling `mask!` before `litmask::init()` or `litmask::init_with()`
SHALL trigger lazy initialization using the default `EnvVarProvider`.

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

### §2.2 Iteration 2 — Format string masking (maskfmt!)

#### §2.2.1 Acceptance criteria

§2.2.1.1 — `maskfmt!` SHALL accept a string literal template as its first
argument, followed by zero or more format arguments matching `format!`'s
signature.

§2.2.1.2 — `maskfmt!` SHALL return a value of type `String`.

§2.2.1.3 — `maskfmt!` SHALL produce a compile error when its first argument is
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

§2.2.2.8 — The output of `maskfmt!(template, args...)` SHALL be identical to
the output of `format!(template, args...)` for all supported format
features.

#### §2.2.3 Equivalent format! semantics

§2.2.3.1 — `maskfmt!` SHALL NOT introduce observable differences from
`format!` in argument evaluation order, evaluation count, or panicking
behavior.

§2.2.3.2 — `maskfmt!` SHALL pass through `format!`'s compile-time format
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
- Inside `mask!`, `maskfmt!`, or `unmasked!` invocations

§2.3.1.4 — `#[mask_all]` SHALL emit a compile-time warning for each literal
it skips, identifying the file, line, and reason for the skip.

> **Amendment 2026-05-10:** Until `proc_macro::Diagnostic::emit`
> stabilizes on stable Rust, the warning emission mechanism SHALL be
> the **ghost-deprecation hack**. For each skip, the proc-macro SHALL
> inject an unused item of the form
>
> ```rust
> #[deprecated(note = "litmask: skipped literal at <file>:<line>: <reason>")]
> #[allow(non_upper_case_globals)]
> const _LITMASK_SKIP_<n>: () = ();
> let _ = _LITMASK_SKIP_<n>;
> ```
>
> into the rewritten output, where `<n>` is a per-module monotonic
> counter ensuring uniqueness and `<reason>` is a short ASCII tag
> (e.g., `pattern_position`, `const_initializer`, `unrecognized_macro`).
> The `let _` reference triggers rustc's `deprecated` lint, which
> surfaces as a normal `warning: use of deprecated constant
> _LITMASK_SKIP_<n>: litmask: skipped literal at ...` in cargo output.
> Under `#[mask_all(strict)]`, the proc-macro SHALL substitute
> `compile_error!("litmask: ...")` for the ghost-item pattern so the
> same skip becomes a hard error. Migration to `Diagnostic::emit` is
> a v2 candidate; the warning text format above is normative and MUST
> NOT change without a minor-version bump (so downstream tooling that
> greps cargo output remains stable).

§2.3.1.5 — `#[mask_all]` SHALL recurse into nested modules, functions,
blocks, and closures within the attributed module.

§2.3.1.6 — `#[mask_all]` SHALL NOT see code emitted by other macros
expanding within its module (proc-macro expansion is outside-in; derives
expand after attribute proc-macros).

#### §2.3.2 Substitution table

§2.3.2.1 — Bare string literal expressions SHALL be rewritten to
`mask!(literal)`.

§2.3.2.2 — `format!(template, args...)` SHALL be rewritten as follows:
- If `template` is a string literal: rewrite to `maskfmt!(template, args...)`.
- If `template` is not a string literal: leave `format!` unchanged;
  recursively mask any string-literal arguments in `args...`. Emit a
  compile-time warning identifying the unmasked template.

§2.3.2.3 — Output macros (`println!`, `eprintln!`, `print!`, `eprint!`,
`write!`, `writeln!`) SHALL be rewritten as follows:
- If their template is a string literal: rewrite to
  `{ let __s = maskfmt!(template, args...); <original_macro>("{}", __s) }`,
  preserving the original return type and side effects.
- If their template is not a string literal: leave the macro unchanged;
  recursively mask any string-literal arguments. Emit a compile-time warning.

§2.3.2.4 — Panic macros (`panic!`, `todo!`, `unimplemented!`,
`debug_assert!`, and `assert!`/`assert_eq!`/`assert_ne!` with custom message
form) SHALL be rewritten analogously to §2.3.2.3, wrapping the masked format
result in a literal `"{}"` template when the original template is a literal;
otherwise left unchanged with literal arguments masked recursively.

§2.3.2.5 — `include_str!` and `concat!` SHALL be wrapped: the entire macro
invocation result is wrapped in `mask!()` so the resulting string is masked.

> **Amendment 2026-05-10:** The wrapping produces the literal source
> form `mask!(include_str!(<args>))` and `mask!(concat!(<args>))`
> respectively. These forms are accepted by `mask!`'s extended grammar
> per §2.1.1.14 and resolved at proc-macro time. No companion
> `mask_internal!` macro is introduced; the user-facing API remains a
> single `mask!`.

§2.3.2.6 — `dbg!`, `stringify!`, `assert_eq!`/`assert_ne!` (without custom
message) SHALL be skipped without modification.

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

§2.4.1.1 — `litmask-build::emit()` SHALL be invokable as a one-line
`build.rs`.

§2.4.1.2 — `emit()` SHALL determine the build profile from the `PROFILE`
environment variable.

§2.4.1.3 — In debug profile, `emit()` SHALL source `RNG_SEED` in priority
order: `LITMASK_RNG_SEED` env var, then `target/litmask-seed`, then generate
fresh and persist to `target/litmask-seed`.

§2.4.1.4 — In release profile, `emit()` SHALL source `RNG_SEED` from
`LITMASK_RNG_SEED` env var if set; otherwise generate fresh and NOT persist.

§2.4.1.5 — In release profile, when `RNG_SEED` is freshly generated (not
sourced from `LITMASK_RNG_SEED`), `emit()` SHALL print the seed via
`cargo:warning=` directives:

```
warning: litmask: release build using fresh RNG seed: <base64url>
warning: litmask: to reproduce this build, set LITMASK_RNG_SEED to the value above
```

§2.4.1.6 — `emit()` SHALL generate `mask_key` and `unlock_key`
deterministically from `RNG_SEED` using `rand_chacha::ChaCha20Rng`.

§2.4.1.7 — `emit()` SHALL write the plaintext `mask_key` to a binary file at
`$OUT_DIR/litmask_key.bin` and the `RNG_SEED` to
`$OUT_DIR/litmask_seed.bin`, to be consumed by the proc-macro via
`include_bytes!`.

§2.4.1.8 — `emit()` SHALL NOT emit `mask_key` or `RNG_SEED` via
`cargo:rustc-env` directives, for the leakage reasons documented in §1.3.1.

§2.4.1.9 — `emit()` SHALL emit only the following Cargo directives:
- `cargo:rerun-if-env-changed=LITMASK_RNG_SEED`
- `cargo:rerun-if-changed=build.rs`
- (release-only, when fresh) `cargo:warning=...` per §2.4.1.5

§2.4.1.10 — `emit()` SHALL write `litmask.config` to the location specified
in §1.7.5 with the schema specified in §1.7.4.

§2.4.1.11 — `emit()` SHALL write a deployer-facing comment block at the top
of `litmask.config` describing the file's purpose and warning that it is
secret.

#### §2.4.2 Configuration validation

§2.4.2.1 — `emit()` SHALL succeed without a project-level configuration
file; no `litmask.toml` or equivalent is read in v1.

### §2.5 Iteration 5 — Key providers

#### §2.5.1 KeyProvider trait

§2.5.1.1 — `KeyProvider` SHALL be a public trait with method
`unlock_key(&self) -> Result<UnlockKey, KeyError>`.

§2.5.1.2 — `KeyProvider` SHALL be object-safe (usable as
`Box<dyn KeyProvider>`).

§2.5.1.3 — `UnlockKey` SHALL be a newtype wrapping `[u8; 32]` with `Drop`
zeroing its contents.

§2.5.1.4 — `UnlockKey` SHALL provide constructors from `[u8; 32]` and from
base64url-encoded `&str`, the latter returning `Result<UnlockKey, KeyError>`.

§2.5.1.5 — `KeyProvider` SHALL NOT have a `deployment_hint()` method or any
other method whose return value would embed English-language strings in
binaries that depend on `litmask`.

#### §2.5.2 EnvVarProvider

§2.5.2.1 — `EnvVarProvider::new(var_name: &'static str)` SHALL construct a
provider that reads from the named environment variable.

§2.5.2.2 — `EnvVarProvider::default()` SHALL read from `LITMASK_UNLOCK_KEY`.

§2.5.2.3 — `EnvVarProvider::unlock_key()` SHALL return:
- `Err(KeyError::NotFound)` if the env var is unset
- `Err(KeyError::InvalidFormat)` if the value is not valid base64url
- `Err(KeyError::InvalidFormat)` if the decoded value is not 32 bytes
- `Ok(UnlockKey)` otherwise

#### §2.5.3 FileProvider

§2.5.3.1 — `FileProvider::new(path: impl Into<PathBuf>)` SHALL construct a
provider that reads from the specified path with default base64url encoding.

§2.5.3.2 — `FileProvider::with_encoding(path, encoding)` SHALL construct a
provider with the specified encoding (`KeyEncoding::Base64Url` or
`KeyEncoding::Raw`).

§2.5.3.3 — `FileProvider::unlock_key()` SHALL return:
- `Err(KeyError::NotFound)` if the file does not exist
- `Err(KeyError::Permission)` if the file exists but cannot be read
- `Err(KeyError::InvalidFormat)` if the contents do not parse as the
  configured encoding or do not produce 32 bytes
- `Ok(UnlockKey)` otherwise

§2.5.3.4 — `FileProvider` SHALL zero its in-memory copy of file contents
immediately after extracting the key.

#### §2.5.4 HardwareIdProvider (gated by `hw-id` feature)

§2.5.4.1 — `HardwareIdProvider::new()` SHALL construct a provider with no
salt.

§2.5.4.2 — `HardwareIdProvider::with_salt(salt: &'static [u8])` SHALL
construct a provider that mixes the salt with the hardware ID via
BLAKE3-keyed-hash.

§2.5.4.3 — `HardwareIdProvider::unlock_key()` SHALL:
- Read the machine ID via `machine-uid::get()`
- Apply BLAKE3-keyed-hash with the salt (or zero salt if none) to derive a
  32-byte key
- Return `Err(KeyError::Provider(...))` if `machine-uid` fails
- Return `Ok(UnlockKey(derived_bytes))` otherwise

#### §2.5.5 StaticProvider

§2.5.5.1 — `StaticProvider::new(key: UnlockKey)` SHALL construct a provider
that always returns the given key.

§2.5.5.2 — `StaticProvider::unlock_key()` SHALL return `Ok(self.key.clone())`
unconditionally.

### §2.6 Iteration 6 — Runtime initialization

#### §2.6.1 init functions

§2.6.1.1 — `litmask::init() -> Result<(), InitError>` SHALL initialize the
runtime using `EnvVarProvider::default()`.

§2.6.1.2 — `litmask::init_with<P: KeyProvider>(provider: P) -> Result<(), InitError>`
SHALL initialize the runtime using the given provider.

§2.6.1.3 — Both init functions SHALL retrieve `unlock_key` via
`provider.unlock_key()`, decrypt the embedded `mask_key` wrapper (format per
§1.7.3), and store the result in the global `OnceLock`.

§2.6.1.4 — Successive calls to `init()` or `init_with()` after successful
initialization SHALL return `Ok(())` without re-running the provider
(idempotent).

§2.6.1.5 — Successive calls after a failed initialization SHALL retry the
provider call.

§2.6.1.6 — Lazy initialization (triggered by first `mask!()` call without
prior `init()`) SHALL behave equivalently to explicit `init()`, except that
lazy init failures result in panic per §2.1.1.13 rather than `Result` return.

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
cipher compiled per build, selected by the `aes-gcm` Cargo feature.

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

§2.7.9 — Cipher id byte in the wrapper SHALL be `0x01` for ChaCha20-Poly1305
and `0x02` for AES-256-GCM.

§2.7.10 — Nonce derivation SHALL NOT depend on global state shared between
proc-macro expansions; each invocation derives its nonce solely from its
source location and the build seed.

### §2.8 Iteration 8 — Locator-based binding format

#### §2.8.1 Binary embedding

§2.8.1.1 — The encrypted `mask_key` wrapper SHALL be embedded in the
compiled binary as an ordinary `[u8; 62]` static, with no `#[link_section]`,
no `#[no_mangle]` marker, and no symbol name suggesting `litmask`.

§2.8.1.2 — The wrapper's location in the binary SHALL be discoverable solely
by scanning for its first 12 bytes (the locator).

§2.8.1.3 — Per-string encrypted blobs (output of `mask!` invocations) SHALL
be embedded similarly as ordinary statics with no identifying markers, no
fixed header bytes, and no symbol naming convention attributable to
`litmask`.

#### §2.8.2 litmask.config

§2.8.2.1 — `litmask.config` SHALL be a TOML file conforming to the schema
in §1.7.4.

§2.8.2.2 — `unlock_key` and `locator` fields SHALL be base64url-encoded
without padding.

§2.8.2.3 — The `length` field SHALL equal the byte count of the full
encrypted `mask_key` wrapper (62 in v1, per §1.7.3).

### §2.9 Iteration 9 — CLI tooling

CLI exit codes follow the sysexits.h mapping documented in §1.9.7. The CLI's
own non-litmask-specific failures (argument parsing errors, file I/O errors
not corresponding to a `litmask` semantic) follow standard sysexits
conventions: EX_USAGE (64) for argument errors, EX_NOINPUT (66) for missing
files.

#### §2.9.1 litmask-cli bind

§2.9.1.1 — `litmask-cli bind <binary> --config <litmask.config> [--salt <BASE64URL>]`
SHALL rebind the binary per the workflow in §1.7.6, using the atomic commit
protocol in §1.7.7.

§2.9.1.2 — v1 SHALL support hardware-ID binding only. The `bind` command
does NOT accept a `--provider` flag in v1; future versions may extend it.

§2.9.1.3 — `bind` SHALL exit with the following codes and printed messages
on failure conditions:
- EX_DATAERR (65) and `ambiguous` if multiple locator matches occur in the
  binary
- EX_NOINPUT (66) and `not_found` if no locator match occurs
- EX_DATAERR (65) and `decryption_failed` on AEAD authentication failure
  during wrapper decryption
- EX_UNAVAILABLE (69) and `hardware_id_unavailable` if the hardware ID
  cannot be read
- EX_OK (0) on success

§2.9.1.4 — `bind` SHALL fail without modifying the binary or the config if
any step before the in-place write fails.

§2.9.1.5 — `bind` SHALL preserve all binary metadata not within the rebound
region (symbol tables, section headers, signatures — though re-signing is
the user's responsibility).

§2.9.1.6 — *(added by Amendment 2026-05-10)* `bind` SHALL select the
cipher used for wrapper decryption and re-encryption based on the
cipher-id byte in the wrapper read from the target binary, dispatching
between `chacha20poly1305` (`0x01`) and `aes-gcm` (`0x02`) at runtime.
A cipher-id byte that is neither `0x01` nor `0x02` SHALL cause `bind`
to exit EX_DATAERR (65) with the message `unsupported_cipher` without
modifying the binary or the config. The same dispatch rule SHALL apply
to any future CLI subcommand that decrypts a wrapper.

#### §2.9.2 litmask-cli inspect

§2.9.2.1 — `litmask-cli inspect <binary> --config <litmask.config>` SHALL
verify that the locator in `--config` is findable in the binary.

§2.9.2.2 — `inspect` SHALL exit with:
- EX_OK (0) and print `verified` if exactly one match is found
- EX_DATAERR (65) and print `ambiguous:<count>` if multiple matches are
  found
- EX_NOINPUT (66) and print `not_found` if no match is found

§2.9.2.3 — `inspect` SHALL NOT modify the binary or the config.

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
- `litmask-cli bind` correctly rebinds binaries to new keys
- The atomic commit protocol from §1.7.7 holds under simulated mid-bind
  failures, including the parent-directory fsync requirement on POSIX and
  the `MOVEFILE_WRITE_THROUGH` requirement on Windows
- `InitError::sysexit_code()` returns the values specified in §1.9.7 for
  each variant

§2.12.1.5 — Integration tests SHALL include at least one example binary per
`KeyProvider`.

§2.12.1.6 — Fuzz targets (§1.10.4) SHALL include `parse_format_template`
(maskfmt parser) and `locator_scan` (CLI scanner). CI SHALL run each for at
least 10 seconds per PR. Fuzz corpora SHALL be committed to the repository
and grow from CI findings.

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
the test binary in both pre-bind and post-bind states and assert that no
embedded marker appears in the output. If any marker is found, the job
SHALL fail.

§2.13.2.3 — On platforms where `machine-uid` produces a stable identifier
(Ubuntu, AlmaLinux, macOS, Windows, FreeBSD, and OpenBSD instances with
provisioned machine ID), `litmask-cli bind` SHALL succeed and the bound
binary SHALL execute correctly with output matching expected plaintext.

§2.13.2.4 — On platforms where `machine-uid` does NOT produce a stable
identifier (stock OpenBSD without provisioned machine ID), `litmask-cli bind`
SHALL fail with EX_UNAVAILABLE (69) and the test SHALL assert this failure
mode rather than treating it as a test failure. This validates §1.6.5's
documented portability behavior.

§2.13.2.5 — Each platform smoke test SHALL perform a rebind cycle: bind
once, verify execution, bind a second time with a different `--salt` value,
verify execution again. The rebind cycle is omitted on platforms covered by
§2.13.2.4.

§2.13.2.6 — Platform smoke tests SHALL be written in a CI-portable shell
script invocable from the GitHub Actions YAML for native platforms and from
the `cross-platform-actions/action` `run:` block for VM platforms.

---

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
- Programmatic config parsing (`serde` feature)
- Control-flow obfuscation
- Code-signing-aware binding
- Custom-provider binding via `litmask-cli` (v1 supports hardware-ID only)
- NetBSD, DragonFly BSD, Illumos platform CI

Per-string key derivation is rejected, not deferred — see §1.5.5.

## Appendix C — Glossary

- **mask_key**: 32-byte symmetric key used to encrypt all string literal
  ciphertext in the binary. Stored in the binary, encrypted with
  `unlock_key`, inside the encrypted `mask_key` wrapper.
- **unlock_key**: 32-byte symmetric key used to encrypt `mask_key` for
  storage in the binary. Supplied at runtime via `KeyProvider`.
- **layered key strategy**: The only key strategy in v1. `mask_key` is
  encrypted with `unlock_key` and embedded in the binary; `unlock_key` is
  supplied at runtime.
- **locator**: First 12 bytes of the encrypted `mask_key` wrapper, used to
  find the wrapper's location in the binary during binding operations.
  Stored in `litmask.config`.
- **binding**: The process of replacing the embedded encrypted `mask_key`
  wrapper with a re-encryption under a new `unlock_key` derived from
  hardware ID. Performed by `litmask-cli bind`.
- **wrapper**: The 62-byte structure containing the encrypted `mask_key`
  along with format version, cipher id, nonce, and authentication tag.
- **AEAD**: Authenticated Encryption with Associated Data. The cipher class
  used by `litmask` (ChaCha20-Poly1305 and AES-256-GCM both qualify).
- **sysexits**: BSD `<sysexits.h>` standard exit codes (0, 64-78). Used by
  `InitError::sysexit_code()` for plaintext-free error signaling.
