# Deployment Guide

## Governing a dependency graph

litmask is governed by the **host binary**, not by the libraries it links.
By convention, **masking libraries never call `init!()`** — they only
`mask!()`, and rely on lazy unlock. You, the binary owner, choose how the
whole graph (your crate plus every transitive masking dependency) is
unlocked:

- **Transparent masking** — do nothing. Every masking crate self-unlocks
  at the keyless **Embedded floor** on first use. No provisioning, but
  `strings(1)`-resistance only; the key is recoverable from the artifact.
- **Governed masking** — put one unlock key in the **build** environment
  so it reaches every crate's `build.rs`/`emit()`, then call a single
  governing `init!(provider)`, `init!(bind_to_machine)`, or
  `init!(bind_to_machine + provider)` at startup. That one key unlocks the
  entire graph with real secrecy.

```sh
# Uniform seal: this key reaches every masking crate's emit() in the graph.
LITMASK_UNLOCK_KEY='…' cargo build --release
# Runtime: one governing init! unlocks the whole graph.
LITMASK_UNLOCK_KEY='…' ./my_app
```

The seal tier is uniform by construction — it is fixed by the shared build
environment, so a dependency graph is uniformly Embedded, External, or
Machine. There is no per-library configuration. A masking library that
calls `init!()` (or masks in a `static`/constructor before the host's
governing init! runs) seizes governance from the host and must be treated
as a bug. See
[ADR-0001](adr/0001-masking-crate-unlock-governance.md).

## Key providers

### `EnvVarProvider` (External tier)

The External tier seals the build under the unlock **material** you put
in `LITMASK_UNLOCK_KEY` at build time, then re-supplies that same
material at runtime. The provider derives the key from the raw bytes
(`unlock_key = KDF("litmask-unlock-v1", material)`); it is not an encoded
key, so the material can be any non-empty byte string (an empty value —
the classic unpopulated-CI-secret expansion — fails the build):

```sh
# Build seals the External tier under this material.
LITMASK_UNLOCK_KEY='correct horse battery staple' cargo build --release

# Runtime re-supplies the identical material.
LITMASK_UNLOCK_KEY='correct horse battery staple' ./my_app
```

Inject via systemd `EnvironmentFile=`, Kubernetes secrets, or your
orchestrator's env-var mechanism. The material must not be committed to
version control. A single trailing newline is stripped, so the env and
file channels agree on the same secret regardless of how it was written.

Need fresh material? Install the helper once with `cargo install
litmask-cli` (it puts a `litmask` binary on your `PATH`). `litmask keygen`
then mints 32 random bytes as base64url on stdout — a high-entropy
`LITMASK_UNLOCK_KEY` you can pipe into the build or stash in a secret
store:

```sh
LITMASK_UNLOCK_KEY="$(litmask keygen)" cargo build --release
```

### `FileProvider` (External tier)

Point to a file whose contents are the unlock material — the same value
the build was sealed with:

```rust
use litmask::{FileProvider, init};

let provider = FileProvider::new("/run/secrets/litmask_key");
init!(provider).expect("init");
```

The file holds raw material (any length, no encoding); `FileProvider`
derives the key the same way `EnvVarProvider` does. Set filesystem
permissions so only the application user can read it (`chmod 400`).

### Machine tier (`init!(bind_to_machine)`)

The Machine tier seals the build's `unlock_key` to a host's machine ID at
**build** time. Enable the `machine-id` feature on the `litmask`
dependency (`cargo add litmask --features machine-id` — it is litmask's
feature, so `cargo build --features machine-id` alone would be rejected),
then set `LITMASK_MACHINE_ID` to the target host's id (the CLI prints it)
and build:

```sh
LITMASK_MACHINE_ID="$(litmask show-machine-id)" \
    cargo build --release
```

```rust
litmask::init!(bind_to_machine)?;
```

At runtime `init!(bind_to_machine)` recomputes the host id locally via
`machine_uid::get()` and re-derives the same key — so the binary decrypts
only on the host it was sealed for, with no environment variable or key
file required. Re-targeting a different host means rebuilding with that
host's `LITMASK_MACHINE_ID`. See the
[README](../README.md#machine-id-binding) for the full walkthrough.

### Two-factor tier (`init!(bind_to_machine + provider)`)

Set **both** `LITMASK_MACHINE_ID` and `LITMASK_UNLOCK_KEY` at build time to
seal the MachineExternal tier. At runtime the binary decrypts only on the
sealed host **and** with the sealed external material — either factor wrong
fails the wrapper's AEAD check:

```sh
LITMASK_MACHINE_ID="$(litmask show-machine-id)" \
LITMASK_UNLOCK_KEY="$(litmask keygen)" \
    cargo build --release
```

```rust
let provider = litmask::EnvVarProvider::default(); // LITMASK_UNLOCK_KEY
litmask::init!(bind_to_machine + provider)?;
```

The machine factor is recomputed from the host (no provisioning); the
external factor is re-supplied at runtime exactly as in the External tier
above (env var, file, or custom provider).

### Custom provider

Implement `KeyProvider` for any key source (vault, HSM, network
service):

```rust
use litmask::{KeyProvider, UnlockKey, UnlockMaterial, KeyError};

/// Holds the sealed material fetched from your vault — any non-empty
/// bytes; empty surfaces as `KeyError::InvalidFormat` via `?`.
struct VaultProvider(Vec<u8>);

impl KeyProvider for VaultProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        Ok(UnlockKey::derive(UnlockMaterial::new(&self.0)?))
    }
}
```

## Recommended release profile

```toml
[profile.release]
strip = "symbols"
debug = false
panic = "abort"
lto = true
```

| Setting | Rationale |
|---|---|
| `strip = "symbols"` | Removes symbol names that could identify internal functions or crate names. |
| `debug = false` | Eliminates DWARF debug info that maps binary offsets to source locations. |
| `panic = "abort"` | Removes unwind tables and panic formatting machinery, reducing string surface. |
| `lto = true` | Link-time optimization across crate boundaries enables dead-code elimination of unreachable error paths. |

These settings reduce the binary's string surface area. They are
recommendations, not requirements — `litmask` works with any profile.

### Removing dependency fingerprints (nightly hardening)

`strip = "symbols"` removes the symbol table but **not** `.rodata`
string constants. The largest remaining tell is the panic-location
path string Rust embeds for bounds-check and assert sites — for
example, a binary sealed under the machine tier or using `weak_mask!`
carries:

```text
.../registry/src/index.crates.io-.../blake3-<version>/src/lib.rs
```

This is not unique to BLAKE3: every panic-capable dependency embeds its
own `crate-version/src/….rs` path, and `litmask`'s own
`litmask/src/runtime/mod.rs` leaks the same way. Swapping the hash crate
only changes which name appears — it does not remove the class.

Two nightly `rustc` flags remove these strings for every crate compiled
in the build (zero source change):

```sh
RUSTFLAGS="-Zlocation-detail=none -Zfmt-debug=none" \
    cargo +nightly build --release
```

| Flag | Effect |
|---|---|
| `-Zlocation-detail=none` | Blanks file/line/column in panic-location records → removes all `crate-version/src/….rs` path strings (`blake3`, `cipher`, `base64ct`, and `litmask`'s own). |
| `-Zfmt-debug=none` | Strips `derive(Debug)` name strings → removes dependency error-type names such as `StreamCipherError` and `MachineUidError`. |

Measured on the `machine_id_provider` example (release + strip): the
`blake3` and `litmask` path-string counts both drop from nonzero to
**0**.

Two categories survive and are intentionally acceptable:

- **Rust backtrace machinery** (`addr2line`, `gimli`, `object`,
  `rustc-demangle` paths). These live in precompiled `std`, so in-build
  RUSTFLAGS cannot reach them; `panic = "abort"` does not drop them
  either. They appear in every Rust binary and reveal nothing about
  `litmask` or its cryptography. Removing them requires
  `-Z build-std`.
- **`litmask`'s own `category:variant` Display tags** (e.g.
  `unsupported_format`, `decryption_failed`). These are deliberately
  generic ASCII tags (spec §1.9.3), not `litmask`-identifying.

Both flags are **nightly-only and unstable**, so this recipe cannot be
part of the stable canonical build. Use it only if hiding the
dependency fingerprint is in your threat model; the stable
`strip`-based profile above remains the supported default.

## Machine-tier deployment workflow

The Machine tier is sealed at **build** time, so the per-host targeting
happens in the build, not on the deployment host (the `machine-id`
feature enabled on the `litmask` dependency — see
[Machine tier](#machine-tier-initbind_to_machine)). The binary then runs
on its sealed host with no config, key file, or CLI present:

```sh
LITMASK_MACHINE_ID="$(litmask show-machine-id)" \
    cargo build --release

scp target/release/my_app deploy@host:/opt/my_app/
ssh deploy@host '/opt/my_app/my_app'   # decrypts; no extra material
```

Re-targeting a different host means rebuilding with that host's
`LITMASK_MACHINE_ID`.

### Off-box (vendor-side) sealing

When you build for a host you cannot reach at build time — the customer's
machine is air-gapped, or you seal in a build pipeline — seal against a
machine ID the target reports:

1. **Enroll.** The target host reports its machine ID via the CLI's
   enrollment primitive:

   ```sh
   litmask show-machine-id
   # FB1128DE-C00C-5643-BCF4-5487AFA3245A.sE1d6WI
   ```

   `show-machine-id` prints a **self-checking token** — the host
   identifier (nothing secret), a `.`, and a short checksum — to stdout,
   with usage prose on stderr. The customer can return the token over any
   channel; the checksum lets the build reject a token mangled in transit.

2. **Seal vendor-side.** Build with the reported token and ship the
   binary; it decrypts only on the host whose ID was supplied. `emit()`
   validates the token's checksum and aborts the build on a mistyped id:

   ```sh
   LITMASK_MACHINE_ID="FB1128DE-C00C-5643-BCF4-5487AFA3245A.sE1d6WI" \
       cargo build --release
   ```

## Sysexits.h exit code reference

Binaries using `InitError::sysexit_code()` exit with these codes on
init failure:

| Code | Name | Variant | Meaning |
|---|---|---|---|
| 65 | `EX_DATAERR` | `KeyProvider(InvalidFormat)`, `Decryption` | Malformed key data or AEAD authentication failure |
| 69 | `EX_UNAVAILABLE` | `KeyProvider(Provider(_))` | Provider-specific failure (network, service, machine ID unavailable) |
| 70 | `EX_SOFTWARE` | `UnsupportedFormat` | Wrapper format version unknown to this runtime |
| 77 | `EX_NOPERM` | `KeyProvider(Permission)` | OS-level permission denied reading key |
| 78 | `EX_CONFIG` | `KeyProvider(NotFound)` | Missing key (env var unset, file absent) |

These are standard BSD sysexits.h codes. Operators can interpret them
without litmask-specific knowledge:

```sh
./my_app
echo $?   # 78 → missing configuration
```

## What litmask does NOT protect against

litmask does not defend against runtime memory inspection, debugger
attachment, compromised runtime environments, side-channel attacks, or
control-flow/anti-debugging analysis. See
[THREAT_MODEL.md](THREAT_MODEL.md) for the full out-of-scope list and the
configuration-to-resistance ladder.
