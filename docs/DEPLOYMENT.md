# Deployment Guide

## Key providers

### `EnvVarProvider` (default)

Set `LITMASK_UNLOCK_KEY` to the base64url-encoded key from
`litmask.config`:

```sh
LITMASK_UNLOCK_KEY=$(awk -F'"' '/^unlock_key/ {print $2}' litmask.config) \
    ./my_app
```

Inject via systemd `EnvironmentFile=`, Kubernetes secrets, or your
orchestrator's env-var mechanism. The key must not be committed to
version control.

### `FileProvider`

Point to a file containing the key:

```rust
use litmask::{FileProvider, KeyEncoding};

let provider = FileProvider::new("/run/secrets/litmask_key", KeyEncoding::Base64Url);
litmask::init_with!(provider).expect("init");
```

Set filesystem permissions so only the application user can read the
key file (`chmod 400`).

### `HardwareIdProvider`

Bind the binary to the deployment host's machine ID:

```sh
litmask bind target/release/my_app \
    --config target/release/litmask.config
```

The binary decrypts only on the machine it was bound to. No environment
variable or key file required at runtime.

`bind` also works with `EnvVarProvider` binaries — the updated config
contains the hardware-derived key, which can be injected as the
environment variable. See the [README](../README.md#hardware-binding-litmask-cli-bind)
for details.

### Custom provider

Implement `KeyProvider` for any key source (vault, HSM, network
service):

```rust
use litmask::{KeyProvider, UnlockKey, KeyError};

struct VaultProvider { /* ... */ }

impl KeyProvider for VaultProvider {
    fn unlock_key(&self) -> Result<UnlockKey, KeyError> {
        // fetch 32 raw bytes from your vault
        todo!()
    }
}
```

## `litmask.config` handling

`litmask-build::emit()` writes `litmask.config` to the Cargo target
directory at compile time. It contains the `unlock_key` (secret) and
`locator` (non-secret wrapper identifier).

**Do not commit `litmask.config` to version control.** Add it to
`.gitignore`:

```gitignore
litmask.config
```

For CI/CD pipelines that build and deploy, extract the key from the
config after the build step and inject it into the deployment
environment.

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

## Rebind workflow

For deployments using `HardwareIdProvider`, bind the binary on the
target host after copying:

```sh
scp target/release/my_app deploy@host:/opt/my_app/
scp target/release/litmask.config deploy@host:/opt/my_app/

ssh deploy@host 'litmask bind /opt/my_app/my_app \
    --config /opt/my_app/litmask.config'
```

To rebind with a different salt (e.g., per-product isolation):

```sh
litmask bind /opt/my_app/my_app \
    --config /opt/my_app/litmask.config \
    --salt "$(echo -n 'product-v1' | base64url)"
```

The binary must use `HardwareIdProvider::with_salt(b"product-v1")` at
compile time for the salt to match at runtime.

### Off-box (vendor-side) binding

`bind` derives the new `unlock_key` from the machine ID of *the host it
runs on*. The simplest workflow runs `bind` on the deployment host (the
`ssh` recipe above), so the CLI must be present there.

When the CLI cannot run on the target — the customer never receives
litmask tooling, the host is air-gapped, or you bind in a build pipeline
— bind off-box against a machine ID the target reports:

1. **Enroll.** The target host reports its machine ID. Ship a one-shot
   helper, or run the CLI's enrollment primitive there:

   ```sh
   litmask show-hw-id
   # FB1128DE-C00C-5643-BCF4-5487AFA3245A
   ```

   `show-hw-id` prints the exact bytes `HardwareIdProvider` feeds into
   its key derivation — nothing secret, just the host identifier — so
   the customer can return it over any channel.

2. **Bind vendor-side.** With the reported ID, bind off-box and ship the
   already-bound binary plus its updated config:

   ```sh
   # PLANNED — see TASKS.md Task 34. Not yet implemented.
   litmask bind my_app \
       --config litmask.config \
       --machine-id FB1128DE-C00C-5643-BCF4-5487AFA3245A
   ```

   The bound binary decrypts only on the host whose ID was supplied.

> **Status:** the `--machine-id` flag is not yet wired into the CLI.
> `bind`'s pure planner already accepts a caller-supplied machine ID;
> only the command-line surface is missing. Until it lands, off-box
> binding requires running `bind` on the target host.

## Sysexits.h exit code reference

Binaries using `InitError::sysexit_code()` exit with these codes on
init failure:

| Code | Name | Variant | Meaning |
|---|---|---|---|
| 65 | `EX_DATAERR` | `KeyProvider(InvalidFormat)`, `Decryption` | Malformed key data or AEAD authentication failure |
| 69 | `EX_UNAVAILABLE` | `KeyProvider(Provider(_))` | Provider-specific failure (network, service, hardware ID unavailable) |
| 70 | `EX_SOFTWARE` | `UnsupportedFormat`, `UnsupportedCipher` | Format version or cipher feature mismatch |
| 77 | `EX_NOPERM` | `KeyProvider(Permission)` | OS-level permission denied reading key |
| 78 | `EX_CONFIG` | `KeyProvider(NotFound)` | Missing key (env var unset, file absent) |

These are standard BSD sysexits.h codes. Operators can interpret them
without litmask-specific knowledge:

```sh
./my_app
echo $?   # 78 → missing configuration
```

## What litmask does NOT protect against

- Runtime memory inspection
- Debugger attachment after key derivation
- Compromised runtime environments
- Side-channel attacks (timing, power analysis)
- Control-flow obfuscation or anti-debugging

See [THREAT_MODEL.md](THREAT_MODEL.md) for the full scope.
