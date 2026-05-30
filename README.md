# litmask

[![crates.io](https://img.shields.io/crates/v/litmask.svg)](https://crates.io/crates/litmask)
[![docs.rs](https://img.shields.io/docsrs/litmask)](https://docs.rs/litmask)
[![CI](https://github.com/camercu/litmask/actions/workflows/ci.yml/badge.svg)](https://github.com/camercu/litmask/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/rustc-1.88+-blue.svg)](https://github.com/camercu/litmask)
[![License](https://img.shields.io/crates/l/litmask.svg)](#license)

**Hide string literals from `strings(1)` and hex editors.** AEAD-encrypt
every string constant at compile time, decrypt at runtime. Drop-in
macros, layered key management, `no_std` ready.

```rust
use litmask::mask;

fn main() -> Result<(), litmask::InitError> {
    litmask::init!()?;
    println!("{}", mask!("sensitive data"));
    Ok(())
}
```

```sh
strings target/release/my_app | grep "sensitive data"   # no output
```

`mask!` returns an owned `String` (decryption happens at runtime), not
`&str` — bind `let s: &str = &mask!("...");` when you need a borrow. See
[Macros](#macros) for the full caveat and `weak_mask!`.

## Why litmask

| | `obfstr` | `litcrypt` | **`litmask`** |
|---|---|---|---|
| Cipher | XOR | XOR | **ChaCha20-Poly1305 / AES-256-GCM** |
| Tamper detection | No | No | **Yes (AEAD)** |
| Key model | Compile-time random | Single env var | **Layered providers** |
| Format strings | No | No | **`mask_format!`** |
| Module-level | No | No | **`#[mask_all]`** |
| Hardware binding | No | No | **`litmask bind`** |
| Literal types | `str` | `str` | **str / bytes / cstr** |
| `no_std` | Limited | No | **Yes** |
| Reproducible builds | No | No | **Yes** |

## Quick start

Requires Rust 1.88+.

```sh
cargo add litmask
cargo add --build litmask-build
```

```rust
// build.rs
fn main() { litmask_build::emit(); }
```

```sh
cargo build
LITMASK_UNLOCK_KEY=$(awk -F'"' '/^unlock_key/ {print $2}' target/debug/litmask.config) \
    cargo run
```

`litmask_build::emit()` writes `litmask.config` to the build profile
directory (`target/debug/` here). The `awk` one-liner reads its
`unlock_key` and exports it as `LITMASK_UNLOCK_KEY`, which the default
`EnvVarProvider` uses to unwrap the mask key at runtime.

## How it works

litmask splits encryption across build time and run time:

1. **Build** — `litmask_build::emit()` (in `build.rs`) generates a random
   seed, derives the `mask_key`, and writes `litmask.config` plus the env
   vars the proc macro reads.
2. **Compile** — each `mask!` literal is AEAD-encrypted during macro
   expansion and the ciphertext is embedded in the binary as `&[u8]`. The
   plaintext never appears in the output.
3. **Run** — `init!()` unwraps the `mask_key` using an `unlock_key`
   supplied by a [`KeyProvider`](#key-providers); `mask!` then decrypts
   each blob on demand.

The `unlock_key` is the only secret that lives outside the binary, so key
management reduces to *how you deliver the unlock_key* — environment
variable, file, hardware ID, or a provider you write.

## Macros

| Macro | Returns | Replaces |
|---|---|---|
| `mask!("...")` | `String` | string literals |
| `mask!(b"...")` | `Vec<u8>` | byte string literals |
| `mask!(c"...")` | `CString` | C string literals (`std`) |
| `mask_format!("{}", x)` | `String` | `format!` |
| `mask_print!("{}", x)` | `()` | `print!` (`std`) |
| `mask_println!("{}", x)` | `()` | `println!` (`std`) |
| `mask_write!(dst, "{}", x)` | `Result` | `write!` |
| `mask_writeln!(dst, "{}", x)` | `Result` | `writeln!` |
| `mask_concat!(a, b)` | `String` | `concat!` |
| `mask_env!("VAR")` | `String` | `env!` |
| `mask_option_env!("VAR")` | `Option<String>` | `option_env!` |
| `mask_include_str!("path")` | `String` | `include_str!` |
| `mask_include_bytes!("path")` | `Vec<u8>` | `include_bytes!` |
| `mask_file!()` | `String` | `file!` |
| `weak_mask!("...")` | `&'static str` | pre-`init!` bootstrap strings |
| `weak_mask!(b"...")` | `&'static [u8]` | pre-`init!` bootstrap bytes |
| `weak_mask!(c"...")` | `&'static CStr` | pre-`init!` bootstrap C strings (`std`) |
| `unmasked!("...")` | `&'static str` | opt out of `#[mask_all]` |
| `#[mask_all]` | -- | rewrites all literals in a module |

`mask!` returns owned types because decryption happens at runtime. If you
need `&str`, bind: `let s: &str = &mask!("...");`. For `&'static str`
with weaker guarantees, use `weak_mask!`.

## Key providers

| Provider | Source | Feature |
|---|---|---|
| `EnvVarProvider` | Environment variable | default |
| `FileProvider` | Filesystem path | default |
| `HardwareIdProvider` | Machine ID + BLAKE3 | `hw-id` |
| `StaticProvider` | Fixed key (tests only) | -- |
| `impl KeyProvider` | Anything you write | -- |

```rust
use litmask::{HardwareIdProvider, weak_mask};

let provider = HardwareIdProvider::with_salt(weak_mask!(b"myapp-v1"));
litmask::init_with!(provider)?;
```

## Security model

| Configuration | Defeats |
|---|---|
| Default (`EnvVarProvider`) | `strings`, casual inspection |
| `FileProvider` | Above, key sourced from a file path |
| `HardwareIdProvider` | Above + binary redistribution |
| Custom provider (vault, HSM) | Above + offline attackers |

**Does NOT protect against:** runtime memory inspection, debugger
attachment, compromised runtime environments, side-channel attacks,
or a motivated reverse engineer with runtime access. See
[THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full scope.

## Hardware binding (`litmask bind`)

`bind` re-encrypts a binary's embedded wrapper under a key derived from
the host's machine ID. The typical workflow uses `HardwareIdProvider` at
runtime so the binary decrypts only on the machine it was bound to:

```sh
cargo build --features hw-id --release
litmask bind target/release/my_app --config target/release/litmask.config
./target/release/my_app   # decrypts via HardwareIdProvider — no env var needed
```

`bind` also works with binaries that use `EnvVarProvider` (the default).
After binding, the config's `unlock_key` is the hardware-derived key.
Pass it as the environment variable and decryption succeeds regardless
of the runtime provider:

```sh
cargo build --release
litmask bind target/release/my_app --config target/release/litmask.config
LITMASK_UNLOCK_KEY=$(awk -F'"' '/^unlock_key/ {print $2}' target/release/litmask.config) \
    ./target/release/my_app
```

This is useful for deployment pipelines that bind on a target host but
manage the unlock key externally (e.g., injected by an orchestrator).

## Features

| Feature | Default | |
|---|---|---|
| `std` | yes | `EnvVarProvider`, `FileProvider`, `mask!(c"...")` |
| `chacha20-poly1305` | yes | Default cipher |
| `aes-gcm` | no | AES-256-GCM (takes precedence when enabled) |
| `alloc` | -- | `no_std` + allocator (required for `no_std` builds) |
| `hw-id` | no | `HardwareIdProvider` |

## Documentation

- [API docs (docs.rs)](https://docs.rs/litmask)
- [Threat model](docs/THREAT_MODEL.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Specification](docs/SPECIFICATION.md)

## License

MIT OR Apache-2.0
