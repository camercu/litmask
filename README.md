# litmask

**Hide string literals from `strings(1)` and hex editors.** AEAD-encrypt
every string constant at compile time, decrypt at runtime. Drop-in
macros, layered key management, `no_std` ready.

```rust
use litmask::mask;

fn main() {
    litmask::init!().expect("litmask init");
    println!("{}", mask!("secret token"));
}
```

```sh
strings target/release/my_app | grep "secret token"   # no output
```

## Why litmask

| | `obfstr` | `litcrypt` | **`litmask`** |
|---|---|---|---|
| Cipher | XOR | XOR | **ChaCha20-Poly1305 / AES-256-GCM** |
| Tamper detection | No | No | **Yes (AEAD)** |
| Key model | Compile-time random | Single env var | **Layered providers** |
| Format strings | No | No | **`mask_format!`** |
| Module-level | No | No | **`#[mask_all]`** |
| Hardware binding | No | No | **`litmask-cli bind`** |
| Literal types | `str` | `str` | **str / bytes / cstr** |
| `no_std` | Limited | No | **Yes** |
| Reproducible builds | No | No | **Yes** |

## Quick start

```toml
# Cargo.toml
[dependencies]
litmask = "0.7"

[build-dependencies]
litmask-build = "0.7"
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

## Macros

| Macro | Returns | Replaces |
|---|---|---|
| `mask!("...")` | `String` | string literals |
| `mask!(b"...")` | `Vec<u8>` | byte string literals |
| `mask!(c"...")` | `CString` | C string literals (`std`) |
| `mask_format!("{}", x)` | `String` | `format!` |
| `mask_concat!(a, b)` | `String` | `concat!` |
| `mask_env!("VAR")` | `String` | `env!` |
| `mask_option_env!("VAR")` | `Option<String>` | `option_env!` |
| `mask_include_str!("path")` | `String` | `include_str!` |
| `mask_include_bytes!("path")` | `Vec<u8>` | `include_bytes!` |
| `mask_file!()` | `String` | `file!` |
| `weak_mask!("...")` | `&'static str` | pre-`init!` bootstrap strings |
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
use litmask::HardwareIdProvider;

let provider = HardwareIdProvider::with_salt(b"myapp-v1");
litmask::init_with!(provider).expect("init");
```

## Security model

| Configuration | Defeats |
|---|---|
| Default (`EnvVarProvider`) | `strings`, casual inspection |
| `FileProvider` + permissions | Above + unauthorized file access |
| `HardwareIdProvider` | Above + binary redistribution |
| Custom provider (vault, HSM) | Above + offline attackers |

**Does NOT protect against:** runtime memory inspection, debugger
attachment, compromised runtime environments, side-channel attacks,
or a motivated reverse engineer with runtime access. See
[THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full scope.

## Features

| Feature | Default | |
|---|---|---|
| `std` | yes | `EnvVarProvider`, `FileProvider`, `mask!(c"...")` |
| `chacha20-poly1305` | yes | Default cipher |
| `aes-gcm` | no | AES-256-GCM (takes precedence when enabled) |
| `alloc` | -- | `no_std` + allocator |
| `hw-id` | no | `HardwareIdProvider` |

## Documentation

- [API docs (docs.rs)](https://docs.rs/litmask)
- [Threat model](docs/THREAT_MODEL.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Specification](docs/SPECIFICATION.md)

## License

MIT OR Apache-2.0
