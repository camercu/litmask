# litmask

[![crates.io](https://img.shields.io/crates/v/litmask.svg)](https://crates.io/crates/litmask)
[![docs.rs](https://img.shields.io/docsrs/litmask)](https://docs.rs/litmask)
[![CI](https://github.com/camercu/litmask/actions/workflows/ci.yml/badge.svg)](https://github.com/camercu/litmask/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/rustc-1.88+-blue.svg)](https://github.com/camercu/litmask)
[![License](https://img.shields.io/crates/l/litmask.svg)](#license)

**Hide string literals from `strings(1)` and disassemblers.** AEAD-encrypt
every string constant at compile time, decrypt at runtime. Drop-in
macros, layered key management, `no_std` ready.

```rust
use litmask::mask;

fn main() -> Result<(), Box<dyn Error>> {
    litmask::init!()?;
    proprietary_gonculator(mask!("sensitive data"))
}
```

```sh
strings target/release/my_app | grep "sensitive data"   # no output
```

`mask!` returns an owned `String` (decryption happens at runtime), not
`&str` — bind `let s: &str = &mask!("...");` when you need a borrow. See
[Macros](#macros) for the full caveat and `weak_mask!`.

## Why litmask

|                     | `obfstr`            | `litcrypt`     | **`litmask`**                       |
| ------------------- | ------------------- | -------------- | ----------------------------------- |
| Cipher              | XOR                 | XOR            | **ChaCha20-Poly1305 / AES-256-GCM** |
| Tamper detection    | No                  | No             | **Yes (AEAD)**                      |
| Key model           | Compile-time random | Single env var | **Layered providers**               |
| Format strings      | No                  | No             | **`mask_format!`**                  |
| Module-level        | No                  | No             | **`#[mask_all]`**                   |
| Machine-ID binding    | No                  | No             | **`litmask bind`**                  |
| Literal types       | `str`               | `str`          | **str / bytes / cstr**              |
| `no_std`            | Limited             | No             | **Yes** (requires `alloc`)          |
| Reproducible builds | No                  | No             | **Yes**                             |

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
cargo run    # no key to deliver — the default Embedded tier is keyless
```

By default `init!()` uses the keyless `EmbeddedProvider`: it recomputes
the `unlock_key` from the wrapper's cleartext nonce, so a zero-config
build runs with nothing to provision. This buys `strings(1)` resistance,
not secrecy — the key is recoverable from the artifact. To keep the
`unlock_key` out of the binary, source it at runtime with a
[`KeyProvider`](#key-providers) and `init_with!` (e.g. `EnvVarProvider`
reading `LITMASK_UNLOCK_KEY`).

## How it works

litmask splits encryption across build time and run time:

1. **Build** — `litmask_build::emit()` (in `build.rs`) generates a random
   seed, derives the `mask_key`, and writes `litmask.config` plus the env
   vars the proc macro reads.
2. **Compile** — each `mask!` literal is AEAD-encrypted during macro
   expansion and the ciphertext is embedded in the binary as `&[u8]`. The
   plaintext never appears in the output binary.
3. **Run** — `init!()` unwraps the `mask_key` using an `unlock_key`. The
   default keyless `EmbeddedProvider` recomputes it from the wrapper
   nonce; higher tiers source it at runtime via a
   [`KeyProvider`](#key-providers) and `init_with!`. `mask!` then decrypts
   each blob on demand.

Above the Embedded floor, the `unlock_key` is the only secret that lives
outside the binary, so key management reduces to _how you deliver the
unlock_key_ — environment variable, file, machine ID, or a provider you
write.

## Macros

| Macro                         | Returns          | Replaces                                |
| ----------------------------- | ---------------- | --------------------------------------- |
| `mask!("...")`                | `String`         | string literals                         |
| `mask!(b"...")`               | `Vec<u8>`        | byte string literals                    |
| `mask!(c"...")`               | `CString`        | C string literals (`std`)               |
| `mask_format!("{}", x)`       | `String`         | `format!`                               |
| `mask_print!("{}", x)`        | `()`             | `print!` (`std`)                        |
| `mask_println!("{}", x)`      | `()`             | `println!` (`std`)                      |
| `mask_write!(dst, "{}", x)`   | `Result`         | `write!`                                |
| `mask_writeln!(dst, "{}", x)` | `Result`         | `writeln!`                              |
| `mask_concat!(a, b)`          | `String`         | `concat!`                               |
| `mask_env!("VAR")`            | `String`         | `env!`                                  |
| `mask_option_env!("VAR")`     | `Option<String>` | `option_env!`                           |
| `mask_include_str!("path")`   | `String`         | `include_str!`                          |
| `mask_include_bytes!("path")` | `Vec<u8>`        | `include_bytes!`                        |
| `mask_file!()`                | `String`         | `file!`                                 |
| `weak_mask!("...")`           | `&'static str`   | pre-`init!` bootstrap strings           |
| `weak_mask!(b"...")`          | `&'static [u8]`  | pre-`init!` bootstrap bytes             |
| `weak_mask!(c"...")`          | `&'static CStr`  | pre-`init!` bootstrap C strings (`std`) |
| `unmasked!("...")`            | `&'static str`   | opt out of `#[mask_all]`                |
| `#[mask_all]`                 | --               | rewrites all literals in a module       |

`mask!` returns owned types because decryption happens at runtime. For `&str`,
bind: `let s: &str = &mask!("...");`. If you absolutely need `&'static str`,
use `weak_mask!`, but its key is recoverable statically from the binary.

## Key providers

| Provider             | Source                 | Feature |
| -------------------- | ---------------------- | ------- |
| `EmbeddedProvider`   | Wrapper nonce (keyless default) | always |
| `EnvVarProvider`     | Environment variable   | default |
| `FileProvider`       | Filesystem path        | default |
| `MachineIdProvider` | Machine ID + BLAKE3    | `machine-id` |
| `impl KeyProvider`   | Anything you write     | --      |

```rust
use litmask::{MachineIdProvider, weak_mask};

let provider = MachineIdProvider::with_salt(weak_mask!(b"myapp-v1"));
litmask::init_with!(provider)?;
```

## Security model

| Configuration                | Defeats                             |
| ---------------------------- | ----------------------------------- |
| Default (keyless `EmbeddedProvider`) | `strings`, casual inspection (key recoverable from artifact) |
| `EnvVarProvider`             | Above, key sourced from an env var, kept out of the binary |
| `FileProvider`               | Above, key sourced from a file path |
| `MachineIdProvider`         | Above + binary redistribution       |
| Custom provider (vault, HSM) | Above + offline attackers           |

**Does NOT protect against:** runtime memory inspection, debugger
attachment, compromised runtime environments, side-channel attacks,
or a motivated reverse engineer with runtime access. See
[THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full scope.

## Machine-ID binding (`litmask bind`)

`bind` re-encrypts a binary's embedded wrapper under a key derived from
the host's machine ID. The typical workflow uses `MachineIdProvider` at
runtime so the binary decrypts only on the machine it was bound to:

```sh
cargo build --features machine-id --release
litmask bind target/release/my_app --config target/release/litmask.config
./target/release/my_app   # decrypts via MachineIdProvider — no env var needed
```

## Features

| Feature             | Default |                                                     |
| ------------------- | ------- | --------------------------------------------------- |
| `std`               | yes     | `EnvVarProvider`, `FileProvider`, `mask!(c"...")`   |
| `chacha20-poly1305` | yes     | Default cipher                                      |
| `aes-gcm`           | no      | AES-256-GCM (takes precedence when enabled)         |
| `alloc`             | --      | `no_std` + allocator (required for `no_std` builds) |
| `machine-id`             | no      | `MachineIdProvider`                                |

## Documentation

- [API docs (docs.rs)](https://docs.rs/litmask)
- [Threat model](docs/THREAT_MODEL.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Specification](docs/SPECIFICATION.md)

## License

MIT OR Apache-2.0
