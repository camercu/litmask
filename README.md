# litmask

Compile-time string literal obfuscation with runtime decryption for Rust.

Raise the cost of static binary analysis for string constants. Each call
to `mask!` encrypts its literal at compile time with an AEAD cipher
(ChaCha20-Poly1305 or AES-256-GCM); the runtime decrypts on first use
after a process-global mask key is recovered from an embedded wrapper.

```rust
use litmask::mask;

fn main() {
    litmask::init!().expect("litmask init");
    println!("{}", mask!("secret token"));
}
```

```sh
# The plaintext never appears in the binary:
strings target/release/my_app | grep "secret token"
# (no output)
```

## Security levels

| Configuration | Defeats |
|---|---|
| Zero-config build (defaults to `EnvVarProvider`) | `strings`, casual binary inspection (Level 1); also Level 2 because `unlock_key` is not embedded |
| `FileProvider` + filesystem permissions | Above with OS-enforced access control |
| `HardwareIdProvider` | Above + binary moved to a different machine |
| Custom `KeyProvider` (network call, vault) | Above + offline attackers |

The "zero-config" descriptor refers to absence of project configuration,
not to absence of runtime key provisioning. Providers that source
`unlock_key` from external runtime state require the deployer to
provision that state. A binary configured with such a provider but
without the corresponding state will fail at init.

## What litmask does NOT protect against

- Runtime memory inspection
- Debugger attachment after key derivation
- Compromised runtime environments
- Side-channel attacks (timing, power analysis)
- Control-flow obfuscation or anti-debugging
- Protection of dynamically generated strings
- Perfect secrecy under any threat model

`litmask` raises the cost of static analysis. It is not a DRM system and
does not claim to defeat a motivated reverse engineer with runtime
access.

## Comparison with existing crates

| Property | `obfstr` | `litcrypt`/`litcrypt2` | `litmask` |
|---|---|---|---|
| Cipher | XOR | XOR | ChaCha20-Poly1305 (AEAD) or AES-256-GCM |
| Tamper detection | No | No | Yes (AEAD authentication) |
| Per-string nonces | Compile-time random (no auth) | None | Per-build deterministic, authenticated |
| Key model | Compile-time random per build | Single env var | Layered: `mask_key` + `unlock_key`, multiple providers |
| Format string masking | Separate `fmtools` crate | None | Built-in `mask_format!` with single-evaluation semantics |
| Module-level masking | None | None | `#[mask_all]` with deep substitution |
| Hardware binding | None | None | Yes (post-build rebind via `litmask-cli`) |
| Multiple literal types (str/bytes/cstr) | str only | str only | All three |
| `no_std` support | Limited | No | Yes (with `alloc`) |
| Threat model documented | Minimal | Minimal | Explicit security ladder, honest scope |
| Reproducible builds | No | No | Yes (with `LITMASK_RNG_SEED`) |
| Fuzzing | No | No | Yes |

The cipher upgrade (XOR to AEAD) is the primary technical advance.
Everything else is operational maturity (key management, deployment
story, tooling).

## Quick start

Add `litmask` and its build-time companion to your `Cargo.toml`:

```toml
[dependencies]
litmask = "0.7"

[build-dependencies]
litmask-build = "0.7"
```

Create a `build.rs` at your crate root:

```rust
fn main() {
    litmask_build::emit();
}
```

Use `mask!` in your code:

```rust
use litmask::{init, mask};

fn main() {
    // Initialize with the default EnvVarProvider.
    // Reads LITMASK_UNLOCK_KEY from the environment.
    litmask::init!().expect("litmask init");

    let secret = mask!("my secret string");
    println!("{secret}");
}
```

Run with the unlock key from the build config:

```sh
cargo build
LITMASK_UNLOCK_KEY=$(awk -F'"' '/^unlock_key/ {print $2}' target/debug/litmask.config) \
    cargo run
```

## Masking macros

| Macro | Returns | Description |
|---|---|---|
| `mask!("...")` | `String` | AEAD-encrypted string literal |
| `mask!(b"...")` | `Vec<u8>` | AEAD-encrypted byte string |
| `mask!(c"...")` | `CString` | AEAD-encrypted C string (requires `std`) |
| `mask_format!("...", args)` | `String` | Masked format template |
| `mask_concat!(a, b, ...)` | `String` | Masked concatenation |
| `mask_env!("VAR")` | `String` | Masked build-time env var |
| `mask_option_env!("VAR")` | `Option<String>` | Masked optional env var |
| `mask_include_str!("path")` | `String` | Masked file contents |
| `mask_include_bytes!("path")` | `Vec<u8>` | Masked file bytes |
| `mask_file!()` | `String` | Masked source file path |
| `weak_mask!("...")` | `&'static str` | XOR obfuscation only, works pre-`init!` |
| `unmasked!("...")` | `&'static str` | Opt-out marker for `#[mask_all]` |
| `#[mask_all]` | — | Rewrites all literals in a module |

### Return types

`mask!` and its companions return owned types (`String`, `Vec<u8>`,
`CString`) because masked values are decrypted at runtime and cannot
inhabit `'static` storage. If a call site needs `&str`, bind once:

```rust
let secret = mask!("my secret");
let s: &str = &secret;
```

When the threat model permits weaker guarantees (no AEAD, plaintext
cached for program lifetime), `weak_mask!` returns `&'static str`
directly.

## Key providers

| Provider | Source | Feature |
|---|---|---|
| `EnvVarProvider` | Environment variable | `std` (default) |
| `FileProvider` | Filesystem path | `std` (default) |
| `HardwareIdProvider` | Machine-id + BLAKE3 | `hw-id` |
| `StaticProvider` | Fixed key (tests only) | always |
| Custom `impl KeyProvider` | Anything | always |

## Features

| Feature | Default | Description |
|---|---|---|
| `std` | Yes | Enables `EnvVarProvider`, `FileProvider`, `mask!(c"...")` |
| `chacha20-poly1305` | Yes | ChaCha20-Poly1305 cipher |
| `aes-gcm` | No | AES-256-GCM cipher (takes precedence when both enabled) |
| `alloc` | — | `no_std` + allocator support |
| `hw-id` | No | `HardwareIdProvider` (machine-bound keys) |

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT License](LICENSE-MIT) at your option.
