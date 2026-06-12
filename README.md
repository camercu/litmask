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
use litmask::{mask, mask_println};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    litmask::init!()?; // call once before any mask!
    // proprietary LLM system prompt — present at runtime, absent from the binary's `strings`
    let system_prompt = mask!("You're ACME's pricing oracle; channel Warren Buffett.");
    mask_println!("prompt loaded: {system_prompt}"); // mask_println! hides its input too
    Ok(())
}
```

```sh
strings target/release/my_app | grep "pricing oracle"   # no output
```

`mask!` returns owned types (decryption happens at runtime) — see
[Macros](#macros) for the `&str` borrow caveat and `weak_mask!`.

## Why litmask

|                     | `obfstr`            | `litcrypt`     | **`litmask`**                       |
| ------------------- | ------------------- | -------------- | ----------------------------------- |
| Cipher              | XOR                 | XOR            | **ChaCha20-Poly1305 / AES-256-GCM** |
| Tamper detection    | No                  | No             | **Yes (AEAD)**                      |
| Key model           | Compile-time random | Single env var | **Layered providers**               |
| Format strings      | No                  | No             | **`mask_format!`**                  |
| Module-level        | No                  | No             | **`#[mask_all]`**                   |
| Machine-ID binding  | No                  | No             | **`init!(bind_to_machine)`**             |
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

```rust
// src/main.rs
use litmask::mask;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    litmask::init!()?; // call once before any mask!
    // `mask!` returns an owned String; the literal never lands in the binary.
    let secret_sauce = mask!("smoked paprika + maple + 18h sous-vide");
    println!("{secret_sauce}");
    Ok(())
}
```

```sh
cargo build
cargo run    # no key to deliver — the default Embedded tier is keyless
```

The zero-config default is keyless: `init!()` uses `EmbeddedProvider`, so
a build runs with nothing to provision. That buys `strings(1)` resistance,
not secrecy — the key is recoverable from the artifact. To keep the
`unlock_key` out of the binary, source it at runtime with a
[`KeyProvider`](#key-providers) and `init_with!` (e.g. `EnvVarProvider`
reading `LITMASK_UNLOCK_KEY`).

## How it works

`litmask` splits encryption across build time and run time:

1. **Build** — `litmask_build::emit()` (in `build.rs`) generates a random
   seed, derives the `mask_key`, seals it into a wrapper, and writes the
   `OUT_DIR` artifacts the proc macro reads — plus the seal-tier tag that
   `init!` cross-checks at compile time.
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
| `#[derive(MaskDebug)]`        | --               | masks `Debug` type/field/variant names  |

`mask!` returns owned types because decryption happens at runtime. For `&str`,
bind: `let s: &str = &mask!("...");`. If you absolutely need `&'static str`,
use `weak_mask!`, but its key is recoverable statically from the binary.

## Debug derive

`#[derive(Debug)]` embeds the type name, every field name, and every enum
variant name as cleartext in the binary. `#[derive(MaskDebug)]` masks the
names through the same AEAD pipeline as `mask!` while keeping `{:?}` and
`{:#?}` output byte-identical to the plain derive:

```rust
use litmask::MaskDebug;

#[derive(MaskDebug)]
struct LicenseManifest {
    license_server_url: String,   // field name absent from the binary
    activation_token: String,
}
```

No feature flag needed — names are decrypted during each `fmt` call (the
formatter borrows `&str`, so nothing is cached or leaked), and the derive
works in `no_std` + `alloc` builds. Structs and enums are supported; unions
are a compile error. Adding a plain `#[derive(Debug)]` to the same type
re-embeds the names and defeats the masking.

See `examples/mask_debug_demo.rs` and SPECIFICATION.md §2.14.

## Serde integration (experimental)

`#[derive(serde::Serialize)]` embeds every field name and the struct name as
cleartext in the binary — `strings(1)` reveals your schema vocabulary even
when every field value is masked. The `unstable-serde` feature adds
`#[derive(MaskSerialize)]`, which masks the names through the same AEAD
pipeline as `mask!` while keeping serialized output byte-identical to the
plain derive for every serde format:

```rust
use litmask::MaskSerialize;

#[derive(MaskSerialize)]
struct LicenseManifest {
    license_server_url: String,   // field name absent from the binary
    activation_token: String,
}
```

Current limitations (the `unstable-` prefix means semver-exempt):

- Named-field structs only — enums, tuple structs, and `#[serde(...)]`
  attributes are compile errors rather than silent cleartext fallbacks.
- `Serialize` only. A plain `#[derive(serde::Deserialize)]` on the same
  struct re-embeds every name and defeats the masking — same for plain
  `Debug` (use `#[derive(MaskDebug)]` instead).

See `examples/mask_serde_demo.rs` and SPECIFICATION.md Appendix E.

## Key providers

| Provider            | Source                                  | Feature      |
| ------------------- | --------------------------------------- | ------------ |
| `EmbeddedProvider`  | Wrapper nonce (keyless default)         | always       |
| `EnvVarProvider`    | Environment variable                    | default      |
| `FileProvider`      | Filesystem path                         | default      |
| `init!(bind_to_machine)` | Host machine ID + BLAKE3 (build-sealed) | `machine-id` |
| `impl KeyProvider`  | Anything you write                      | --           |

A runtime provider is sourced explicitly with `init_with!` (or the
equivalent `init!(provider)`):

```rust
let provider = litmask::EnvVarProvider::new("LITMASK_UNLOCK_KEY");
litmask::init_with!(provider)?;
```

The machine tier is sealed at build time instead — see
[Machine-ID binding](#machine-id-binding) below. Sealing with **both**
`LITMASK_MACHINE_ID` and `LITMASK_UNLOCK_KEY` gives the two-factor tier,
unlocked with `init!(bind_to_machine + provider)` — the binary opens only on
the sealed host _and_ with the sealed material.

## Security model

| Configuration                        | Defeats                                                      |
| ------------------------------------ | ------------------------------------------------------------ |
| Default (keyless `EmbeddedProvider`) | `strings`, casual inspection (key recoverable from artifact) |
| `EnvVarProvider`                     | Above, key sourced from an env var, kept out of the binary   |
| `FileProvider`                       | Above, key sourced from a file path                          |
| `init!(bind_to_machine)`                  | Above + binary redistribution                                |
| `init!(bind_to_machine + provider)`       | Above + the external factor the binary alone never carries   |
| Custom provider (vault, HSM)         | Above + offline attackers                                    |

**Does NOT protect against:** runtime memory inspection, debugger
attachment, compromised runtime environments, side-channel attacks,
or a motivated reverse engineer with runtime access. See
[THREAT_MODEL.md](docs/THREAT_MODEL.md) for the full scope.

## Machine-ID binding

The `machine-id` feature seals the build's `unlock_key` to a host's
machine ID, so the binary decrypts only on the machine it was built for.
The factor is supplied at **build** time via `LITMASK_MACHINE_ID` and
re-sourced at **run** time by `init!(bind_to_machine)`, which recomputes the
host ID locally — no env var or key file to deliver at runtime:

```sh
LITMASK_MACHINE_ID="$(cargo run -q -p litmask-cli -- show-machine-id)" \
    cargo build --release --features machine-id

./target/release/my_app   # decrypts only on this host
```

```rust
litmask::init!(bind_to_machine)?;
```

Moving the binary to a different host makes `init!(bind_to_machine)` fail: the
runtime recomputes a different machine ID, derives a different
`unlock_key`, and the wrapper's AEAD tag check rejects it.

`show-machine-id` prints a **self-checking token** — `raw_id "."
checksum` — to stdout, with usage prose on stderr. The build-time
`emit()` validates the checksum and rejects a mistyped id before it can
seal a binary nobody can open. Pipe stdout straight into the build (above)
or copy the token to whoever does the sealing.

## CLI

The `litmask` CLI is a small build-time helper with two subcommands:

| Command           | Output                                                         |
| ----------------- | -------------------------------------------------------------- |
| `keygen`          | 32 random bytes, base64url, to stdout — a `LITMASK_UNLOCK_KEY` |
| `show-machine-id` | this host's self-checking machine-id token to stdout           |

`keygen` is a plain generator you can pipe into a build or a secret store:

```sh
LITMASK_UNLOCK_KEY="$(cargo run -q -p litmask-cli -- keygen)" \
    cargo build --release
```

## Features

| Feature             | Default |                                                     |
| ------------------- | ------- | --------------------------------------------------- |
| `std`               | yes     | `EnvVarProvider`, `FileProvider`, `mask!(c"...")`   |
| `chacha20-poly1305` | yes     | Default cipher                                      |
| `aes-gcm`           | no      | AES-256-GCM (takes precedence when enabled)         |
| `alloc`             | --      | `no_std` + allocator (required for `no_std` builds) |
| `machine-id`        | no      | `init!(bind_to_machine)` machine-ID binding              |
| `unstable-serde`    | no      | EXPERIMENTAL `#[derive(MaskSerialize)]` (semver-exempt) |

## Documentation

- [API docs (docs.rs)](https://docs.rs/litmask)
- [Threat model](docs/THREAT_MODEL.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Specification](docs/SPECIFICATION.md)

## License

MIT OR Apache-2.0
