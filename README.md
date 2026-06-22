# litmask

[![crates.io](https://img.shields.io/crates/v/litmask.svg)](https://crates.io/crates/litmask)
[![docs.rs](https://img.shields.io/docsrs/litmask)](https://docs.rs/litmask)
[![CI](https://github.com/camercu/litmask/actions/workflows/ci.yml/badge.svg)](https://github.com/camercu/litmask/actions/workflows/ci.yml)
[![MSRV](https://img.shields.io/badge/rustc-1.88+-blue.svg)](https://github.com/camercu/litmask)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

**Hide string literals from `strings(1)` and disassemblers.** AEAD-encrypt
every string constant at compile time, decrypt at runtime. Drop-in
macros, layered key management, `no_std` ready.

```rust
use litmask::{mask, mask_println};

fn main() {
    // example proprietary LLM prompt — present at runtime, absent from binary's `strings`
    let system_prompt = mask!("You're ACME's pricing oracle; channel Warren Buffett.");
    mask_println!("prompt loaded: {system_prompt}"); // mask_println! hides its input too
}
```

```sh
strings target/release/my_app | grep "pricing oracle"   # no output
```

`mask!` returns owned types (decryption happens at runtime) — see
[Macros](#macros) for the `&str` borrow caveat and `weak_mask!`.

## Why litmask

|                          | `obfstr`            | `litcrypt`     | **`litmask`**                                           |
| ------------------------ | ------------------- | -------------- | ------------------------------------------------------- |
| Cipher                   | XOR                 | XOR            | **ChaCha20-Poly1305 / AES-256-GCM**                     |
| Tamper detection         | No                  | No             | **Yes (AEAD)**                                          |
| Per-string nonces        | Compile-time random | None           | **Per-build, authenticated**                            |
| Literal types            | `str`               | `str`          | **str / bytes / cstr**                                  |
| Format strings           | No                  | No             | **`mask_format!`**                                      |
| File / env / path inputs | No                  | No             | **`mask_include_str!`, `mask_env!`, `mask_concat!`, …** |
| Module-level masking     | No                  | No             | **`#[mask_all]`** (whole module, deep rewrite)          |
| `Debug` name masking     | No                  | No             | **`#[derive(MaskDebug)]`**                              |
| serde name masking       | No                  | No             | **`MaskSerialize` / `MaskDeserialize`** (experimental)  |
| Key model                | Compile-time random | Single env var | **Layered: `mask_key` + runtime `unlock_key`**          |
| Dependency-graph unlock  | No                  | No             | **Governed masking — one `init!`, uniform seal**        |
| Machine-ID binding       | No                  | No             | **`init!(bind_to_machine)`**                            |
| `no_std`                 | Limited             | No             | **Yes** (requires `alloc`)                              |
| Reproducible builds      | No                  | No             | **Yes**                                                 |

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

fn main() {
    // `mask!` returns an owned String; the literal never lands in the binary.
    // The keyless Embedded tier self-initializes on this first `mask!`.
    let secret_sauce = mask!("smoked paprika + maple + 18h sous-vide");
    println!("{secret_sauce}");
}
```

```sh
cargo build
cargo run    # no key to deliver — the default Embedded tier is keyless
```

The zero-config default is keyless — the Embedded tier self-initializes on
the first `mask!()`, so a build runs with nothing to provision. That buys
`strings(1)` resistance, not secrecy; for real secrecy, source the key at
runtime with a [`KeyProvider`](#key-providers) — see
[Security model](#security-model).

## How it works

`litmask` splits encryption across build time and run time:

1. **Build** — `litmask_build::emit()` (in `build.rs`) generates a random
   seed, derives the `mask_key`, seals it into a wrapper, and writes the
   `OUT_DIR` artifacts the proc macro reads — plus the seal-tier tag that
   `init!` cross-checks at compile time.
2. **Compile** — each `mask!` literal is AEAD-encrypted during macro
   expansion and the ciphertext is embedded in the binary as `&[u8]`. The
   plaintext never appears in the output binary.
3. **Run** — the `mask_key` is unwrapped using an `unlock_key`. The default
   keyless Embedded tier recomputes it from the wrapper nonce on the first
   `mask!()`; higher tiers source it at runtime via a
   [`KeyProvider`](#key-providers) and a governing `init!(provider)`.
   `mask!` then decrypts each blob on demand.

Above the Embedded floor, the `unlock_key` is the only secret that lives
outside the binary, so key management reduces to _how you deliver the
unlock_key_ — environment variable, file, machine ID, or a provider you
write.

## Libraries and governed masking

`litmask` composes across a dependency graph. The rule for **library
authors** is one line:

> **If your crate uses `litmask` internally, never call `init!()` — only
> `mask!()`.** Unlocking is the _host binary's_ job, not the library's.

A library just `mask!()`s its own strings. Whoever links the final binary
decides how the whole graph is unlocked:

- **Transparent masking** (default): the host does nothing. Every masking
  crate — yours and its dependencies — self-unlocks at the keyless
  **Embedded floor** on first use (`strings(1)`-resistance only).
- **Governed masking**: the host sets one unlock key in the _build_
  environment (`LITMASK_UNLOCK_KEY`, which reaches every crate's
  `build.rs`) and calls a single governing `init!(provider)` at startup.
  That one key unlocks the entire graph — the host's strings and every
  transitive library's — with real secrecy.

Because the seal tier is fixed by the shared build environment, there is
no per-library configuration: the binary owner governs deployment
security for the whole graph. The governing forms are `init!(provider)`,
`init!(bind_to_machine)`, and `init!(bind_to_machine + provider)`.

See [ADR-0001](docs/adr/0001-masking-crate-unlock-governance.md) for the
rationale and the [Deployment Guide](docs/DEPLOYMENT.md) for host setup.

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
works in `no_std` + `alloc` builds. Structs (including `#[repr(packed)]`)
and enums are supported; unions are a compile error. Adding a plain
`#[derive(Debug)]` to the same type re-embeds the names and defeats the
masking.

See `examples/mask_debug_demo.rs` and SPECIFICATION.md §2.14.

## Serde integration (experimental)

The plain `serde` derives embed every field name and the struct name as
cleartext in the binary — `strings(1)` reveals your schema vocabulary even
when every field value is masked (`Deserialize` is the larger leak: `FIELDS`
arrays, field-matching arms, and `missing field` diagnostics all carry the
names). The `unstable-serde` feature adds `#[derive(MaskSerialize)]` and
`#[derive(MaskDeserialize)]`, which mask the names through the same AEAD
pipeline as `mask!` while keeping behavior identical to the plain derives —
byte-identical serialized output, same accepted inputs, same error messages:

```rust
use litmask::{MaskDeserialize, MaskSerialize};

#[derive(MaskSerialize, MaskDeserialize)]
struct LicenseManifest {
    license_server_url: String,   // field name absent from the binary
    activation_token: String,
}
```

Every struct shape (named-field, tuple, newtype, unit) and enums are
supported, including the variant names self-describing formats print and
match on. A documented subset of `#[serde(...)]` is honored and stays wire-identical
to the plain derive — `rename`/`rename_all`, `skip*`, `default`, `alias`,
`with`, `deny_unknown_fields`, `transparent`, and more; SPECIFICATION.md
Appendix E lists the full set.

Current limitations (the `unstable-` prefix means semver-exempt):

- Any other `#[serde(...)]` key (e.g. `flatten`, enum `tag` / `untagged`
  / `content`) is a compile error rather than a silent cleartext fallback,
  as are unions; `with` / `serialize_with` / `deserialize_with` is not yet
  supported on a generic type.
- A plain `serde` derive or plain `Debug` on the same struct re-embeds every
  name and defeats the masking (use `#[derive(MaskDebug)]` for `Debug`).

See `examples/mask_serde_demo.rs` and SPECIFICATION.md Appendix E.

## Key providers

The Embedded tier (default) needs no `init!`; every other tier needs exactly
one governing `init!(...)` at startup.

| Provider                 | Source                                    | Feature      |
| ------------------------ | ----------------------------------------- | ------------ |
| _Keyless default_        | Wrapper nonce (Embedded tier, no `init!`) | always       |
| `EnvVarProvider`         | Environment variable                      | default      |
| `FileProvider`           | Filesystem path                           | default      |
| `init!(bind_to_machine)` | Host machine ID + BLAKE3 (build-sealed)   | `machine-id` |
| `impl KeyProvider`       | Anything you write                        | --           |

A runtime provider is sourced explicitly with `init!(provider)`:

```rust
let provider = litmask::EnvVarProvider::new("LITMASK_UNLOCK_KEY");
litmask::init!(provider)?;
```

The machine tier is sealed at build time instead — see
[Machine-ID binding](#machine-id-binding) below. Sealing with **both**
`LITMASK_MACHINE_ID` and `LITMASK_UNLOCK_KEY` gives the two-factor tier,
unlocked with `init!(bind_to_machine + provider)` — the binary opens only on
the sealed host _and_ with the sealed material.

## Security model

Protection scales with how the key is supplied. The keyless **Embedded**
default gives `strings(1)` resistance only (the key is recoverable from the
artifact); sourcing the key at runtime — `EnvVarProvider`, `FileProvider`,
`init!(bind_to_machine)`, or a custom vault/HSM provider — keeps it out of the
binary and raises the bar accordingly. The full
configuration-to-resistance ladder lives in
[THREAT_MODEL.md](docs/THREAT_MODEL.md).

**Does NOT protect against:** runtime memory inspection, debugger
attachment, compromised runtime environments, side-channel attacks,
or a motivated reverse engineer with runtime access.

For memory-remanence hygiene, wrap a masked output in `litmask::Zeroizing`
to overwrite its buffer on drop — `let token = litmask::Zeroizing::new(litmask::mask!("secret"));`.
This shrinks the window a dropped secret survives in a core dump, swap, or
hibernation image; it does not change the memory-inspection limits above.
See [THREAT_MODEL.md](docs/THREAT_MODEL.md) for the per-macro coverage.

## Machine-ID binding

The `machine-id` feature seals the build's `unlock_key` to a host's
machine ID, so the binary decrypts only on the machine it was built for.
The factor is supplied at **build** time via `LITMASK_MACHINE_ID` and
re-sourced at **run** time by `init!(bind_to_machine)`, which recomputes the
host ID locally — no env var or key file to deliver at runtime:

```sh
LITMASK_MACHINE_ID="$(litmask show-machine-id)" \
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

Install the build-time helper with `cargo install litmask-cli`; it puts a
`litmask` binary on your `PATH` with two subcommands:

| Command           | Output                                                         |
| ----------------- | -------------------------------------------------------------- |
| `keygen`          | 32 random bytes, base64url, to stdout — a `LITMASK_UNLOCK_KEY` |
| `show-machine-id` | this host's self-checking machine-id token to stdout           |

`keygen` is a plain generator you can pipe into a build or a secret store:

```sh
LITMASK_UNLOCK_KEY="$(litmask keygen)" cargo build --release
```

## Features

| Feature             | Default |                                                                                        |
| ------------------- | ------- | -------------------------------------------------------------------------------------- |
| `std`               | yes     | `EnvVarProvider`, `FileProvider`, `mask!(c"...")`                                      |
| `chacha20-poly1305` | yes     | Default cipher                                                                         |
| `aes-gcm`           | no      | AES-256-GCM (takes precedence when enabled)                                            |
| `alloc`             | --      | `no_std` + allocator (required for `no_std` builds)                                    |
| `machine-id`        | no      | `init!(bind_to_machine)` machine-ID binding                                            |
| `unstable-serde`    | no      | EXPERIMENTAL `#[derive(MaskSerialize)]` + `#[derive(MaskDeserialize)]` (semver-exempt) |

## Documentation

- [Architecture (start here)](docs/ARCHITECTURE.md) — the one-page mental model
- [API docs (docs.rs)](https://docs.rs/litmask)
- [Threat model](docs/THREAT_MODEL.md)
- [Deployment guide](docs/DEPLOYMENT.md)
- [Specification](docs/SPECIFICATION.md)
- [Benchmarks](docs/BENCHMARKS.md) — build-time and runtime overhead (regenerate with `just bench-doc`)

## License

MIT OR Apache-2.0
