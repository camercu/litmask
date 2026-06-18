# Migration Guide

litmask replaces the compile-time string-obfuscation crates `litcrypt`
(v1 and v2) and `obfstr`. Setup is identical for all three; only the
call-site rewrites differ.

## Setup (all sources)

Add the runtime and the build helper, then add a build script:

```sh
cargo add litmask
cargo add --build litmask-build
```

```rust
// build.rs
fn main() { litmask_build::emit(); }
```

Remove the old dependency and any `use_litcrypt!()` import — litmask needs
no macro import; `litmask::mask!` is always in scope.

## Call sites

| From | Old | litmask |
|---|---|---|
| `litcrypt` v1 / v2 | `lc!("secret")` | `litmask::mask!("secret")` |
| `obfstr` | `obfstr!("secret")` | `litmask::mask!("secret")` |

`lc!` and `mask!` both return `String`, so litcrypt call sites need no
type changes. `obfstr!` returns `&str` (a temporary borrow) while `mask!`
returns an owned `String`; bind it if you need a borrow:

```rust
let owned = litmask::mask!("my secret");
let s: &str = &owned;
```

For `&'static str` with weaker (XOR, non-AEAD) guarantees, use `weak_mask!`:

```rust
let s: &'static str = litmask::weak_mask!("my secret");
```

### `obfstr` extras

```diff
-let msg = obfstr::obfstr!("hello ") + name;
+let msg = litmask::mask_format!("hello {}", name);
```

```diff
-let key: &[u8] = obfstr::obfstr!(b"\xde\xad");
+let key: Vec<u8> = litmask::mask!(b"\xde\xad");
```

## What changes vs. each crate

| | `litcrypt` v1 / v2 | `obfstr` | `litmask` |
|---|---|---|---|
| Cipher | XOR | XOR | ChaCha20-Poly1305 (AEAD) |
| Return type | `String` | `&str` (temporary) | `String` (owned) |
| Key location | Embedded in binary | Embedded in binary | Keyless Embedded default, or external (env, file, machine ID) |
| Tamper detection | No | No | Yes |
| Format strings | No | No | `mask_format!` |
| Byte / C strings | — | `&[u8]` | `Vec<u8>`, `CString` |
| `no_std` | No | Limited | Yes (with `alloc`) |

## Runtime & seal tiers

litcrypt and obfstr embed the key in the binary, so they have no runtime
step. litmask's keyless **Embedded** default also needs none — it lazily
initializes on the first `mask!`. This matches the old crates' resistance:
`strings(1)` only, since the key is recoverable from the artifact.

To keep the key _out_ of the binary — the core security improvement — seal
the build under `LITMASK_UNLOCK_KEY` (or `LITMASK_MACHINE_ID`) and
re-supply that factor at runtime through a governing `init!` before the
first `mask!`. The `init!` also surfaces unlock errors early and governs
every transitive masking crate under one uniform seal:

```rust
litmask::init!(litmask::EnvVarProvider::default()).expect("litmask init");
```

```sh
LITMASK_UNLOCK_KEY='same material the build was sealed with' ./my_app
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for the per-tier operational guide and
[THREAT_MODEL.md](THREAT_MODEL.md) for what each tier defends against.
