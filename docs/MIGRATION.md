# Migration Guide

## From `litcrypt` v1

### Build setup

```diff
 # Cargo.toml
 [dependencies]
-litcrypt = "0.2"
+litmask = "0.7"
+
+[build-dependencies]
+litmask-build = "0.7"
```

```rust
// build.rs (new file)
fn main() { litmask_build::emit(); }
```

### Code changes

```diff
-use_litcrypt!();
+// No macro import needed — litmask::mask! is always available.
```

```diff
-let secret = lc!("my secret");
+let secret = litmask::mask!("my secret");
```

### Runtime

litcrypt v1 reads `LITCRYPT_ENCRYPT_KEY` at compile time and embeds it.
litmask generates a random key per build and writes it to
`litmask.config`. At runtime:

```sh
# litcrypt (key baked into binary — no runtime step)
./my_app

# litmask (key external — must be provisioned)
LITMASK_UNLOCK_KEY=$(awk -F'"' '/^unlock_key/ {print $2}' litmask.config) \
    ./my_app
```

### Key differences

| | `litcrypt` v1 | `litmask` |
|---|---|---|
| Cipher | XOR | ChaCha20-Poly1305 (AEAD) |
| Key location | Embedded in binary | External (env var, file, hardware ID) |
| Tamper detection | No | Yes |
| `no_std` | No | Yes |

## From `litcrypt2`

### Build setup

```diff
 # Cargo.toml
 [dependencies]
-litcrypt2 = "0.1"
+litmask = "0.7"
+
+[build-dependencies]
+litmask-build = "0.7"
```

```rust
// build.rs (new file)
fn main() { litmask_build::emit(); }
```

### Code changes

```diff
-use_litcrypt!();
+// No macro import needed.
```

```diff
-let secret = lc!("my secret");
+let secret = litmask::mask!("my secret");
```

litcrypt2's `lc!` returns `String`, same as litmask's `mask!` — no
type changes needed at call sites.

### Runtime

Same as litcrypt v1 migration above. litcrypt2 also embeds the key;
litmask externalizes it.

## From `obfstr`

### Build setup

```diff
 # Cargo.toml
 [dependencies]
-obfstr = "0.6"
+litmask = "0.7"
+
+[build-dependencies]
+litmask-build = "0.7"
```

```rust
// build.rs (new file)
fn main() { litmask_build::emit(); }
```

### Code changes

```diff
-let s: &str = obfstr::obfstr!("my secret");
+let s: String = litmask::mask!("my secret");
```

**Type change:** `obfstr!` returns `&str` (temporary borrow);
`mask!` returns `String` (owned). If you need `&str`:

```rust
let owned = litmask::mask!("my secret");
let s: &str = &owned;
```

For `&'static str` with weaker guarantees (XOR, not AEAD), use
`weak_mask!`:

```rust
let s: &'static str = litmask::weak_mask!("my secret");
```

### Format strings

```diff
-let msg = obfstr::obfstr!("hello ") + name;
+let msg = litmask::mask_format!("hello {}", name);
```

### Byte strings

```diff
-let key: &[u8] = obfstr::obfstr!(b"\xde\xad");
+let key: Vec<u8> = litmask::mask!(b"\xde\xad");
```

### Runtime

obfstr embeds a compile-time random XOR key — no runtime provisioning.
litmask requires `LITMASK_UNLOCK_KEY` at runtime (see litcrypt
migration above).

### Key differences

| | `obfstr` | `litmask` |
|---|---|---|
| Cipher | XOR | ChaCha20-Poly1305 (AEAD) |
| Return type | `&str` (temporary) | `String` (owned) |
| Key location | Embedded in binary | External |
| Tamper detection | No | Yes |
| Format strings | No | `mask_format!` |
| Byte / C strings | `&[u8]` | `Vec<u8>`, `CString` |
| `no_std` | Limited | Yes (with `alloc`) |

## Common migration notes

1. **Add `build.rs`** — every litmask project needs
   `litmask_build::emit()` in a build script.

2. **Provision the key at runtime** — unlike litcrypt and obfstr,
   litmask does not embed key material in the binary. This is the
   core security improvement but requires a deployment step.

3. **Call `init!()` before `mask!()`** — litmask lazily initializes on
   first `mask!` call, but explicit init surfaces errors early:
   ```rust
   litmask::init!().expect("litmask init");
   ```

4. **`mask!` returns owned types** — `String`, `Vec<u8>`, or `CString`.
   If you need borrows, bind the result to a variable first.
