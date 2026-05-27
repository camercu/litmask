# Threat Model

This document describes what `litmask` protects against, what it does
not, and what limitations apply when things go wrong.

## Attacker levels

`litmask` uses a four-level model. The library targets **Level 2** as
the baseline and provides meaningful **Level 3** resistance through
layered key management.

### Level 1 — Casual inspection

Runs `strings`, opens a hex editor, or browses `.rodata`.

**Stopped by:** any encryption. `litmask` encrypts every literal with
ChaCha20-Poly1305 (or AES-256-GCM) at compile time. No plaintext
survives in the binary.

### Level 2 — Static reverse engineering

Uses a disassembler (Ghidra, IDA), identifies decryption routines,
manually decrypts embedded ciphertext.

**Stopped by:** per-string unique nonces, AEAD ciphers, and the absence
of plaintext key material in the binary. `mask_key` is encrypted under
`unlock_key`, which is never embedded in the binary under the default
(`EnvVarProvider`) and layered (`FileProvider`, `HardwareIdProvider`)
configurations.

### Level 3 — Automated unpacker

Writes tooling that emulates decryption stubs, processes ciphertext
in bulk.

**Resistance from:**
- `mask_key` encrypted under `unlock_key` that is not in the binary.
- Per-build key uniqueness — a generic unpacker built against one
  binary does not transfer to another.

`litmask` does not promise complete Level 3 resistance. A determined
attacker who runs the binary or controls its environment can observe
decryption.

### Level 4 — Runtime memory inspection

Dumps process memory at runtime, attaches a debugger after key
derivation, instruments the decryption function.

**Out of scope.** Once `unlock_key` is in process memory and
decryption runs, any observer with runtime access sees plaintext.

## Security guarantees by configuration

| Configuration | Defeats |
|---|---|
| Zero-config build (`EnvVarProvider`) | `strings`, casual binary inspection (Level 1); also Level 2 because `unlock_key` is not embedded |
| `FileProvider` + filesystem permissions | Above with OS-enforced access control |
| `HardwareIdProvider` | Above + binary moved to a different machine |
| Custom `KeyProvider` (vault, HSM) | Above + offline attackers |

"Zero-config" means no project configuration beyond `build.rs` — the
deployer still provisions `LITMASK_UNLOCK_KEY` at runtime.

## Explicitly out of scope

The following are **not** threats `litmask` addresses:

- Runtime memory inspection
- Debugger attachment after key derivation
- Compromised runtime environments
- Side-channel attacks (timing, power analysis)
- Control-flow obfuscation or anti-debugging
- Protection of dynamically generated strings
- Perfect secrecy under any threat model

These exclusions are fundamental, not aspirational gaps. An obfuscation
library that claims to defeat runtime memory inspection is lying; we
prefer honesty over false confidence.

## Init-failure plaintext limitation

After `litmask::init!()` fails, `mask!()` cannot be used because
`mask_key` is undecrypted. Any error message the application displays
about the failure must use plaintext strings, opaque error codes, or
sysexits.

This is an inherent property: any decryption mechanism for init-failure
messages would require a second always-available key, which would itself
be embedded as plaintext — defeating the purpose.

The recommended pattern for minimal plaintext:

```rust
if let Err(e) = litmask::init!() {
    std::process::exit(e.sysexit_code());
}
```

`sysexit_code()` returns numeric exit codes (no string contribution to
the binary). Operators interpret the codes via standard sysexits.h
documentation.

## Error variant strings

Auto-derived `Debug` impls produce short variant name strings
(`"NotFound"`, `"Permission"`, etc.). `Display` impls produce short
`category:variant` tags. These are ASCII identifiers common to any Rust
crate with derived `Debug` — they do not identify `litmask` specifically.

Users requiring provable absence of these strings should use
`sysexit_code()` and verify with `strings` on their built binary.

## Timing

`litmask` does not guarantee constant-time operations in the decryption
path. The underlying AEAD crates (ChaCha20-Poly1305, AES-256-GCM) use
constant-time primitives, but surrounding Rust code (comparisons,
branching) is not audited for timing leaks. Side-channel attacks are
explicitly out of scope, but this note is provided for users who
assess timing properties independently.
