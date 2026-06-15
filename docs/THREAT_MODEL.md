# Threat Model

This document describes what `litmask` protects against, what it does
not, and what limitations apply when things go wrong.

## Attacker levels

`litmask` uses a four-level model. The keyless **Embedded** default tier
targets **Level 1** only — it recomputes `unlock_key` from the wrapper's
cleartext nonce, so the key is recoverable from the artifact; this buys
`strings(1)` resistance, not secrecy. Layered key management
(`EnvVarProvider`, `FileProvider`, the `bind_to_machine` keyword tier, or a
custom provider) raises the baseline to **Level 2** and provides meaningful
**Level 3** resistance.

### Level 1 — Casual inspection

Runs `strings`, opens a hex editor, or browses `.rodata`.

**Stopped by:** any encryption. `litmask` encrypts every masked literal
with ChaCha20-Poly1305 (or AES-256-GCM) at compile time. No masked
plaintext survives in the binary.

### Level 2 — Static reverse engineering

Uses a disassembler (Ghidra, IDA), identifies decryption routines,
manually decrypts embedded ciphertext.

**Stopped by (layered tiers only):** per-string unique nonces, AEAD
ciphers, and the absence of plaintext key material in the binary.
`mask_key` is encrypted under `unlock_key`, which under `EnvVarProvider`,
`FileProvider`, or the machine tier is sourced at runtime and never
embedded. The keyless **Embedded** default does **not** reach Level 2: it
recomputes `unlock_key` from the wrapper's cleartext nonce, so the key is
recoverable from the binary.

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
| Zero-config build (keyless Embedded tier) | `strings`, casual binary inspection (Level 1) — `unlock_key` is recoverable from the artifact |
| `EnvVarProvider` | Above + Level 2: `unlock_key` sourced at runtime, not embedded |
| `FileProvider` + filesystem permissions | Above with OS-enforced access control |
| Machine tier (`init!(bind_to_machine)`) | Above + binary moved to a different machine |
| Two-factor tier (`init!(bind_to_machine + <provider>)`) | Above + the external factor (env/file/vault) the binary alone never carries |
| Custom `KeyProvider` (vault, HSM) | Above + offline attackers |

"Zero-config" means no project configuration beyond `build.rs` and no
runtime key provisioning — the keyless Embedded default recomputes
`unlock_key` from the embedded nonce. Sourcing the key at runtime (e.g.
`LITMASK_UNLOCK_KEY` via `EnvVarProvider`) is opt-in through `init!(provider)`.

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

After a governing `litmask::init!(provider)` fails, `mask!()` cannot be
used because `mask_key` is undecrypted. Any error message the application
displays about the failure must use plaintext strings, opaque error codes,
or sysexits. (The keyless Embedded tier has no fallible init — it lazily
self-initializes — so this applies to the External / Machine tiers.)

This is an inherent property: any decryption mechanism for init-failure
messages would require a second always-available key, which would itself
be embedded as plaintext — defeating the purpose.

The recommended pattern for minimal plaintext:

```rust
if let Err(e) = litmask::init!(litmask::EnvVarProvider::default()) {
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
