# litmask architecture (start here)

The one-page mental model of how litmask works. Read this first; the other
docs go deeper on their own slice (see [Map of the docs](#map-of-the-docs)).

litmask encrypts string literals at **compile time** (AEAD) and decrypts
them at **runtime**. Plaintext never lands in the binary's `.rodata`.

## The three moving parts

```text
build time (build.rs)        compile time (proc-macro)      run time
─────────────────────        ─────────────────────────      ────────────────
litmask-build::emit()        mask!("secret") expands to:    init!(provider)? (optional)
  → derives keys, seals         AEAD-encrypt the literal       installs a governing provider
    the wrapper                 into a &[u8] blob;             mask!() decrypts a blob using
  → writes OUT_DIR blobs        embeds include_bytes!          the mask key (recovered from
  → publishes seal tier         of the wrapper                the wrapper on first use)
```

- **`litmask-build`** runs in the consumer's `build.rs`. It generates a
  per-build seed, derives the `mask_key` and the `unlock_key`, seals the
  `mask_key` into the **wrapper** (`AEAD(mask_key)` under `unlock_key`),
  and writes the build artifacts.
- **`litmask-macros`** (the `mask!` / `init!` proc-macros) reads those
  artifacts at expansion, encrypts each literal into an embedded blob, and
  emits the runtime calls.
- **`litmask`** (runtime) recovers the `mask_key` from the embedded wrapper
  and decrypts blobs on demand. **`litmask-internal`** holds the shared
  wire format and crypto primitives; **`litmask-cli`** mints unlock
  material (`keygen`) and prints the host machine id (`show-machine-id`).

## What the build writes, and who reads it

Every build artifact has exactly one job and a real consumer — enforced by
`litmask-build/tests/artifacts_have_consumers.rs`. No key material is ever
written to disk (§1.7.4); arbitrary unlock material comes from `litmask
keygen`.

| Artifact | Written by | Read by |
|---|---|---|
| `$OUT_DIR/litmask_seed.bin` | `emit()` | `litmask-macros` — per-call-site nonce derivation |
| `$OUT_DIR/litmask_key.bin` | `emit()` | `litmask-macros` — encrypts each `mask!` literal |
| `$OUT_DIR/litmask_wrapper.bin` | `emit()` | `litmask` runtime via `include_bytes!`; `weak_mask!` expansion |
| `LITMASK_SEAL_TIER` (rustc-env) | `emit()` | `init!` macro — form↔tier cross-check at compile time |
| `target/<profile>/litmask_seed.bin` (debug only) | `emit()` | next `emit()` — reproducible incremental builds |

## Seal tiers (how the `unlock_key` is sourced)

The tier is fixed at **build time** by which env vars are present, and is
**uniform across a dependency graph** (the same build environment reaches
every crate's `emit()`). The `unlock_key` is re-established at runtime, never
stored.

| Tier | Build input | Runtime source of `unlock_key` |
|---|---|---|
| **Embedded** (default) | none | recomputed from the public wrapper nonce — keyless, `strings(1)`-resistance only |
| **External** | `LITMASK_UNLOCK_KEY` | a `KeyProvider` re-supplies the same material (`EnvVarProvider` / `FileProvider`) |
| **Machine** | `LITMASK_MACHINE_ID` | re-derived from the host machine id at startup |
| **MachineExternal** | both | the two-factor composition of the above |

## Initialization & governance (ADR-0001)

- There is **no bare `init!()`**. The keyless Embedded tier
  **self-initializes** on the first `mask!()`.
- The surviving `init!` forms **govern**: `init!(provider)`,
  `init!(bind_to_machine)`, `init!(bind_to_machine + provider)` install one
  process-global **governing provider** and unlock the whole dependency
  graph under a uniform seal.
- **Lazy-unlock rule:** on first `mask!()` for a wrapper, if a governor is
  installed it supplies the key for that wrapper regardless of tier;
  otherwise only the keyless Embedded floor self-unlocks (a non-Embedded
  wrapper with no governor refuses, naming the ordering bug).

### The three usage patterns

| Pattern | Who masks | Who unlocks |
|---|---|---|
| **Self-masking** | a host binary masks its own strings | itself (Embedded floor, or its own governing `init!`) |
| **Transparent masking** | the host links **masking libraries** | each crate self-unlocks at the Embedded floor; no `init!` |
| **Governed masking** | the host links masking libraries | one governing `init!(provider)` + a uniform seal unlocks the whole graph |

> **Convention for library authors:** if your crate uses litmask
> internally, **never call `init!()` — only `mask!()`.** Unlocking is the
> host binary's concern. A library that calls `init!()` (or masks in a
> `static`/constructor) seizes governance from the host and is a bug.

## Map of the docs

| Doc | Owns |
|---|---|
| **`docs/ARCHITECTURE.md`** (this) | the mental model — read first |
| `CONTEXT.md` | ubiquitous-language glossary (the canonical terms) |
| `README.md` | quickstart + the macro reference (user-facing) |
| `docs/SPECIFICATION.md` | normative requirements, invariants, and rationale (behavior is owned by the **code + tests**, which are authoritative) |
| `docs/DEPLOYMENT.md` | operator/host guide per seal tier |
| `docs/THREAT_MODEL.md` | what litmask does and does **not** protect against |
| `docs/MIGRATION.md` | migrating from `obfstr` / `litcrypt` |
| `docs/SECURITY_AUDIT.md` | dependency and security review |
| `docs/adr/` | load-bearing architectural decisions |
| `CLAUDE.md` / `AGENTS.md` | contributor & agent working agreement |

Behavior questions are best answered by the **code, its rustdoc, and the
tests** — prose docs capture the _why_ and the cross-cutting invariants, and
may lag the code. When they disagree, the code wins (and the doc is a bug).
