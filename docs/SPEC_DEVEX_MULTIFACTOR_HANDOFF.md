# litmask DevEx — Multi-Factor Build/Runtime Key-Agreement: Handoff

> **Purpose.** Hand off one open design problem to a fresh agent for longer
> discussion. The problem is *how Alice supplies the correct build-time key
> material when her runtime uses a multi-factor `KeyProvider`*. This doc is
> self-contained: it captures the problem, the current codebase reality, the
> relevant DevEx-I definitions, and the constraints/rejections that bound the
> solution space. Nothing here is implemented — the whole DevEx variant chain
> (base → A…I) is spec exploration on top of a codebase that still reflects the
> **base spec**.
>
> **Status:** RESOLVED 2026-06-03 (design only — no code). See §-1. The decided
> design is folded into `docs/SPEC_DEVEX_I.md`, which is now authoritative; this
> handoff is retired.

---

## -1. Resolution (2026-06-03)

The open problem is **closed**. Decided design (folded into SPEC_DEVEX_I —
that doc is authoritative; this handoff is being deleted):

- **Scope narrowed to `machine_id` + exactly one external provider.** The general
  `MultiProvider` is **deleted** — it carried a variadic order/topology footgun
  (§3(C), §5.1) that has no clean build-side reproduction. With the combo fixed
  at arity 2, order is fixed too, so the footgun dissolves.
- **`machine_id` becomes a macro keyword carve-out, not a public provider type.**
  Four `init!` forms only:
  `init!()`, `init!(<provider-expr>)`, `init!(machine_id)`,
  `init!(machine_id + <provider-expr>)`. Machine binding is therefore **explicit
  in Alice's source** — chosen over a build-authoritative value-only form, which
  had an asymmetric silent-downgrade hole (one direction of dropped factor went
  undetected).
- **`emit()` stays dumb / presence-driven.** It composes from whatever material
  channels are populated — `LITMASK_MACHINE_ID` (raw target-host id, captured
  *before* the build per §4.1, so no post-build re-key) and `LITMASK_UNLOCK_KEY`
  (external material) — and publishes a **tracked** build→macro tag
  `cargo:rustc-env=LITMASK_SEAL_TIER=<tag>` (one of `tier0` / `external` /
  `machine` / `machine_external`). rustc-env is part of the crate compile
  fingerprint ⇒ reliable recompile; an `$OUT_DIR` marker file would be untracked.
- **The macro cross-checks the `init!` form against the tag (1:1 map) and emits
  `compile_error!` on any mismatch.** This is the breakthrough: build/runtime
  agreement is enforced at **compile time** on the macro-visible channel (form
  identity + tracked tag), *not* by grepping the `init!` arg text (alias-
  defeatable). Closes **both** dropped-factor directions — no silent downgrade.
- Composition is the fixed, machine-first, macro-injected
  `KDF(len_prefixed(machine_material) ‖ len_prefixed(external_material))`, reusing
  the existing 8-byte-LE length-prefix convention from `kdf.rs`.

Authoritative sections in SPEC_DEVEX_I: §2 intro (the four forms + parse rule),
§2.1 (no-silent-downgrade as a compile-time guarantee), §2.2 (fixed arity-2
composition), §2.4 (presence-driven tag table + form↔tag cross-check + AC4
narrowing), §3.3 (build channels), §4.1 (id captured pre-build), §8 (owed doc
edits), §9 (comparison rows).

The earlier "two surviving directions" in §6 are superseded: the chosen design is
a blend — direction (II)'s purpose-built two-factor construct (no general
MultiProvider), but with `machine_id` material supplied to the build (direction
(I)'s channel), reconciled by the compile-time tag cross-check rather than a
post-build bind.

---

## 0. Orientation (read this first)

litmask AEAD-encrypts string literals at compile time and decrypts them at
runtime, to hide sensitive plaintext from static analysis (`strings(1)`).
Canonical scenario: developer **Alice** ships app **Cryptio** to customer
**Bob**.

Key hierarchy:

```
seed (32-byte build master, ChaCha20Rng)
 ├─ mask_key   → encrypts every per-call-site blob (mask!())
 └─ unlock_key → encrypts mask_key into the `wrapper` envelope
```

Runtime flow: a `KeyProvider` yields `unlock_key` → decrypts `wrapper` → recovers
`mask_key` → decrypts each blob. AEAD failure (wrong unlock_key) → init panics /
errors with **no message** (avoid leaking identifiers).

The whole problem below exists because the **build** must produce a `wrapper`
that the **runtime** `KeyProvider` can open — and build and runtime evaluate the
key in **two different places, blind to each other** (see §3).

---

## 1. The problem, stated precisely

DevEx-I proposes a `MultiProvider` so Alice can combine factors, e.g.
machine-id **+** an external env key:

```rust
// runtime
litmask::init!(MultiProvider::new([&MachineIdProvider::new(), &EnvVarProvider::new("CRYPTIO_KEY")]));
```

Under the DevEx-I/F/G **material model** (§2 below), the runtime composes the
unlock_key like this:

```
material   = Σ len_prefixed(child_material_i)        # concat, ORDER-significant
unlock_key = KDF(material, "litmask-...")            # ONE kdf at the init boundary
```

For the wrapper to open, **the build must reproduce that exact unlock_key.** But
at build time (`emit()` in `build.rs`), litmask must know:

1. each child's **material bytes** (machine-id bytes, the env value, the file
   bytes, …), and
2. the **composition** — which factors, in **what order** — so the
   len-prefixed concat is byte-identical, and
3. apply **the same single KDF**.

That is the crux: **how does Alice declare the multi-factor topology + supply
each factor's material to the build, such that build and runtime agree without a
footgun?**

### 1.1 Why this is genuinely hard (the ordering-induced blindness)

The three stages run in a fixed order and **cannot see each other**:

| Stage | When | Knows | Cannot |
|---|---|---|---|
| `build.rs emit()` | first | build-side material bytes | see the `init!` argument |
| proc-macro expansion | second | the `init!` argument **as text** | evaluate it (no runtime) |
| runtime `init!` | third | the only place the provider is evaluated | influence the already-built wrapper |

So **compile-time prevention of a build/runtime mismatch is impossible.** A
mismatch surfaces only as an opaque AEAD-decrypt failure at runtime.

### 1.2 Single-factor case is already DISSOLVED (do not re-litigate)

For a single factor the user established the governing principle — **carry it
forward, don't reopen it**:

> **material = identity.** `unlock_key = KDF(material)`. The variable/file
> **name never enters the KDF** — names are plumbing. Two different var names
> carrying the **same bytes** → no problem. A "mismatch" only exists if the
> **material bytes** differ between build and runtime, and that is **Alice's
> secret-management responsibility, not a litmask API concern.**

User's words:

> "It's not a mismatch unless the key material supplied to `CRYPTIO_KEY` at
> runtime differs from the material supplied to `LITMASK_UNLOCK_KEY` at build
> time. If Alice is managing secrets properly, she should know what material she
> supplied. The env vars are just where the material gets pulled in. **The var
> names should not be bound to the result of the KDF.**"

Conclusion reached for single-factor: **no mechanism needed**, only documentation
of the material=identity contract. The hard part is **multi-factor**, where
litmask itself owns the *composition* (concat + order + KDF), so it cannot just
defer everything to Alice — litmask must reproduce its own composition at build.

---

## 2. The DevEx-I material model (relevant definitions)

These are **spec** (DevEx-I/F/G), **not yet code**. The current `KeyProvider`
differs (see §4).

- **KeyProvider returns *material*, not a finished key.** The framework applies
  **one KDF at the init boundary**. (Current code returns a finished
  `UnlockKey` — a key difference, see §4.)
- **MultiProvider** (`§2.2`): `MultiProvider::new([&a, &b, &c])` — a flat slice
  of `&dyn KeyProvider`. It **concatenates only, never KDFs**:
  `material = Σ len_prefixed(child_material)`. Composition is **order-significant
  = argument order**. There is **no verbatim/pre-hashed path** — the framework
  always KDFs once over the concatenated material.
- **Tier model** (G/I):
  - **Tier 0** — nonce-derived zero-config floor:
    `KDF(wrapper_nonce, "litmask-tier0-v1")`. Degrades to AEAD-`obfstr`; key
    recoverable from the artifact → **obfuscation only**. `init!()` bare.
  - **Tier 1** — external key custody (env / file / custom provider).
  - **Tier 2** — binding / multi-factor (`machine_id`, `multi`).
- **DevEx-I central bet:** delete **all** post-build re-keying — no
  `bind`/`reseal`/`inspect`/`verify` CLI, no derived locator. **Per-customer =
  per-build.** Locate the wrapper by its **compile-time address**, not by
  scanning. Per-customer rebuild is **cheap** (§0.4 of SPEC_DEVEX_I): pinned seed
  ⇒ `mask_key` constant ⇒ blobs byte-identical across customers ⇒ cached ⇒ a
  per-customer build only **re-seals the wrapper + re-links**.

### 2.1 The §3 gap that this handoff must close

SPEC_DEVEX_I §3.1 says build secrets are read from "env var, file, or stdin to
litmask-build" but **never specifies how `emit()` COMPOSES a multi at build time,
nor how Alice declares the build-side topology.** That undefined seam is exactly
the problem in §1.

---

## 3. Build interfaces considered (and their costs)

For `MultiProvider::new([env, file])`, `emit()` must reproduce the runtime
composition (len-prefix concat + single KDF). Three shapes of build interface:

- **(A) Finished-key in:** Alice hands `emit()` a finished unlock_key.
  **Forbidden** — double-KDF (runtime would KDF it again); also defeats the whole
  material model.
- **(B) Len-prefix-concat blob in:** Alice hands `emit()` the pre-concatenated
  `Σ len_prefixed(material)`. **Leaks the wire format** into Alice's build
  tooling and is fragile to order.
- **(C) Per-factor channels + build topology declaration:** Alice declares the
  factor set + order to the build *and* supplies each factor's material on its
  own channel; `emit()` composes. **Cleanest in spirit**, but requires declaring
  topology in **two blind places** (build decl **and** the `init!` arg) →
  **topology + order agreement footgun**, because §2.2 is order-significant.

---

## 4. Current codebase reality (what actually exists today)

**Critical:** the repo is essentially the **BASE SPEC**, not variant B/I. The
entire A→I chain is unimplemented. Ground any proposal in these facts:

- **`litmask/src/provider/mod.rs` — `KeyProvider` returns a FINISHED key:**
  ```rust
  pub trait KeyProvider: Send + Sync {
      fn unlock_key(&self) -> Result<UnlockKey, KeyError>;
  }
  ```
  No material/KDF-boundary model. **No `MultiProvider`.** Built-ins:
  `EnvVarProvider`, `FileProvider`, `MachineIdProvider` (feature-gated),
  `StaticProvider` (tests-only).
- **`litmask-build/src/lib.rs` — build GENERATES the unlock_key:**
  ```rust
  let mut rng = ChaCha20Rng::from_seed(*seed);
  rng.fill_bytes(&mut mask_key);
  rng.fill_bytes(&mut unlock_key);   // build invents unlock_key
  ```
  Then writes a **secret `litmask.config`** (TOML with unlock_key + locator) to
  the profile dir, plus seed/key/wrapper `.bin` to `OUT_DIR`. This is the
  **operator-does-NOT-own-the-key** base model. Variant B/I flips this to
  **operator-owned** unlock_key — i.e. the build must *derive* unlock_key from
  Alice-supplied material instead of inventing it. **That flip is the precondition
  for the whole multi-factor question** and is itself unimplemented.
- **`litmask-internal/src/wire.rs` — wrapper still carries a PLAINTEXT header**
  (`VERSION_OFFSET=0`, `CIPHER_OFFSET=1`, `NONCE_OFFSET=2`, `HEADER_LEN=14`,
  `WRAPPER_LEN=62`). Spec I/B want it **opaque (61 bytes, no plaintext header)**.
- **`litmask-internal/src/kdf.rs`** — `MACHINE_ID_DERIVATION_CONTEXT = "machine-v1"`
  (the one BLAKE3 separator that lands in user binaries, shared
  runtime+CLI-bind). `derive_machine_id_key(context, machine_id, salt)` =
  `BLAKE3::derive_key(context, len_le8(machine_id) || machine_id || salt)`.
  **8-byte LE length-prefix convention used throughout** — this is the existing
  precedent for the proposed multi concat.
- **`litmask/src/provider/machine_id.rs`** —
  `MachineIdProvider { salt: Option<&'static [u8]> }`; `unlock_key()` calls
  `machine_uid::get()` then `derive_machine_id_key(...)`, returns a finished
  `UnlockKey`. Salt is compile-time `&'static [u8]`.
- **`litmask-cli/src/`** still has `bind.rs`, `inspect.rs`, `config.rs` — all
  things DevEx-I **deletes**.
- **`litmask/src/runtime.rs`** — `__init_with_wrapper<P: KeyProvider>` calls
  `provider.unlock_key()?` then `decrypt_wrapper(...)`; AEAD failure →
  `InitError::Decryption`. Lazy-defaults to `EnvVarProvider::default()` under std
  if no `init_with!` ran. Bare `panic!()` (no message) on failure.

---

## 5. Constraints and REJECTIONS (must carry into the discussion)

The user has already rejected two "solutions". Do **not** re-propose them:

1. > "**Canonical ordering cannot work** precisely because we allow user defined
   > custom providers."

   (An arbitrary `impl KeyProvider` has no stable tag to sort on, so the build
   cannot deterministically re-derive the order. Order-by-sorting is dead.)

2. > "**Fingerprint is still an ugly Band-Aid** over the problem, not solving it
   > at the source."

   (A build-embedded composition fingerprint that fails fast at runtime detects
   the mismatch but does not prevent it / does not address the root cause.)

Other firm constraints:

- **material = identity** (§1.2) — names are plumbing, never enter the KDF.
- **Finished-key build input is forbidden** (double-KDF) — §3(A).
- DevEx-I deletes post-build tooling; a *build-time* CLI is still on the table,
  but anything that resurrects `bind`/`reseal` semantics fights the variant's
  central bet.

---

## 6. The two surviving directions (the actual discussion)

The user narrowed the design space and named the two live options:

> "Another option is to **add CLI to litmask to support building the correct
> unlock key from multiple factors.** Finally, we can **reconsider the design
> altogether.** In reality, **the only multi-factor functionality I want is
> machine ID plus some other external key provider.**"

So scope the discussion to **machine_id + exactly one external provider** (env /
file / custom), and weigh:

- **(I) Build-time CLI / `emit()` factor composition.** A litmask build helper
  that takes each factor's material on its own channel + a topology declaration,
  and produces the unlock_key the runtime will reproduce. Must resolve: where
  does the machine-id factor's material come from **at build time** (the build
  host's machine-id is meaningless — Bob's machine is the target)? This is the
  reason machine-id was historically a *post-build bind* step, which I deletes.
  **Key tension to crack:** machine_id is inherently a *target-host* factor
  resolved *after* the build, but I forbids post-build re-keying. How can a
  per-customer build incorporate Bob's machine-id without a post-build bind?
- **(II) Redesign scoped to machine_id + one external.** Because the only wanted
  combo is fixed, consider **not** a general `MultiProvider` at all — instead a
  purpose-built two-factor construct where the external factor is the
  build-suppliable material and machine_id is composed **at runtime only**,
  layered so the build never needs Bob's machine-id. E.g. build seals under the
  external factor; runtime additionally folds machine-id — but that changes what
  the wrapper protects and must be worked through against the tier model.

Either way the deliverable from the next session is a **decided design** for
machine_id + one external provider that (a) the build can reproduce, (b) carries
no order/topology footgun, and (c) respects I's "no post-build re-keying" bet —
or an explicit, justified exception to that bet for the machine-id factor.

---

## 7. Pointers

- `docs/SPEC_DEVEX_I.md` — the leading variant (build-sealed only, no post-build
  tooling). §0.4 cheap-rebuild, §2.2 MultiProvider, §3 build secrets, §4.5
  machine-id-as-stable-host-factor.
- `docs/SPEC_DEVEX_G.md`, `_F.md` — tier model + material-returning provider
  origins (collapsed into I).
- `docs/SPECIFICATION.md` — the implemented base spec.
- `CONTEXT.md` — domain glossary (ubiquitous language).
- Code: `litmask/src/provider/`, `litmask/src/runtime.rs`,
  `litmask-internal/src/{kdf,wire}.rs`, `litmask-build/src/lib.rs`.
