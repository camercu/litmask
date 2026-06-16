# litmask — Zeroize-on-Drop for Masked Output — Tasks

Source: conversation 2026-06-16 (grill-me design session). Rolls into:
[docs/SPECIFICATION.md](./SPECIFICATION.md), [docs/THREAT_MODEL.md](./THREAT_MODEL.md),
[README.md](../README.md).

Vertical slices, walking skeleton first. Each slice cuts through every
affected layer (runtime / macro codegen / tests / docs) and is demoable
on its own. Docs update piece-by-piece inside each slice. TDD
throughout: test first (RED), implement (GREEN), test + impl in the same
atomic pathspec commit.

## Scope and honesty (governing constraints)

- **Threat:** memory-remanence _hygiene_ only — shrink the window where
  decrypted plaintext lingers in residual memory after a secret is no
  longer needed, so a `strings`/grep pass over a remanence artifact
  won't recover an already-dropped secret. Covers core/crash dumps,
  swap files, hibernation images, and freed-heap reuse.
- **NOT in scope, must never be claimed:** live debugger / runtime
  memory inspection (THREAT_MODEL Level 4 stays out of scope; swap and
  hibernation may also capture a page while the value is still live,
  before drop), and re-derivation — the `mask_key` is resident `'static`
  (`litmask/src/runtime/mask_key_store.rs:14`, `:73`) and ciphertext
  blobs live in `.rodata`, so an attacker with any such artifact can
  re-derive regardless of output wiping. Zeroize defeats the _grep_, not
  the _analyst_.
- The byte-clearing primitive is `zeroize`'s upstream-tested contract —
  cite it, do not re-prove it. Our tests prove routing, types, capacity,
  and that the drop path triggers a `Zeroize` call.
- No new feature flag (`zeroize` is already a mandatory dependency,
  `litmask/Cargo.toml:102`). No `zmask!` macro family. No `unsafe`
  (forbidden workspace-wide).

---

## Task 1: Capture requirements in the spec (HITL)

**Implements:** new SPECIFICATION section (number assigned at write time)
**Blocked by:** None — start here

Add a section to `docs/SPECIFICATION.md` recording the high-level
requirements settled in the design session, so every later slice has a
checkable home for what it implements. Requirements only — the
configuration→resistance ladder and coverage matrix live in
THREAT_MODEL.md (Task 5), not here.

The section must state, as numbered requirements:

- A consumer can opt a masked `String`/`Vec<u8>` output into
  zeroize-on-drop without litmask changing the default `mask!` return
  type.
- `mask_format!` wipes its per-fragment decrypted plaintext and bounds
  accumulator reallocation by reserving capacity for the known
  (compile-time) literal fragments; runtime-argument growth beyond that
  reserve is a documented residual.
- `#[derive(MaskDebug)]` wipes the decrypted type/field names it
  materializes during `fmt`, with byte-identical `Debug` output.
- `mask!(c"…")` (CString) is explicitly **excluded**, with a documented
  escape hatch (`mask!("secret")` → wrap the `String` → build a
  transient `CString` at the FFI boundary).
- Scope is memory-remanence hygiene (core/crash dumps, swap,
  hibernation, freed-heap reuse); the feature must not be documented as
  defeating runtime memory inspection or re-derivation.

### Acceptance Criteria

- [ ] SPECIFICATION.md has a numbered subsection enumerating the
      requirements above; each is phrased as an observable obligation a
      later task/test can satisfy.
- [ ] The section names memory-remanence hygiene as the scope and
      explicitly disclaims memory-inspection / re-derivation defense.
- [ ] User confirms the requirement set and its acceptance phrasing
      before downstream slices begin.

## Task 2: Walking skeleton — the `Zeroizing` seam (AFK)

**Implements:** Task 1 (consumer opt-in requirement)
**Blocked by:** Task 1

Thinnest end-to-end path proving the architecture: a consumer can wrap
any masked `String` output and get a buffer that wipes on drop, and an
internal seam exists for the macros to emit.

- Re-export `zeroize::Zeroizing` as `litmask::Zeroizing` (public API).
- Add `__internal::__decrypt_string_zeroizing(blob, wrapper, tier) ->
  Zeroizing<String>`, preserving the "expansion never names `String`"
  invariant (`litmask/src/runtime/mod.rs:210`). It must reuse the same
  single allocation `__decrypt_string` does (no extra plaintext copy).
- Self-contained rustdoc on the consumer pattern
  (`Zeroizing::new(mask!("…"))`) including the one-line honest scope; no
  link to spec/threat-model.

### Acceptance Criteria

- [ ] `let s = litmask::Zeroizing::new(litmask::mask!("secret"));`
      compiles and `&*s` Derefs to `&str`.
- [ ] `__decrypt_string_zeroizing` returns `Zeroizing<String>` (type-level
      test) whose value round-trips the masked plaintext.
- [ ] A drop-path test asserts dropping a `Zeroizing<T>` calls
      `T::zeroize` exactly once (proves wiring to zeroize-on-drop). Uses a
      no-`Drop` probe rather than `provider/mod.rs:84`'s `Counted`, whose
      own `Drop` would double-count under `Zeroizing`.
- [ ] Rustdoc on `mask!` carries the usage pattern + honest scope and
      reads correctly standalone (no cross-doc links).
- [ ] `just ci` green.

## Task 3: MaskDebug internal name wipe (AFK)

**Implements:** Task 1 (MaskDebug requirement)
**Blocked by:** Task 2

Route the decrypted type/field names that `#[derive(MaskDebug)]`
materializes during `fmt` through the zeroizing seam, so they wipe at
scope exit. The shared `mask_name`/`mask_ident` codegen must stay on the
plain `__decrypt_string` for serde (whose `masked_static_name`
deliberately `Box::leak`s — zeroize there is meaningless), so the
zeroizing path is MaskDebug-specific.

### Acceptance Criteria

- [ ] `{:?}` / `{:#?}` output of a `#[derive(MaskDebug)]` type is
      byte-identical to before (existing snapshot/Debug tests stay green).
- [ ] A routing test shows MaskDebug emission references the zeroizing
      seam, while serde emission still references plain `__decrypt_string`.
- [ ] No change to serde derive behavior or output.
- [ ] `just ci` green.

## Task 4: mask_format fragment-wipe + capacity reserve (AFK)

**Implements:** Task 1 (mask_format requirement)
**Blocked by:** Task 2 (independent of Task 3 — may run in parallel)

Make `mask_format!` wipe each decrypted literal fragment and bound
accumulator reallocation. Each fragment temporary is bound to a
`Zeroizing` local (via the seam) before `write_str`, wiped at scope
exit. The accumulator is created with `with_capacity` equal to the sum
of the compile-time fragment byte-lengths. `mask_print!`/`mask_write!`
inherit the fragment wipe for free; their final accumulator is a sink-
bound temporary and is intentionally left unwrapped (the data
deliberately escapes to the destination).

### Acceptance Criteria

- [ ] `mask_format!` output value is unchanged (existing format tests
      green).
- [ ] A unit test asserts the reserved capacity equals the sum of the
      compile-time fragment byte-lengths (pins the capacity decision).
- [ ] A routing test shows each fragment is bound to a zeroizing local
      before being written into the accumulator.
- [ ] `mask_print!`/`mask_write!` still emit identical output; their
      fragment temporaries route through the seam.
- [ ] `just ci` green.

## Task 5: Security docs + reconcile (HITL)

**Implements:** Task 1 (scope/honesty requirements)
**Blocked by:** Tasks 2, 3, 4

Now that coverage is real, document it honestly and reconcile the
standing comments. Written last so the matrix reflects shipped behavior.

- THREAT_MODEL.md: new subsection near Level 4 with a **coverage
  matrix** — String/Vec (wrap-complete), `mask_format!` (internal
  fragment-wipe + wrap; runtime-arg-growth residual),
  `mask_print`/`mask_write` (fragments only, by design), CString
  (excluded + escape hatch), MaskDebug (automatic). Each row **cites the
  test** that pins it. State explicitly that Level 4 (runtime memory
  inspection) **stays out of scope** — this is memory-remanence hygiene
  (core/crash dumps, swap, hibernation, freed-heap reuse), not
  memory-inspection or re-derivation defense.
- README "Security model": keep the existing "Does NOT protect against
  runtime memory inspection" line verbatim; add one sentence on
  memory-remanence hygiene + the `Zeroizing::new(mask!(…))` usage
  pattern.
- Reconcile `litmask/src/runtime/mask_key_store.rs:14` ("threat model is
  the binary at rest, not process memory") so the narrow hygiene
  exception is noted without contradiction.
- Document the CString exclusion + escape hatch where c-string masking
  is described.

### Acceptance Criteria

- [ ] THREAT_MODEL.md coverage matrix present; every row cites an
      existing test (file:line or test name) so the claim is checkable.
- [ ] THREAT_MODEL.md states Level 4 stays out of scope and frames the
      feature as memory-remanence hygiene only.
- [ ] README security section keeps the memory-inspection disclaimer
      verbatim and adds the usage pattern.
- [ ] `mask_key_store.rs:14` comment reconciled (no contradiction).
- [ ] CString exclusion + escape hatch documented.
- [ ] No doc claims defeat of runtime memory inspection or
      re-derivation. User confirms honesty wording.
- [ ] `just ci` green (typos/markdown/links pass).
