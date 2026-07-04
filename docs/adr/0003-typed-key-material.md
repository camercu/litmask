---
status: accepted
---

# Empty key material is unrepresentable, not re-checked

## Context

Both keyed inputs to the unlock-key derivation are non-secret-but-load-bearing
values that must never be empty:

- **External material** (`LITMASK_UNLOCK_KEY`, key files, custom-provider
  bytes). An unpopulated CI secret expands to `""`; sealing under
  `KDF("litmask-unlock-v1", "")` yields a key everyone knows.
- **The host machine id** (`machine_uid::get()`, the `LITMASK_MACHINE_ID`
  token). An empty read would bind a binary to "any host with the same broken
  read".

The first hardening pass rejected empty at each site independently: a build-side
`require_external_material` panic, a runtime `derive_nonempty_material` →
`InvalidFormat`, the token codec's `EmptyId`, and a runtime `is_empty` in the
machine provider. Four guards enforcing one invariant, which must stay
byte-for-byte in agreement (the build and runtime both derive over the same
material) or a seal the build accepts becomes un-openable at runtime. Worse, the
shared normalization entry point — `UnlockKey::derive(&[u8])`, public and
infallible, documented as the derivation "for every external factor (env, file,
custom provider)" — happily derived a key from empty bytes, so a custom
`KeyProvider` that skipped the guard re-opened the gap.

## Decision

Make empty **unrepresentable where the key is derived**, via two validated
domain types in `litmask-internal`, constructed once at each channel's edge
(parse, don't validate):

- `UnlockMaterial::new(&[u8]) -> Result<_, EmptyMaterial>` — strips at most one
  trailing newline, rejects the empty result. `derive_external_unlock_key` and
  `UnlockKey::derive` take `UnlockMaterial`, so the KDF cannot be handed empty
  bytes and normalization lives at the one construction site (out of the KDF).
- `MachineId::new(&str)` / `MachineId::from_token(&str)` — both reject an empty
  id; `from_token` also verifies the check group. `derive_machine_id_key` takes
  `&MachineId`.

The four guards collapse into these two constructors; the build seal and every
provider (built-in and custom) pass through them, so build↔runtime agreement on
"what is empty" is type-enforced rather than comment-enforced. `EnvVarProvider`
/ `FileProvider` map `EmptyMaterial` to `KeyError::InvalidFormat`; the build maps
it to its actionable panic. Observable behavior is unchanged — empty is still
rejected at build and surfaces as `InvalidFormat` at runtime — so the
SPECIFICATION's contracts (§1.6.3, §2.5.2.3/§2.5.3.2, §2.9.3.3) are untouched;
this is a structural change proven behaviour-preserving by the unchanged
round-trip and `machine_tier_e2e` tests.

## Considered options

- **Keep the four site-local guards (with a shared `is_empty` predicate).**
  First recommendation, and defensible: the true security boundary is the
  _build seal_ — because `emit()` refuses to seal empty material, an empty key
  at runtime can never open any wrapper; it fails closed regardless, so the
  runtime guards are _diagnostic_ (a named error instead of a generic decrypt
  failure), not a security fix. Under a "minimize churn / avoid the breaking
  API change" frame this wins. **Reversed** under a "best-possible-codebase"
  frame: the guarantee is worth carrying in the type system (make-illegal-
  states-unrepresentable), the churn is a pre-1.0 minor bump, and the shared
  predicate still let a future custom provider forget the check. The reversal
  is recorded here deliberately — the decline was constraint-bound, not a
  judgment that the typing was wrong.
- **One conflated `NonEmptyMaterial` newtype for both inputs.** Rejected:
  external material and the machine id are distinct domain values at different
  layers (different normalization, different error surface). Two types, not one.

## Consequences

- **Breaking (MINOR, pre-1.0):** `UnlockKey::derive` takes `UnlockMaterial`;
  `derive_machine_id_key` takes `&MachineId`. `UnlockMaterial` / `EmptyMaterial`
  are re-exported from `litmask` because a custom `KeyProvider` constructs
  `UnlockMaterial` before deriving. `decode_machine_id_token` stays as a thin
  `&str`-returning wrapper over `MachineId::from_token` for callers wanting the
  id, not the type.
- A new built-in provider or a third-party `KeyProvider` cannot re-open the
  empty-secret gap without going out of its way — the natural derivation path
  requires a validated type.
- The empty-material predicate and the newline normalization each live at one
  site; a change to either is one edit, not four that can drift into
  un-openable seals.
