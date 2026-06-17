---
status: accepted
---

# Experimental-feature promotion: one written, checkable bar

## Context

litmask ships experimental surfaces behind `unstable-`-prefixed Cargo
features — today `unstable-serde` (the `MaskSerialize` / `MaskDeserialize`
derives, SPEC Appendix E) and `unstable-stack` (the `mask_stack!` family,
SPEC §2.1.9). The prefix is the semver-exemption signal: the surface may
change or be removed in any release, and stabilization renames the feature
(drops the `unstable-` prefix) as a deliberate breaking change.

What we lack is a written bar for _when_ a feature has earned that rename.
Without one, promotion is an ad-hoc judgment call, and the failure mode is
specific and severe: stabilizing a surface with **silent gaps** (a serde
derive that quietly mishandles `#[serde(flatten)]`, a guard type that
overstates a guarantee). A stabilized API is a semver commitment; walking
one back costs a major bump. The bar must also fit the project's docs
doctrine — claims are tests, not prose, and decisions cite checkable
evidence (`file:line` / test name).

## Decision

An `unstable-X` feature graduates to `X` only when it satisfies **all**
generic gates below **and** its per-feature support matrix is complete
(every row a passing test). The promoting change MUST cite the evidence
(test names / `file:line`) for each gate; an unfalsifiable "the tests cover
it" does not satisfy a gate.

### Generic gates

1. **Real-world validation.** At least one genuine consumer or a realistic
   end-to-end integration test exercises the feature — not unit tests
   alone. (Same YAGNI discipline as the rest of the project: do not
   stabilize speculatively.)
2. **Settled surface.** No open design questions on the public API — the
   macro/derive name, accepted attributes, and generated items are final.
   Any "we might reshape this" disqualifies.
3. **Support matrix complete.** Every capability the feature advertises has
   a passing test; every plausible-but-unsupported input is **explicitly
   rejected** (a `compile_error!` or typed error), never silently
   mishandled. The matrix table (template below) is the exit checklist.
4. **Honest, reviewed security model.** Guarantees are stated with
   deliberate understatement; the threat model and residuals are
   documented; no self-describing-lie surface. What the feature does _not_
   protect is named.
5. **Full build/feature matrix.** Compiles and passes under both ciphers
   (`chacha20-poly1305`, `aes-gcm`) and the `std` + `no_std`+`alloc`
   configurations it claims; ecosystem interop is tested where relevant; a
   binary-scrub (or equivalent) test proves the security property; any
   added runtime path is benched.

### Per-feature support matrix (template)

Each experimental feature carries a table whose every row is green before
promotion. Unsupported rows are allowed only if the input is explicitly
rejected, with the rejection itself tested.

| Capability / input | Status | Evidence (test / `file:line`) |
|---|---|---|
| … | supported / rejected | … |

## Considered options

- _No written policy (per-PR judgment)._ Rejected: invites premature
  stabilization, and the silent-gap failure mode is exactly what an
  unwritten bar misses.
- _Bespoke criteria per feature._ Rejected: duplicative and drifts; two
  features promoting against different bars is how one ships with gaps the
  other would have caught.

## Consequences

- A promotion PR is gated on a filled support matrix with cited evidence;
  reviewers check the table, not vibes.
- Stabilization is a breaking change (the feature rename), MINOR pre-1.0.
- Each `unstable-` feature's SPEC section owns its support matrix (SPEC
  §2.1.9 for stack, Appendix E for serde); this ADR owns the generic bar
  they share.

## Implementation status

Policy only — no code. The per-feature matrices live with each feature in
the SPEC and are filled in as the feature matures; this ADR is the shared
gate they are checked against.
