# Promotion checklist — `unstable-serde` → `serde`

Tracks `unstable-serde` against the shared bar in
[ADR-0002](../adr/0002-experimental-feature-promotion.md). Stabilization
renames the feature `unstable-serde` → `serde` (a breaking change by
design, MINOR pre-1.0). The normative surface lives in SPEC Appendix E;
this file is the exit checklist and cites the evidence for each gate.

Every claim names a test or `file:line` so it can be re-verified (project
doc doctrine: decisions cite checkable evidence, no unfalsifiable "the
tests cover it"). Paths are relative to the repo root.

## Generic gates (ADR-0002)

| # | Gate | Status | Evidence |
|---|---|---|---|
| 1 | Real-world validation (genuine consumer or realistic e2e, not unit tests alone) | ✅ | `litmask/examples/mask_serde_demo.rs` is built and its compiled binary scrubbed end-to-end by `litmask/tests/example_scrub.rs::mask_serde_demo_names_and_fixtures_absent_from_binary` |
| 2 | Settled surface (derive names, attributes, generated items final) | ⚠️ | Names `MaskSerialize` / `MaskDeserialize` final; subset in Appendix E §E.2.5 landed. One open call: reclassify `into`/`from`/`try_from`/`getter` from "deferred" to "out of scope" (see Open items) |
| 3 | Support matrix complete (every advertised row tested; every unsupported input explicitly rejected + that rejection tested) | ✅ | See [Support matrix](#support-matrix) below — all supported rows have twin-tests, all rejected rows have trybuild cases |
| 4 | Honest, reviewed security model (understated guarantees, residuals named, no self-describing-lie surface) | ✅ | Residuals enumerated in SPEC §E.3 (plain-derive re-embed, self-describing-format runtime print, serde-internal strings); threat model §1.1; at-rest-only scope stated §E.2.3 |
| 5 | Full build/feature matrix (both ciphers; claimed std/no_std; ecosystem interop; binary scrub; new runtime paths benched) | ⚠️ | One sub-item left (bench); see below |

### Gate 5 detail

| Sub-item | Status | Evidence / gap |
|---|---|---|
| `chacha20-poly1305` (default) | ✅ | Serde tests run under `--all-features` (`justfile:122` `test-all-features`); chacha wins whenever enabled (`litmask-internal/src/aead.rs:33`), so this is the cipher actually exercised |
| `aes-gcm` | ✅ | `test-aes-gcm` (`justfile`) now folds in `unstable-serde`, running the serde twin tests under `--no-default-features --features std,aes-gcm` (106 serde tests green). The masked-name blob is cipher-specific, so this is a distinct decrypt path from chacha |
| `std` claimed; `no_std` not claimed | ✅ | §E.2.3 requires `std` (names leaked into `OnceLock<&'static str>`); no no_std obligation to test |
| Ecosystem interop | ✅ | Wire/behavior identity pinned against real serde + `serde_json` twins across the matrix (e.g. `litmask/tests/mask_serde_rename.rs`); §E.2.1 documents the non-self-describing-format (bincode/postcard) shape contract |
| Binary scrub proves the property | ✅ | `litmask/tests/example_scrub.rs::mask_serde_demo_names_and_fixtures_absent_from_binary` |
| New runtime path benched | ❌ | **Gap.** The name-decrypt + `OnceLock` caching path (§E.2.3) is unbenched; `benches/litmask-bench/benches/decrypt.rs` covers `mask!` only. Either add a serde-name-decrypt bench, or document that the path reduces to the already-benched `mask!` decrypt plus a one-time cache fill and accept that as the evidence |

## Support matrix

Mirrors SPEC §E.2.5. Every supported row is a passing twin-test against
the plain serde derive (byte-identical wire / behavior, §E.2.1/§E.2.6).
Every rejected row is a `compile_error!` pinned by a trybuild case.

### Supported

| Capability / input | Status | Evidence (test) |
|---|---|---|
| `rename` / `rename(serialize=,deserialize=)` (container, variant, field) | supported | `litmask/tests/mask_serde_rename.rs`; parser parity `litmask-macros/src/serde_attrs.rs` tests |
| `rename_all` (+ split), all 8 case rules | supported | `litmask/tests/mask_serde_rename_all.rs`; rule parity `serde_attrs.rs::rename_rule_*_conventions_match_serde` |
| `skip` / `skip_serializing` / `skip_deserializing` (named field) | supported | `litmask/tests/mask_serde_skip.rs` |
| `skip_serializing_if = "path"` | supported | `litmask/tests/mask_serde_skip_if.rs` |
| `default` / `default = "path"` | supported | `litmask/tests/mask_serde_default.rs` |
| `alias` (field) | supported | `litmask/tests/mask_serde_alias.rs` |
| `deny_unknown_fields` (container) | supported | `litmask/tests/mask_serde_alias.rs::deny_unknown_fields_*` |
| `bound` / `bound(serialize=,deserialize=)` (container) | supported | `litmask/tests/mask_serde_bound.rs` |
| `transparent` (container) | supported | `litmask/tests/mask_serde_transparent.rs` |
| `with` / `serialize_with` / `deserialize_with` (named field) | supported | `litmask/tests/mask_serde_with.rs` |
| Generic types (per-param `Serialize`/`Deserialize<'de>` bound) | supported | `litmask/tests/mask_serde_bound.rs` |
| `&str`/`&[u8]` (opt. `Option`) implicit borrow | supported | §E.2.6; deserialize tests `litmask/tests/mask_deserialize.rs` |
| `#[mask_all]` derive swap (serde ↔ masked) | supported | `litmask/tests/mask_all_serde.rs` |
| Missing `Option<T>` field → `None`; missing required → error | supported | `litmask/src/serde_support.rs::missing_field_*` |

### Rejected (reject-loud, explicitly tested)

| Input | Status | Evidence (trybuild) |
|---|---|---|
| `union` | rejected (`grammar`) | `litmask/tests/compile/mask_serialize_union.rs` (+ deserialize twin) |
| `flatten` (field) | rejected (`invalid-arg`) | `litmask/tests/compile/mask_serialize_serde_attr_field.rs` (+ deserialize) |
| `tag` / `untagged` / `content` (container) | rejected (`invalid-arg`) | `litmask/tests/compile/mask_serialize_serde_attr_container.rs` (+ deserialize) |
| `other` (variant) | rejected (`invalid-arg`) | `litmask/tests/compile/mask_serialize_serde_attr_variant.rs` (+ deserialize) |
| `with`/`serialize_with`/`deserialize_with` on a generic type | rejected (`invalid-arg`) | `serde_attrs.rs::reject_with_on_generic`; compile case `litmask/tests/compile/mask_serialize_with_on_generic.rs` |
| `#[serde(...)]` on a tuple field | rejected (`invalid-arg`) | `serde_attrs.rs::reject_tuple_field_attrs`; compile case `litmask/tests/compile/mask_serialize_skip_tuple_field.rs` |
| Any other unsupported key (`getter`/`into`/`from`/`try_from`/explicit `borrow`/variant `alias`) | rejected (`invalid-arg`) | `serde_attrs.rs::unsupported` + unit `unsupported_key_is_reject_loud` |

## Open items blocking promotion

1. ~~**Gate 5 — aes-gcm × serde untested.**~~ Done: `test-aes-gcm` now
   folds in `unstable-serde` (`justfile`), so the serde twin tests run
   under `--no-default-features --features std,aes-gcm`.
2. **Gate 5 — serde runtime path unbenched.** Add a name-decrypt /
   `OnceLock`-fill bench, or record in this checklist that the path reduces
   to the benched `mask!` decrypt plus a one-time cache fill (and cite the
   `mask!` bench as the evidence).
3. **Gate 2 — reclassify `into`/`from`/`try_from`/`getter`.** These
   delegate (de)serialization to a shadow type whose own derive owns the
   names, so masking cannot reach them from here — supporting them yields
   no masking benefit. Recommend moving them in SPEC §E.2.5/§E.3 from
   "deferred, tracked for later" to **out of scope** (permanently
   reject-loud), so "settled surface" has no implied future work.

The remaining deferred attributes — `flatten`, the enum representations
`tag`/`untagged`/`content`, explicit `borrow`, and variant `alias` — stay
reject-loud and are **not** promotion blockers: ADR-0002 gate 3 permits a
rejected row as long as the rejection is tested (it is).

## Deferred surface — post-stabilization roadmap

Feasibility triage of the attributes that stay reject-loud at
stabilization. None blocks promotion (ADR-0002 gate 3 permits tested
reject-loud rows); this is the backlog for _after_ `serde` lands.
Effort is relative; "masking value" is whether the attribute actually
moves schema vocabulary out of the binary (the whole point of the
feature).

### Low effort — completes existing parity

- **variant `alias`** — masking value: high (alias names are wire
  vocabulary). Field `alias` already works
  (`litmask/tests/mask_serde_alias.rs`) and the variant identifier
  visitor already matches against runtime-decrypted names (§E.2.6), so
  this is threading an alias list into the variant arm. The
  field-works/variant-doesn't asymmetry makes it the obvious first
  follow-up. Currently rejected via the catch-all
  (`serde_attrs.rs::unsupported`).

### Medium effort

- **`with`/`serialize_with`/`deserialize_with` on a generic type** —
  masking value: neutral (routes values through user fns; names still
  masked normally). Reject-loud today because the generated adapter is a
  local item that cannot name the surrounding impl's generic parameters
  (`serde_attrs.rs::reject_with_on_generic`, ~`:472`). Fix: emit the
  adapter so it carries the impl generics (or inline the call). Closes a
  documented limitation rather than adding new surface.
- **explicit `borrow`** — masking value: neutral (lifetime control).
  Implicit borrow for `&str`/`&[u8]`/`Option<…>` is already handled via
  the `'de: 'a` bound (§E.2.6); explicit `#[serde(borrow)]` is the
  less-common override. Moderate visitor/lifetime plumbing.

### High effort — separate projects

- **enum representations `tag` / `untagged` / `content`** — masking
  value: **high, strongest case in the backlog.** Internally/adjacently
  tagged enums put the _tag field name_ and every variant name on the
  wire as strings — exactly what the feature exists to mask. Cost is the
  blocker: serde's codegen leans on `serde::__private` (`Content`,
  `ContentDeserializer`, `TaggedContentVisitor`), which §E.2.6 forbids
  referencing, so a large slice of that machinery would have to be
  replicated against public API in `litmask::__serde_support`.
- **`flatten`** — masking value: moderate. Needs content-buffering plus a
  `FlatMapSerializer` equivalent, again replicated out of
  `serde::__private`. Additional snag: serde itself breaks `flatten` on
  non-self-describing formats (bincode/postcard), which collides with the
  §E.2.1 byte-identity contract for those formats — the supported scope
  would have to be carved carefully.

### Out of scope — not deferred (see Open item 3)

- **`into` / `from` / `try_from` / `getter`** — masking value: **none.**
  These delegate (de)serialization to a shadow type whose own derive owns
  the names; masking applied here cannot reach that type. Supporting them
  would add surface with zero masking benefit and could mislead. Keep
  permanently reject-loud.

## Promotion procedure

When gates 1–5 are all ✅:

1. Rename the feature `unstable-serde` → `serde` in `litmask/Cargo.toml`
   and `litmask-macros/Cargo.toml` (and the macro's internal feature
   reference).
2. Update gating in code (`#[cfg(feature = "unstable-serde")]` →
   `"serde"`), examples' `required-features`, and the scrub test's
   feature list.
3. Promote SPEC Appendix E from EXPERIMENTAL to stable; fold this matrix
   into the spec section per ADR-0002, or keep this file as the historical
   record and link it.
4. Note the rename as a breaking change in `docs/MIGRATION.md`.
5. Mark this checklist complete.
