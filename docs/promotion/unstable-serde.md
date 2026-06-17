# Promotion checklist — `unstable-serde` → `serde`

**Status: COMPLETED (2026-06-17).** All gates green; the feature was
renamed `unstable-serde` → `serde` and SPEC Appendix E promoted to
STABLE. This file is retained as the historical promotion record.

Tracks `unstable-serde` against the shared bar in
[ADR-0002](../adr/0002-experimental-feature-promotion.md). The promotion
renamed the feature `unstable-serde` → `serde` (a breaking change by
design, MINOR pre-1.0). The normative surface lives in SPEC Appendix E;
this file is the exit checklist and cites the evidence for each gate.

Every claim names a test or `file:line` so it can be re-verified (project
doc doctrine: decisions cite checkable evidence, no unfalsifiable "the
tests cover it"). Paths are relative to the repo root.

## Generic gates (ADR-0002)

| # | Gate | Status | Evidence |
|---|---|---|---|
| 1 | Real-world validation (genuine consumer or realistic e2e, not unit tests alone) | ✅ | `litmask/examples/mask_serde_demo.rs` is built and its compiled binary scrubbed end-to-end by `litmask/tests/example_scrub.rs::mask_serde_demo_names_and_fixtures_absent_from_binary` |
| 2 | Settled surface (derive names, attributes, generated items final) | ✅ | Names `MaskSerialize` / `MaskDeserialize` final; subset in Appendix E §E.2.5 landed; `into`/`from`/`try_from`/`getter` reclassified out of scope in §E.3, pinned by `serde_attrs.rs::out_of_scope_*` tests — no implied future work remains |
| 3 | Support matrix complete (every advertised row tested; every unsupported input explicitly rejected + that rejection tested) | ✅ | See [Support matrix](#support-matrix) below — all supported rows have twin-tests, all rejected rows have trybuild cases |
| 4 | Honest, reviewed security model (understated guarantees, residuals named, no self-describing-lie surface) | ✅ | Residuals enumerated in SPEC §E.3 (plain-derive re-embed, self-describing-format runtime print, serde-internal strings); threat model §1.1; at-rest-only scope stated §E.2.3 |
| 5 | Full build/feature matrix (both ciphers; claimed std/no_std; ecosystem interop; binary scrub; new runtime paths benched) | ✅ | All sub-items below green |

### Gate 5 detail

| Sub-item | Status | Evidence / gap |
|---|---|---|
| `chacha20-poly1305` (default) | ✅ | Serde tests run under `--all-features` (`justfile:122` `test-all-features`); chacha wins whenever enabled (`litmask-internal/src/aead.rs:33`), so this is the cipher actually exercised |
| `aes-gcm` | ✅ | `test-aes-gcm` (`justfile`) now folds in `unstable-serde`, running the serde twin tests under `--no-default-features --features std,aes-gcm` (106 serde tests green). The masked-name blob is cipher-specific, so this is a distinct decrypt path from chacha |
| `std` claimed; `no_std` not claimed | ✅ | §E.2.3 requires `std` (names leaked into `OnceLock<&'static str>`); no no_std obligation to test |
| Ecosystem interop | ✅ | Wire/behavior identity pinned against real serde + `serde_json` twins across the matrix (e.g. `litmask/tests/mask_serde_rename.rs`); §E.2.1 documents the non-self-describing-format (bincode/postcard) shape contract |
| Binary scrub proves the property | ✅ | `litmask/tests/example_scrub.rs::mask_serde_demo_names_and_fixtures_absent_from_binary` |
| New runtime path benched | ✅ | The serde path adds no novel crypto cost: each name is decrypted once via the same per-blob AEAD-open as `mask!` (benched `decrypt_masked`, cold path `first_use_unlock` in `benches/litmask-bench/benches/decrypt.rs`), then cached in a `OnceLock<&'static str>` (§E.2.3) — so steady-state (de)serialization is an atomic load with zero crypto. No dedicated bench: it would only re-measure those primitives |

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
| `alias` (field, variant) | supported | `litmask/tests/mask_serde_alias.rs` (variant: `variant_alias_accepts_each_name`) |
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
| Any other unsupported key (`getter`/`into`/`from`/`try_from`/explicit `borrow`) | rejected (`invalid-arg`) | `serde_attrs.rs::unsupported` + unit `unsupported_key_is_reject_loud` |

## Open items blocking promotion

All three resolved — gates 1–5 are green. Promotion (the
`unstable-serde` → `serde` rename) is unblocked; see
[Promotion procedure](#promotion-procedure-completed).

1. ~~**Gate 5 — aes-gcm × serde untested.**~~ Done: `test-aes-gcm` now
   folds in `unstable-serde` (`justfile`), so the serde twin tests run
   under `--no-default-features --features std,aes-gcm`.
2. ~~**Gate 5 — serde runtime path unbenched.**~~ Resolved by reduction:
   the path is `mask!`'s benched per-blob decrypt for the one-time
   per-name fill, then a `OnceLock` atomic load steady-state. A dedicated
   bench would only re-measure those primitives, so none was added (see
   the gate-5 bench row for the cited evidence).
3. ~~**Gate 2 — reclassify `into`/`from`/`try_from`/`getter`.**~~ Done:
   SPEC §E.3 now marks them out of scope (not deferred), and
   `serde_attrs.rs::out_of_scope_container_keys_are_reject_loud` /
   `out_of_scope_getter_field_key_is_reject_loud` pin the permanent
   rejection.

The remaining deferred attributes — `flatten`, the enum representations
`tag`/`untagged`/`content`, and explicit `borrow` — stay
reject-loud and are **not** promotion blockers: ADR-0002 gate 3 permits a
rejected row as long as the rejection is tested (it is).

## Deferred surface — post-stabilization roadmap

Feasibility triage of the attributes that stay reject-loud at
stabilization. None blocks promotion (ADR-0002 gate 3 permits tested
reject-loud rows); this is the backlog for _after_ `serde` lands.
Effort is relative; "masking value" is whether the attribute actually
moves schema vocabulary out of the binary (the whole point of the
feature).

### Done — landed post-stabilization

- **variant `alias`** — masking value: high (alias names are wire
  vocabulary). Implemented by threading a variant-keyed `AliasMatch`
  (`mask_deserialize.rs::variant_aliases`) into the enum-level
  identifier visitor, reusing the field-alias machinery. Twins:
  `litmask/tests/mask_serde_alias.rs::variant_alias_*`.

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

  **Spike 2a landed (parser seam).** The container parser now folds
  `tag`/`content`/`untagged` into a `serde_attrs::Tagging` model
  (`External`/`Internal`/`Adjacent`/`Untagged`); codegen reject-louds any
  non-`External` form through the single guard
  `ContainerAttrs::reject_unsupported_tagging`, called at both derive
  entry points (`mask_serialize.rs` `try_expand`, `mask_deserialize.rs`
  `deserialize_body`). That guard is the seam the codegen slices replace.
  Sizing of the remaining work (the `__serde_support` surface to
  replicate against public serde API, smallest subset that passes the
  twins):
  - **`Content`** — an owned enum buffering one deserialized value
    (`Bool`/`U*`/`I*`/`F*`/`Str`/`Bytes`/`None`/`Some`/`Unit`/`Newtype`/`Seq`/`Map`),
    built by a `ContentVisitor`. Needed by all three reprs to peek the
    tag/variant before committing to a variant.
  - **`ContentDeserializer`** — a `Deserializer` replaying a buffered
    `Content` into the chosen variant's `Deserialize`. The bulk of the
    code (every `deserialize_*` forward + `EnumAccess`/`VariantAccess`).
  - **`TaggedContentVisitor`** — splits a map into `(tag, rest)` for
    internally/adjacently tagged; the tag key compares against the
    runtime-decrypted tag name (not a cleartext literal), the masking
    point.
  - **untagged** reduces to: buffer `Content`, then try each variant's
    `Deserialize` over a `ContentRefDeserializer` until one succeeds.
  No twin file is added yet (a `#[serde(tag=...)]` `MaskDeserialize` can't
  compile while the guard rejects); the trybuild reject cases
  (`compile/mask_*_serde_attr_container.rs`) remain the pinned contract.
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

## Promotion procedure (completed)

1. ✅ Renamed the feature `unstable-serde` → `serde` in
   `litmask/Cargo.toml` and `litmask-macros/Cargo.toml`.
2. ✅ Updated gating in code (`#[cfg(feature = "serde")]`), examples'
   `required-features`, the scrub test's feature list, and the
   `test-aes-gcm` lane.
3. ✅ Promoted SPEC Appendix E from EXPERIMENTAL to STABLE; this file is
   kept as the historical record.
4. ✅ Noted the rename as a breaking change in `docs/MIGRATION.md`.
5. ✅ Marked this checklist complete (status banner at top).
