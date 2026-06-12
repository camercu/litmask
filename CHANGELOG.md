## [0.11.0](https://github.com/camercu/litmask/compare/v0.10.0...v0.11.0) (2026-06-12)

### ⚠ BREAKING CHANGES

* **build:** LITMASK_MACHINE_ID must be a `litmask show-machine-id`
token (raw_id "." checksum); a bare id now aborts the build.
* **machine:** MachineIdProvider is no longer public. The machine tier
is reached only through the init!(machine_id) keyword form, which the
proc-macro cross-checks against the build's seal tier.
* **build:** a build with LITMASK_UNLOCK_KEY set now seals the
external tier and emits no litmask.config; previously the variable was
ignored and the embedded tier was always sealed.
* **provider:** KeyEncoding and FileProvider::with_encoding are
removed; FileProvider::new now treats file contents as raw material
rather than base64url-encoded text.
* **provider:** LITMASK_UNLOCK_KEY is interpreted as raw key material,
not a base64url-encoded 32-byte key. Deployers must supply the same
material fed to the build seal.
* **provider:** StaticProvider is removed; init!() now unlocks via
EmbeddedProvider, and derive_embedded_unlock_key takes an explicit
context argument.
* **keying:** unlock_key derivation changed; binaries built before
this change will not decrypt under the new Embedded-tier key.
* **wire:** wrapper wire format changed (old binaries/wrappers no
longer decrypt); litmask-cli bind and inspect subcommands removed;
InitError::UnsupportedCipher and litmask-internal scan/config locator
APIs removed; litmask.config drops the locator and length fields.
* HardwareIdProvider -> MachineIdProvider, feature
hw-id -> machine-id, CLI --hw-id -> --machine-id and show-hw-id ->
show-machine-id. The derivation context value "hw-v1" -> "machine-v1"
changes derive_machine_id_key output, so every machine-ID-bound binary
must be re-bound. External nouns (machine_uid crate, /etc/machine-id,
AES hardware acceleration) are unchanged.

* rename hardware-id concept to machine-id ([8538435](https://github.com/camercu/litmask/commit/85384357e9281ae63467fe5f8009920d81b5fe6a))

### Features

* **build:** presence-driven external sealing under LITMASK_UNLOCK_KEY ([4950040](https://github.com/camercu/litmask/commit/49500406b22226749ebbc58fc2d985bbfdc0c909))
* **build:** require self-checking token form for LITMASK_MACHINE_ID ([e1f96f7](https://github.com/camercu/litmask/commit/e1f96f77fe9a7df9166653ac7cb42fd2b08a2334))
* **build:** seal MachineExternal two-factor tier ([92c0474](https://github.com/camercu/litmask/commit/92c047450a144a18a15f8b05a657a0938314e02b))
* **build:** warn on Embedded floor in release builds ([c9180d0](https://github.com/camercu/litmask/commit/c9180d023fd7921b3aefc9765ca22c38a7215102))
* **cli:** add bind --hw-id for off-box (vendor-side) binding ([e7c332d](https://github.com/camercu/litmask/commit/e7c332dfc96a05b766de7d568d8f09ef14c3fc50))
* **cli:** add keygen and self-checking show-machine-id token ([bcf96cd](https://github.com/camercu/litmask/commit/bcf96cdb4728074cb494c28199639242141ca864))
* **cli:** add show-hw-id command and send bind errors to stderr ([3383369](https://github.com/camercu/litmask/commit/33833693f7c12faf3a530c6186c55d67686aee89))
* **init:** add init!(machine_id + provider) two-factor form ([ec28cc8](https://github.com/camercu/litmask/commit/ec28cc8f9f54546b43fe252ec1f0b632aab2bb71))
* **internal:** add external-tier unlock-key derivation ([792101a](https://github.com/camercu/litmask/commit/792101ab2c44c954561d01b54ccdbf4034ce14c9))
* **internal:** add self-checking machine-id token codec ([573ad0e](https://github.com/camercu/litmask/commit/573ad0ee250853828e4503bf86095171df1c79e4))
* **internal:** add strip_trailing_newline for external material ([e757c87](https://github.com/camercu/litmask/commit/e757c87f969f84d4627b53d2e266463565b3c8ef))
* **internal:** add two-factor unlock-key composition KDF ([c54da46](https://github.com/camercu/litmask/commit/c54da46273ecd29b47720951bfe555076724cfef))
* **key:** add public UnlockKey::derive for external material ([5a24e73](https://github.com/camercu/litmask/commit/5a24e735375879b09db74405e3c755894222545e))
* **key:** add UnlockKey::compose for two-factor keying ([4466002](https://github.com/camercu/litmask/commit/446600271c57880b5d82919d82f10ad88f649673))
* **keying:** embedded nonce-derived unlock_key + seal-tier tag ([f4a0918](https://github.com/camercu/litmask/commit/f4a091852d59f6dd2aa64ba944911728fc8bc340))
* **machine:** add machine-id seal tier via init!(machine_id) ([eea8e35](https://github.com/camercu/litmask/commit/eea8e351b29f697303385928de4a7aa4c602dc02))
* **macros:** add init!(<provider>) external form with tier cross-check ([6548f63](https://github.com/camercu/litmask/commit/6548f6300cc40ac3dd870a73ad733342ccc169a0))
* **macros:** convert init! to proc-macro with form↔tier cross-check ([2ee89cf](https://github.com/camercu/litmask/commit/2ee89cf942d21242365d207c750e8a469c5b9d08))
* **provider:** env provider derives unlock_key from raw material ([038e5fc](https://github.com/camercu/litmask/commit/038e5fc788db74f1cc869baeebfab61edcfcb403))
* **provider:** file provider derives unlock_key from raw material ([842c6e0](https://github.com/camercu/litmask/commit/842c6e00834dec0999b69623e8b5369197f6f102))
* **provider:** make EmbeddedProvider the keyless default unlock path ([fdaf9ba](https://github.com/camercu/litmask/commit/fdaf9bae50cd7f0c0a2ca3658bda2bb5fef57b46))
* **runtime:** gate lazy init on the build-sealed tier ([e6d2895](https://github.com/camercu/litmask/commit/e6d28954e91abeefd791cd471d24ace774d78303))
* **runtime:** profile-split failure diagnostics ([b926758](https://github.com/camercu/litmask/commit/b926758934689466665bef863b6d947c0126cca2))
* **wire:** build-sealed wrapper format, drop locator + CLI bind/inspect ([b8bbeb9](https://github.com/camercu/litmask/commit/b8bbeb91b5537be666c22c1d7eaf5c5caa58e9c5))

### Bug Fixes

* **ci:** drop removed locator_scan fuzz target ([b573c53](https://github.com/camercu/litmask/commit/b573c53830a0506e179c1a90e8e39e34508a412b))
* **ci:** isolate per-example seal env, exclude machine example from coverage ([55231cf](https://github.com/camercu/litmask/commit/55231cf7dbf19a0b175df540dfedcaaa0375e28e))
* **ci:** seal machine tier for scrub-hardened example build ([b6a2661](https://github.com/camercu/litmask/commit/b6a26610119446f7864d214cc1b99f7f82f2397a))
* **cli:** inherit litmask-internal dep from workspace ([f350462](https://github.com/camercu/litmask/commit/f3504622b83e1e716d1693d0dd132f45bbffe73a))
* **machine:** strip trailing newline from build-time machine id ([45b83ae](https://github.com/camercu/litmask/commit/45b83aeddb9048d6de92c2b37a7061c7c0eb8744))
* **macros:** guide init!(machine_id) built without the machine-id feature ([8859e75](https://github.com/camercu/litmask/commit/8859e759da0d502411cd2af1582fa9bf9ef4a6cc))
* **macros:** require lone `+` for two-factor init! form ([794251d](https://github.com/camercu/litmask/commit/794251dd1f7417e38f488139f7416ac37e28e4c4))
* **test:** match compile-fixture stderr to no-rust-src toolchain ([8299586](https://github.com/camercu/litmask/commit/8299586b43a9f7d348de1a69a3f06808f1b4b799))

## [0.10.0](https://github.com/camercu/litmask/compare/v0.9.0...v0.10.0) (2026-05-30)

### ⚠ BREAKING CHANGES

* **macros:** empty mask_concat!, include path resolution, mask_file
output, and the env error formats change observable behavior.
* **internal:** alters derive_hw_key output. Binaries already bound by
litmask-cli must be re-bound with a matching cli version; the cli and
the embedded runtime are versioned in lockstep.
* **internal:** `litmask_internal::cipher` is now `litmask_internal::decrypt`.

- Rename cipher.rs → decrypt.rs to reflect its actual content
  (decrypt-only helpers, not cipher selection/dispatch).
- Replace `pub use mod::*` glob re-exports with explicit item lists
  so the crate's public API surface is self-documenting.
- Add feature-mapping comment to aead.rs import block clarifying
  which features pull which backends.
- Update all downstream references (litmask runtime, litmask-build).

* **internal:** rename cipher module to decrypt, replace glob re-exports ([9a13575](https://github.com/camercu/litmask/commit/9a135756efb2783063661d67b4b122a78229b0aa))
* **internal:** widen hw-key length prefix to u64 ([ee2fe4e](https://github.com/camercu/litmask/commit/ee2fe4e85d947b7112bf51b9fedcfe0688a94b40))

### Features

* **macros:** make mask_* macros drop-in parity with stdlib ([7491b22](https://github.com/camercu/litmask/commit/7491b22e494109ae5b37853984e0b4391565d3b5))

### Bug Fixes

* **cli:** escape WindowsCommitFs doc link unresolvable on non-Windows ([968baad](https://github.com/camercu/litmask/commit/968baad3b43279adc7c5443daaf209a32595b5b4))
* **cli:** zeroize mask_key decrypt result and redact Debug output ([afa2e45](https://github.com/camercu/litmask/commit/afa2e45cf2475b492663ee4d5ca432058ed92ad5))
* **internal:** distinguish payload-length from authentication error ([9c0efa4](https://github.com/camercu/litmask/commit/9c0efa4bbd3636d3e8a9f7f1c43f4dbfc1d00bf8))

### Performance Improvements

* **ci:** merge coverage into test pass and background it ([1d935a1](https://github.com/camercu/litmask/commit/1d935a12c867c3a3fda59c6bbc2fc3fadff66306))

## [0.9.0](https://github.com/camercu/litmask/compare/v0.8.0...v0.9.0) (2026-05-29)

### ⚠ BREAKING CHANGES

* **crypto:** derive_hw_key output changes for all inputs. No
deployed binaries exist yet so no migration needed.
* **bind:** LocateOutcome::Single/Multiple renamed to
Found/Ambiguous (internal crate, not public API).
* **cli:** the installed binary is now `litmask` instead of
`litmask-cli`. Users need `litmask bind` / `litmask inspect` in
scripts and CI. The crate name remains `litmask-cli` for cargo.

### Features

* add mask_print!, mask_println!, mask_write!, mask_writeln! macros ([4f43a45](https://github.com/camercu/litmask/commit/4f43a4527762a6b387686a684634bb816c440364))
* **cli:** rename binary from litmask-cli to litmask ([43f6f11](https://github.com/camercu/litmask/commit/43f6f11f567eb1172c61f620dbe150dcfdc7ee4c))
* extend weak_mask! to accept b"..." and c"..." literals ([6c14241](https://github.com/camercu/litmask/commit/6c1424156ad732b068a1dfb2b86be95c828cd1df))
* **internal:** add all-ciphers feature for dual-cipher builds ([7770da6](https://github.com/camercu/litmask/commit/7770da66b7decbd54e4cbc030e59996c1b578176))
* **key:** add constant-time PartialEq/Eq to UnlockKey ([b729828](https://github.com/camercu/litmask/commit/b729828b83a918eb04e03799982372cc6121800e))
* **provider:** add Debug impl to all provider types ([8f8b69c](https://github.com/camercu/litmask/commit/8f8b69c892d1dff4d61d470e280fe45dba52ee31))

### Bug Fixes

* **bind:** handle identical wrapper duplicates from include_bytes ([053f64b](https://github.com/camercu/litmask/commit/053f64b0fb32f19decca7b94c91c0bf82cf6425c))
* **ci:** build hello_world example in Windows smoke job ([86ea2b4](https://github.com/camercu/litmask/commit/86ea2b4abcde5d406b8d4a32254a73a9cce7ba49))
* **ci:** scope push trigger to main, fix POSIX boolean check ([1ce0d48](https://github.com/camercu/litmask/commit/1ce0d4838b6a88c9fa83d728e72d6198c9d179d5))
* **cli:** preserve file permissions during bind commit ([d2c9364](https://github.com/camercu/litmask/commit/d2c93643b1f71c60b7d545422266778af6bdcacc))
* **cli:** suppress cast_possible_truncation lint in test ([b0833a3](https://github.com/camercu/litmask/commit/b0833a325f9d8bf87f46f941efdad3d8637e0690))
* **cli:** use temp+rename for binary write in bind commit protocol ([b49585f](https://github.com/camercu/litmask/commit/b49585f6d7a133e4bd37df88d9a66bb7d7e804f6))
* **cli:** zeroize derived unlock_key and clean up orphaned tempfiles in bind ([94bb171](https://github.com/camercu/litmask/commit/94bb171279bc20c7f415d8aa9a9d3ca4223a89df))
* **crypto:** rewrite derive_hw_key as single-step BLAKE3 with length prefix ([ccc7d16](https://github.com/camercu/litmask/commit/ccc7d163c22227cb378f0f0ac104ddacdb66c666))
* **fuzz:** update locator_scan target for renamed LocateOutcome variants ([34f9c7d](https://github.com/camercu/litmask/commit/34f9c7dbd77fff67fe858eaf80487d40d60a3686))
* **macros:** emit no_std-safe paths from mask_format! ([21a5e1f](https://github.com/camercu/litmask/commit/21a5e1f9ab0e44f021c19b30f9943b9e2ddc1d66))
* **runtime:** replace bare unwrap in __weak_decode with non-identifying panic ([2925046](https://github.com/camercu/litmask/commit/292504653287eb34bd80863407cdcea54a345a15))
* scan doc accuracy, AGENTS key source, macros default-features ([da7ffd9](https://github.com/camercu/litmask/commit/da7ffd96b62f40e928fac8116a098d488f008d7a))
* **smoke:** fail early when target binary is missing ([e6d986c](https://github.com/camercu/litmask/commit/e6d986cce7215e276e3f4173c0b022ddc47d256a))
* **weak-mask:** derive XOR key from nonce rotation + BLAKE3 keyed hash ([37780fe](https://github.com/camercu/litmask/commit/37780fef03927b57a3e3ae3c1b6fab5b1dc52b72))

### Performance Improvements

* **ci:** drop redundant test-all-features and test-hw-id from CI gate ([c159afe](https://github.com/camercu/litmask/commit/c159afe441af91a6a6b1efab22d07931129a6e88))

## [0.8.0](https://github.com/camercu/litmask/compare/v0.7.0...v0.8.0) (2026-05-27)

### ⚠ BREAKING CHANGES

* **cli:** none — internal-only code path, no public API change.
* **cli:** execute() now takes &dyn CommitFs parameter.
* **internal:** none

* **cli:** extract CommitFs trait from execute() for platform testability ([d5e84a2](https://github.com/camercu/litmask/commit/d5e84a244f9a847d3c3c9c4cb3deaf1624e77595))

### Features

* **ci:** add cargo-semver-checks tooling end-to-end ([9251c9a](https://github.com/camercu/litmask/commit/9251c9a58ad8878dc2a4f30f8778beaab7ee59f8))
* **ci:** add cross-compile targets and check-cross recipe ([732329a](https://github.com/camercu/litmask/commit/732329aabb44c427670147f73c2f95efbb052201))
* **ci:** add fuzz job and justfile recipe ([0de1f23](https://github.com/camercu/litmask/commit/0de1f235792519d6846a1e7a9ac40498da625304))
* **ci:** add test-aes-gcm feature-matrix recipe ([0d56cd3](https://github.com/camercu/litmask/commit/0d56cd34c5f9d89abdfb26b2c762421baa97b3a5))
* **ci:** add test-hw-id feature-matrix recipe ([4be3164](https://github.com/camercu/litmask/commit/4be316415a62d98316ff27fdec3d4d65f8d40b04))
* **ci:** add test-no-default feature-matrix recipe ([312e0ac](https://github.com/camercu/litmask/commit/312e0ac5451ce611eee7ea8d7e67440a00da8a2f))
* **cli:** add Windows atomic commit via MoveFileExW + CI job ([834415f](https://github.com/camercu/litmask/commit/834415fad7121d5579676b9de9e540c0f95f4df0))
* **coverage:** add cargo-llvm-cov tooling end-to-end ([f284e5a](https://github.com/camercu/litmask/commit/f284e5a5f785d97bb5cc4d75a08e59fa07353f61))
* **fuzz:** add locator_scan fuzz target ([0efad23](https://github.com/camercu/litmask/commit/0efad2341408419c0a4458ddf1f154f32817ee66))
* **fuzz:** add parse_format_template fuzz target ([2ed8d4c](https://github.com/camercu/litmask/commit/2ed8d4c28f99a1bbe2f43d27c9c8a6ffa2894b5c))

### Bug Fixes

* **ci:** force gnu target for fuzz jobs to avoid ASAN/musl conflict ([abb551d](https://github.com/camercu/litmask/commit/abb551d95eae75afbfb87077b6efbdbd1fd195e7))
* **ci:** pin rust-cache workspace to prevent trybuild target discovery ([a5cc53a](https://github.com/camercu/litmask/commit/a5cc53a05b612a1f9fac1777b841ed4f733878a0))
* **cli:** open sync_file handle with write access for Windows ([f22a98d](https://github.com/camercu/litmask/commit/f22a98d8a087555e4d118aac0d7343fe8c8f4501))
* **deps:** enable blake3 pure feature to fix cross-compilation ([94f166f](https://github.com/camercu/litmask/commit/94f166f56c2888c5b9abd697f4989f491a48d213))
* **docs:** replace broken `init!` intra-doc link with plain code span ([6606f72](https://github.com/camercu/litmask/commit/6606f72dfcfee59af2e8a070e836195c51e40985))
* **internal:** blob test helpers use CURRENT_CIPHER for dual-cipher compat ([65e0387](https://github.com/camercu/litmask/commit/65e03874bd0d1321340e4cec736cee556831348c))
* **lint:** add must_use, errors doc, and panics suppression to extracted fns ([ab9bd80](https://github.com/camercu/litmask/commit/ab9bd803b4e615c397cc19fc731e516e11415ddd))
* **parser:** return error on overflowing positional index instead of panicking ([603636f](https://github.com/camercu/litmask/commit/603636f57bbc699bb4c5f0bcc80446cb0b448644))
* **setup:** regenerate rust-toolchain.toml with llvm-tools + targets ([2fe803e](https://github.com/camercu/litmask/commit/2fe803ea76e011220762c140d74deeddc755aaea))
* **test:** allowlist doc-example expect() in tamper_panic scan ([12cc426](https://github.com/camercu/litmask/commit/12cc42634f80fd7bd7eff8dcecd80516e0071b92))

## [0.7.0](https://github.com/camercu/litmask/compare/v0.6.0...v0.7.0) (2026-05-25)

### ⚠ BREAKING CHANGES

* **hw-id:** every binary previously bound with `litmask-cli
bind` under the old context fails to decrypt under the new one.
`HW_ID_DERIVATION_CONTEXT` must change in lockstep on bind and
runtime — re-bind every shipped binary.

The old context, `"litmask 2026-05-20 HardwareIdProvider
derivation"` (49 chars), was three layers of leak baked into every
`HardwareIdProvider` user binary's `.rodata`:

- the literal `"litmask"` (library identifier)
- a date stamp (`2026-05-20`) that pinned the constant to a moment
  in history without serving uniqueness
- the Rust type name (`HardwareIdProvider derivation")

Shrink to `"hw-v1"` (5 chars, no library identifier). The `-v1`
suffix reserves a rotation path if a future security review
invalidates the current derivation. Workspace-internal global
uniqueness in BLAKE3's `derive_key` namespace is satisfied — this
is the only `derive_key` call in the workspace.

Also shrink the two non-leaking nonce personalization strings:
`NONCE_TAG_WRAPPER` → `b"wrapper"`,
`NONCE_TAG_CALL_SITE` → `b"call-site"`. These are
`blake3::keyed_hash` / `Hasher::new_keyed` data inputs, not
`derive_key` contexts, and `nonce_for_wrapper` /
`nonce_for_call_site` are called only at build-script /
proc-macro time — they don't reach user binaries either way. The
shrink keeps them readable for code review without spending bytes
on a `litmask-` prefix that had no security role.

Route the runtime `HardwareIdProvider` BLAKE3 context through
`weak_mask!("hw-v1")` so the literal is obfuscated in user
binaries — the runtime is the only consumer that ships in user
binaries; `litmask-cli bind` (the other consumer) uses the
canonical `HW_ID_DERIVATION_CONTEXT` directly. Pin the
literal-vs-const drift via a unit test
(`weak_mask_literal_matches_const`) so bind ↔ runtime can't
silently desync.

`derive_hw_key` now takes the context as a parameter — the
runtime call site supplies the `weak_mask!`-decoded form; tests
supply `HW_ID_DERIVATION_CONTEXT` directly so the test path
doesn't depend on `weak_mask!`'s wrapper-XOR machinery.

Make `hw-id = ["std", "dep:machine-uid"]` explicit. `std` is
load-bearing because `machine-uid` requires it for filesystem
identity probes; the prior `hw-id = ["dep:machine-uid"]` was a
feature combination that compiled half the time.

### Features

* **hw-id:** shrink BLAKE3 context + weak_mask runtime literal ([9e97f55](https://github.com/camercu/litmask/commit/9e97f55657c50345114a89dadbb48f26276d1765))

## [0.6.0](https://github.com/camercu/litmask/compare/v0.5.0...v0.6.0) (2026-05-25)

### Features

* **cli:** implement litmask-cli bind POSIX atomic commit ([50f6b35](https://github.com/camercu/litmask/commit/50f6b356a038a2c0631f75f6cbeacddeb8a4b144))
* **cli:** implement litmask-cli inspect subcommand ([c99c6ee](https://github.com/camercu/litmask/commit/c99c6ee691b0f1f2e31aaf23a4ee419859dd4a82))
* **error:** add InitError::sysexit_code() per §1.9.7 ([807d1d3](https://github.com/camercu/litmask/commit/807d1d328a203f143af92707df82abc3bac45756))
* **error:** add UnsupportedFormat / UnsupportedCipher InitError variants ([40b662a](https://github.com/camercu/litmask/commit/40b662a44c7c9e28df640ad9063a47e0f951ebe3))
* **internal:** add AES-256-GCM cipher feature ([1786962](https://github.com/camercu/litmask/commit/178696265e25d94296241b7afaf26ed1f683b69f))
* **macros:** add #[mask_all(strict)] mode + non-literal-template warning ([da76356](https://github.com/camercu/litmask/commit/da7635615db535cac37e57662d95ecec6eac8f3d))
* **provider:** add FileProvider with base64url + Raw encodings ([268ea12](https://github.com/camercu/litmask/commit/268ea12e35d0a9dad9f33b94fb6876cf2b39913f))
* **provider:** add HardwareIdProvider behind hw-id feature ([01c28cb](https://github.com/camercu/litmask/commit/01c28cb7dc57ed93e15e3ad047baad53914088e2))
* **provider:** add StaticProvider tests-only key holder ([5809f64](https://github.com/camercu/litmask/commit/5809f64e1bfffc3edd0a1d5a0391eaf5ecbaa5cb))

### Bug Fixes

* **cli:** unreachable!() on bind locator slice fallback ([0c46395](https://github.com/camercu/litmask/commit/0c463958e418b52c5d18c558fe78c245a26f0851))
* **docs:** unbreak StaticProvider intra-doc link under default features ([0c61b24](https://github.com/camercu/litmask/commit/0c61b24a0889a0b383ba60842e14a7d223cf0cc0))
* **error:** align Decryption Display tag with §1.9.3 ([327dff0](https://github.com/camercu/litmask/commit/327dff0ddb031955d70a165284ff0e908d7e142f))
* **internal,cli:** panic on unreachable cipher-dispatch arms ([8a4a263](https://github.com/camercu/litmask/commit/8a4a2631c1bae07b0d427cee69f6d96081f528ba))
* **macros:** restore at <file>:<line> in mask_all skip diagnostics per §2.3.1.4 ([1fb48b1](https://github.com/camercu/litmask/commit/1fb48b18898466717e2e4bcc156bdedd14b212e0))

## [0.5.0](https://github.com/camercu/litmask/compare/v0.4.0...v0.5.0) (2026-05-20)

### ⚠ BREAKING CHANGES

* **macros:** pre-1.0. The mask_env! custom-message form
(mask_env!("X", "my message")) now emits 'mask_env! unset: my message'
rather than the bare custom message. Downstream consumers that
matched the exact prior wording must update. The macro-name prefix
and the closed-set tag are §1.9.6-mandated as of Amendment 2026-05-20.
* **spec:** pre-1.0 spec change. Implementations that previously
matched on the §1.9.6 exact substrings should switch to matching the
macro-name + tag pattern. The current implementation's strings already
conform; no user-visible behavior change ships with this commit.
* **macros:** public macro mask_fmt! is renamed to mask_format!.
Downstream callers must search-and-replace mask_fmt! -> mask_format!.
The error-message substring 'mask_fmt!' is also renamed; users
matching the prior text must update their checks.
* **macros:** for any out-of-tree user of `mask!(include_str!(...))`
or `mask!(concat!(...))`. Documented in Task 13A's breaking-change
list. 168/168 tests pass after the migration; clippy + fmt green.

* **macros:** remove mask!(include_str/concat) shim from mask.rs ([fcc4fdf](https://github.com/camercu/litmask/commit/fcc4fdf1c14a89c4f37ae4f452a7643ffd19cd50))
* **macros:** rename mask_fmt! to mask_format! ([1c11144](https://github.com/camercu/litmask/commit/1c11144236cf05b401343db745fa5bc4c196b9e3))
* **macros:** route every compile error through common::compile_error ([d68213e](https://github.com/camercu/litmask/commit/d68213ef66bf9b1bf85129570028606d73ff8789))
* **spec:** relax §1.9.6 to macro-name + closed tag set ([3875af9](https://github.com/camercu/litmask/commit/3875af937eae1bbe439ab86b687da4f7bcf6a2de))

### Features

* add debug_assert! at type-uncovered invariant points ([c4309af](https://github.com/camercu/litmask/commit/c4309afa081e36d8505e9f2da97ad94f7b6274d7))
* **internal:** const-assert wire-format layout invariants ([a13eee8](https://github.com/camercu/litmask/commit/a13eee8bcd259ef804b3c2febefc2df075d669e0))
* **macros:** add mask_concat! macro ([57941b1](https://github.com/camercu/litmask/commit/57941b10e537e745451e4f51aa4b766ad07fa64a))
* **macros:** add mask_env! macro ([0132eed](https://github.com/camercu/litmask/commit/0132eed5b62f7aba4380a6eba815b3a9bdcfca88))
* **macros:** add mask_file! macro ([2b818c9](https://github.com/camercu/litmask/commit/2b818c9462c35570f9d9a72b1e1edee8003b18f4))
* **macros:** add mask_include_bytes! macro ([feb0aa8](https://github.com/camercu/litmask/commit/feb0aa80eeedff3acf239549307282b5fa50f7a8))
* **macros:** add mask_include_str! macro with trybuild + round-trip tests ([39ae545](https://github.com/camercu/litmask/commit/39ae5456328524361fb7622ef59d4e15112b77fa))
* **macros:** add mask_option_env! macro ([cc23226](https://github.com/camercu/litmask/commit/cc23226c50a2d20d5d6b7f4dcdf6ee8fb19bc82a))
* **macros:** canonicalize Span::file() against CARGO_MANIFEST_DIR ([7eb044f](https://github.com/camercu/litmask/commit/7eb044f481a4b12bfa2435d6bd3e254484e019c7))
* **macros:** expand mask_all macro coverage + harden walker internals ([a98a87f](https://github.com/camercu/litmask/commit/a98a87f56a57269bb0a32079e5645391952d86e3))
* **macros:** full macro substitution table + qualified paths ([cd22315](https://github.com/camercu/litmask/commit/cd22315067a7e411e501323700e12ef5f099e418))
* **macros:** mask_all rewrites format!(literal, ...) to maskfmt! ([2cef42d](https://github.com/camercu/litmask/commit/2cef42d9a2427deec05494e8fada5b8954208642))
* **macros:** mask_all rewrites panic-family macros ([4dcfa0c](https://github.com/camercu/litmask/commit/4dcfa0cc97dbcb1634549c1f45ae4bf7e77419f3))
* **macros:** mask_all rewrites println-family output macros ([8c52b3d](https://github.com/camercu/litmask/commit/8c52b3de63cadde431bdbde9a1e6cc140f23a7c8))
* **macros:** mask_all rewrites stdlib forms to dedicated mask_*! macros ([1be1cf0](https://github.com/camercu/litmask/commit/1be1cf0989256ff336997c8bd4dc180fed206f4b))
* **macros:** mask_all warns on user-defined macro literal args ([edeef57](https://github.com/camercu/litmask/commit/edeef57e392b31550e80c103cc8bf509874b00b8))
* **macros:** mask_all wraps include_str! and concat! in mask! ([06c6200](https://github.com/camercu/litmask/commit/06c6200e04865451e5ff46857e1f021edb83163a))
* **macros:** mask_concat! accepts every stdlib literal kind ([70f5aa1](https://github.com/camercu/litmask/commit/70f5aa190243591b20cca15a781d2cf8d9f860ab))
* **macros:** mask_env! accepts stdlib env!'s optional 2nd arg + NotUnicode ([cee9195](https://github.com/camercu/litmask/commit/cee91957744af8ef18fbca023699237bf4bca3dd)), closes [#11](https://github.com/camercu/litmask/issues/11)

### Bug Fixes

* **internal:** zeroize wrapper-decrypt intermediate plaintext ([e9dbc42](https://github.com/camercu/litmask/commit/e9dbc4241ecca473d1de7e8684eb217bc8777368))
* **macros:** reject invalid maskfmt placeholder names with typed error ([779f2fb](https://github.com/camercu/litmask/commit/779f2fb8fdee0abd84a3ac4df5d1fe9ac4fba535))
* **macros:** scope mask_all skip anchors per nested module ([860b396](https://github.com/camercu/litmask/commit/860b3966b4b24981b8ba7ce2978fa5c330527a21))
* **macros:** use macro@ disambiguator for mask_all rustdoc links ([09785e5](https://github.com/camercu/litmask/commit/09785e5cfb0a5ed027418a585aec2ad284936de4))

## [0.4.0](https://github.com/camercu/litmask/compare/v0.3.0...v0.4.0) (2026-05-17)

### Features

* **macros:** clearer error when mask_all is applied to non-module ([e6f77f6](https://github.com/camercu/litmask/commit/e6f77f622e2d10c9dd8b2ded71c68681766a8d50))
* **macros:** mask_all ghost-deprecation warnings per skip ([542420a](https://github.com/camercu/litmask/commit/542420afe712c488a6d0c2466f273ef37b6f5980)), closes [#5](https://github.com/camercu/litmask/issues/5)
* **macros:** mask_all skip rules — patterns + const/static ([8d946e7](https://github.com/camercu/litmask/commit/8d946e78a87eb940a705f53dd4c80addd2be5bcc))
* **macros:** mask_all walking skeleton ([fa19eed](https://github.com/camercu/litmask/commit/fa19eed6046049c233b1adf6a14e0a05b8a5ad33)), closes [#1](https://github.com/camercu/litmask/issues/1) [#4](https://github.com/camercu/litmask/issues/4) [#6](https://github.com/camercu/litmask/issues/6)

### Performance Improvements

* **macros:** drop two allocations in mask_all hot paths ([e8ed24c](https://github.com/camercu/litmask/commit/e8ed24c656da0f501633d9bc500dd5e7bb5d404b))

## [0.3.0](https://github.com/camercu/litmask/compare/v0.2.0...v0.3.0) (2026-05-17)

### Features

* **macros:** maskfmt! named args, implicit captures, dynamic width/precision ([1d24851](https://github.com/camercu/litmask/commit/1d248516220e7918e1b9063fac8a142b3a453e24))

### Bug Fixes

* **macros:** reject duplicate named args in maskfmt! ([9dac5dc](https://github.com/camercu/litmask/commit/9dac5dcde640e727c85bd301d8c97a8bc3a08e65))

### Performance Improvements

* **macros:** cache build_placeholder_emission + hoist out_ident ([0426acc](https://github.com/camercu/litmask/commit/0426acc395e40bd3d3dd6703e3eb10404206eb8a))
* **macros:** use bitmap for maskfmt unused-positional check ([2c9fdfa](https://github.com/camercu/litmask/commit/2c9fdfa336228a0e9cc48a3d2ee8e48aba5e3184))
* **test:** memoize build_example per (name, profile) ([23a5557](https://github.com/camercu/litmask/commit/23a5557b77f1108f7f12119e33bf0d4498a4b30e))

## [0.2.0](https://github.com/camercu/litmask/compare/v0.1.2...v0.2.0) (2026-05-17)


### Features

* **error:** add InitError::Decryption variant ([57130af](https://github.com/camercu/litmask/commit/57130af22d44c1ba2645a623aac385300d8be6c4))
* **internal:** mark FormatVersion + CipherId as non_exhaustive ([8e6639d](https://github.com/camercu/litmask/commit/8e6639d6a7cd5e48d0aaf2627317793e0063e572))
* **macros:** add maskfmt! for masked format-string templates ([1377a63](https://github.com/camercu/litmask/commit/1377a6382ea4f2293c44e4418e1ff19b30da0484))
* **macros:** add unmasked! identity macro ([7d84f7e](https://github.com/camercu/litmask/commit/7d84f7e89eb069fd54e0b9b16c9dee30cd3b9694))
* **macros:** clearer no_std error for mask!(c"...") ([ed3d65a](https://github.com/camercu/litmask/commit/ed3d65a43ec0c9c37e083920b152fc1a6827b77b))
* **macros:** mask! input grammar — invalid rejection + include_str!/concat! whitelist ([12bb8b8](https://github.com/camercu/litmask/commit/12bb8b8d328a37b83eab826f209aad993d48d3cf))
* **macros:** support b"..." and c"..." literals in mask! ([156a632](https://github.com/camercu/litmask/commit/156a63255acd42f3dfc31b7f89c698217f981c84))
* **runtime:** route wrapper AEAD failure to InitError::Decryption ([c4a2a12](https://github.com/camercu/litmask/commit/c4a2a127d991b26487acb32cf4749b87795a0c45))


### Bug Fixes

* **build:** honor LITMASK_RNG_SEED + profile-aware seed sourcing ([a6bbbfe](https://github.com/camercu/litmask/commit/a6bbbfe654c13f88ead4578e4ae022e60d76e298))
* **runtime:** gate decrypt_wrapper_or_panic on std feature ([206fdb7](https://github.com/camercu/litmask/commit/206fdb7e33e2af7e3a68afd739fb1b080a85f609))
* **tests:** correct misspelling of vermilion fixture marker ([88270cd](https://github.com/camercu/litmask/commit/88270cdae0f61cc35587c022afc3580c8e0e3730))


### Reverts

* **ci:** restore semantic-release-cargo in place of release-plz ([d4a5eb7](https://github.com/camercu/litmask/commit/d4a5eb79781ad90ff05d53e5b5f7c80111c1d605))

## [0.1.2](https://github.com/camercu/litmask/compare/v0.1.1...v0.1.2) (2026-05-13)


### Bug Fixes

* **ci:** disable @semantic-release/github issue/PR comment hooks ([a6653c2](https://github.com/camercu/litmask/commit/a6653c235dd559178fff208caf322c8bdb1e7fe5))

## [0.1.1](https://github.com/camercu/litmask/compare/v0.1.0...v0.1.1) (2026-05-13)


### Bug Fixes

* **ci:** centralize inter-crate deps in [workspace.dependencies] ([f803e0a](https://github.com/camercu/litmask/commit/f803e0a928f21d247de8c63902a3b92ce716c908))
