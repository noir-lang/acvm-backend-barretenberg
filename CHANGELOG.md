# Changelog

## [0.2.0](https://github.com/noir-lang/acvm-backend-barretenberg/compare/v0.1.2...v0.2.0) (2023-05-22)


### ⚠ BREAKING CHANGES

* Update to acvm 0.12.0 ([#165](https://github.com/noir-lang/acvm-backend-barretenberg/issues/165))
* Add serialization logic for RAM and ROM opcodes ([#153](https://github.com/noir-lang/acvm-backend-barretenberg/issues/153))

### Features

* Add serde to `ConstraintSystem` types ([#196](https://github.com/noir-lang/acvm-backend-barretenberg/issues/196)) ([4c04a79](https://github.com/noir-lang/acvm-backend-barretenberg/commit/4c04a79e6d2b0115f3b4526c60f9f7dae8b464ae))
* Add serialization logic for RAM and ROM opcodes ([#153](https://github.com/noir-lang/acvm-backend-barretenberg/issues/153)) ([3d3847d](https://github.com/noir-lang/acvm-backend-barretenberg/commit/3d3847de70e74a8f65c64e165ad15ae3d31f5350))
* Update to acvm 0.12.0 ([#165](https://github.com/noir-lang/acvm-backend-barretenberg/issues/165)) ([d613c79](https://github.com/noir-lang/acvm-backend-barretenberg/commit/d613c79584a599f4adbd11d2ce3b61403c185b73))

## [0.1.2](https://github.com/noir-lang/acvm-backend-barretenberg/compare/v0.1.1...v0.1.2) (2023-05-11)


### Bug Fixes

* Remove star dependencies to allow publishing ([#182](https://github.com/noir-lang/acvm-backend-barretenberg/issues/182)) ([1727a79](https://github.com/noir-lang/acvm-backend-barretenberg/commit/1727a79ce7e66d95528f70c445cb4ec1b1ece636))

## [0.1.1](https://github.com/noir-lang/acvm-backend-barretenberg/compare/v0.1.0...v0.1.1) (2023-05-11)


### Bug Fixes

* Add description so crate can be published ([#180](https://github.com/noir-lang/acvm-backend-barretenberg/issues/180)) ([caabf94](https://github.com/noir-lang/acvm-backend-barretenberg/commit/caabf9434031c6023a5e3a436c87fba0a1072539))

## 0.1.0 (2023-05-10)


### ⚠ BREAKING CHANGES

* Update to ACVM v0.11.0 ([#151](https://github.com/noir-lang/acvm-backend-barretenberg/issues/151))
* Add Keccak constraints ([#150](https://github.com/noir-lang/acvm-backend-barretenberg/issues/150))
* migrate to ACVM 0.10.3 ([#148](https://github.com/noir-lang/acvm-backend-barretenberg/issues/148))
* remove all crates other than `acvm-backend-barretenberg` and remove workspace ([#147](https://github.com/noir-lang/acvm-backend-barretenberg/issues/147))
* merge `barretenberg_static_lib` and `barretenberg_wasm` ([#117](https://github.com/noir-lang/acvm-backend-barretenberg/issues/117))
* remove dead blake2 code ([#137](https://github.com/noir-lang/acvm-backend-barretenberg/issues/137))
* Implement pseudo-builder pattern for ConstraintSystem & hide struct fields ([#120](https://github.com/noir-lang/acvm-backend-barretenberg/issues/120))
* return boolean rather than `FieldElement` from `verify_signature` ([#123](https://github.com/noir-lang/acvm-backend-barretenberg/issues/123))
* avoid exposing internals of Assignments type ([#119](https://github.com/noir-lang/acvm-backend-barretenberg/issues/119))
* update to acvm 0.9.0 ([#106](https://github.com/noir-lang/acvm-backend-barretenberg/issues/106))
* Depend upon upstream barretenberg & switch to UltraPlonk ([#84](https://github.com/noir-lang/acvm-backend-barretenberg/issues/84))
* update to ACVM 0.7.0 ([#90](https://github.com/noir-lang/acvm-backend-barretenberg/issues/90))
* Remove create_proof and verify functions ([#82](https://github.com/noir-lang/acvm-backend-barretenberg/issues/82))
* update to acvm v0.5.0 ([#60](https://github.com/noir-lang/acvm-backend-barretenberg/issues/60))

### Features

* **acvm_interop:** Updates to reflect new acvm methods using pk/vk ([#50](https://github.com/noir-lang/acvm-backend-barretenberg/issues/50)) ([cff757d](https://github.com/noir-lang/acvm-backend-barretenberg/commit/cff757dca7971161e4bd25e7a744d910c37c22be))
* Add Keccak constraints ([#150](https://github.com/noir-lang/acvm-backend-barretenberg/issues/150)) ([ce2b9ed](https://github.com/noir-lang/acvm-backend-barretenberg/commit/ce2b9ed456bd8d2ad8357c15736d62c2a5812add))
* allow overriding transcript location with BARRETENBERG_TRANSCRIPT env var ([#86](https://github.com/noir-lang/acvm-backend-barretenberg/issues/86)) ([af92b99](https://github.com/noir-lang/acvm-backend-barretenberg/commit/af92b99c7b5f37e9659931af378a851b3658a80b))
* **ci:** add concurrency group for rust workflow ([#63](https://github.com/noir-lang/acvm-backend-barretenberg/issues/63)) ([5c936bc](https://github.com/noir-lang/acvm-backend-barretenberg/commit/5c936bc63cc3adcf9d43c9c4ce69053566089ad9))
* Depend upon upstream barretenberg & switch to UltraPlonk ([#84](https://github.com/noir-lang/acvm-backend-barretenberg/issues/84)) ([8437bf7](https://github.com/noir-lang/acvm-backend-barretenberg/commit/8437bf7e08acadf43b55b307545336596a9fe766))
* Implement pseudo-builder pattern for ConstraintSystem & hide struct fields ([#120](https://github.com/noir-lang/acvm-backend-barretenberg/issues/120)) ([8ed67d6](https://github.com/noir-lang/acvm-backend-barretenberg/commit/8ed67d68c71d655e1a6a5c38fa9ea1c3566f771d))
* Leverage rustls when using downloader crate ([#46](https://github.com/noir-lang/acvm-backend-barretenberg/issues/46)) ([9de36b6](https://github.com/noir-lang/acvm-backend-barretenberg/commit/9de36b642d125d1fb4facd1bf60db67946be70ae))
* merge `barretenberg_static_lib` and `barretenberg_wasm` ([#117](https://github.com/noir-lang/acvm-backend-barretenberg/issues/117)) ([ba1d0d6](https://github.com/noir-lang/acvm-backend-barretenberg/commit/ba1d0d61b94de91b15044d97608907c21bfb5299))
* migrate to ACVM 0.10.3 ([#148](https://github.com/noir-lang/acvm-backend-barretenberg/issues/148)) ([c9fb9e8](https://github.com/noir-lang/acvm-backend-barretenberg/commit/c9fb9e806f1400a2ff7594a0669bec56025220bb))
* remove all crates other than `acvm-backend-barretenberg` and remove workspace ([#147](https://github.com/noir-lang/acvm-backend-barretenberg/issues/147)) ([8fe7111](https://github.com/noir-lang/acvm-backend-barretenberg/commit/8fe7111ebdcb043764a83436744662e8c3ca5abc))
* remove dead blake2 code ([#137](https://github.com/noir-lang/acvm-backend-barretenberg/issues/137)) ([14d8a5b](https://github.com/noir-lang/acvm-backend-barretenberg/commit/14d8a5b893eb1cb91d5bde908643b487b41809d6))
* replace `downloader` dependency with `reqwest` ([#114](https://github.com/noir-lang/acvm-backend-barretenberg/issues/114)) ([dd62231](https://github.com/noir-lang/acvm-backend-barretenberg/commit/dd62231b8bfcee32e1029d31a07895b16159339c))
* return boolean from `verify_signature` ([e560602](https://github.com/noir-lang/acvm-backend-barretenberg/commit/e560602ebbd547386ca4cab35735ffa92e98ac4b))
* return boolean rather than `FieldElement` from `check_membership` ([#124](https://github.com/noir-lang/acvm-backend-barretenberg/issues/124)) ([a0a338e](https://github.com/noir-lang/acvm-backend-barretenberg/commit/a0a338e2295635a07f6b9e497c029160a5f323bc))
* return boolean rather than `FieldElement` from `verify_signature` ([#123](https://github.com/noir-lang/acvm-backend-barretenberg/issues/123)) ([e560602](https://github.com/noir-lang/acvm-backend-barretenberg/commit/e560602ebbd547386ca4cab35735ffa92e98ac4b))
* store transcript in `.nargo/backends` directory ([#91](https://github.com/noir-lang/acvm-backend-barretenberg/issues/91)) ([c6b5023](https://github.com/noir-lang/acvm-backend-barretenberg/commit/c6b50231da065e7550bfe8bddf8e46f4cd8002d7))
* update `aztec_backend_wasm` to use new serialization ([#94](https://github.com/noir-lang/acvm-backend-barretenberg/issues/94)) ([28014d8](https://github.com/noir-lang/acvm-backend-barretenberg/commit/28014d803d052a7f459e03dbd7b5b9210449b1d0))
* update to acvm 0.9.0 ([#106](https://github.com/noir-lang/acvm-backend-barretenberg/issues/106)) ([ff350fb](https://github.com/noir-lang/acvm-backend-barretenberg/commit/ff350fb111043964b8a14fc0df62508c87506423))
* Update to ACVM v0.11.0 ([#151](https://github.com/noir-lang/acvm-backend-barretenberg/issues/151)) ([9202415](https://github.com/noir-lang/acvm-backend-barretenberg/commit/92024155532e15f25acb2f3ed8d5ca78da0fddd9))
* update to acvm v0.5.0 ([#60](https://github.com/noir-lang/acvm-backend-barretenberg/issues/60)) ([74b4d8d](https://github.com/noir-lang/acvm-backend-barretenberg/commit/74b4d8d8b118e4477880c04149e5e9d93d388384))


### Bug Fixes

* Avoid exposing internals of Assignments type ([614c81b](https://github.com/noir-lang/acvm-backend-barretenberg/commit/614c81b0ea5e110bbf5a61a526bb0173f4fe377a))
* avoid exposing internals of Assignments type ([#119](https://github.com/noir-lang/acvm-backend-barretenberg/issues/119)) ([614c81b](https://github.com/noir-lang/acvm-backend-barretenberg/commit/614c81b0ea5e110bbf5a61a526bb0173f4fe377a))
* fix serialisation of arithmetic expressions ([#145](https://github.com/noir-lang/acvm-backend-barretenberg/issues/145)) ([7f42535](https://github.com/noir-lang/acvm-backend-barretenberg/commit/7f4253570257d9dedcfa8c8fb96b9d097ef06419))
* Implement random_get for wasm backend ([#102](https://github.com/noir-lang/acvm-backend-barretenberg/issues/102)) ([9c0f06e](https://github.com/noir-lang/acvm-backend-barretenberg/commit/9c0f06ef56f23e2b5794e810f433e36ff2c5d6b5))
* rename gates to opcodes ([#59](https://github.com/noir-lang/acvm-backend-barretenberg/issues/59)) ([6e05307](https://github.com/noir-lang/acvm-backend-barretenberg/commit/6e053072d8b9c5d93c296f10782251ccb597f902))
* reorganize and ensure contracts can be compiled in Remix ([#112](https://github.com/noir-lang/acvm-backend-barretenberg/issues/112)) ([7ec5693](https://github.com/noir-lang/acvm-backend-barretenberg/commit/7ec5693f194a79c379ae2952bc17a31ee63a42b9))
* replace `serialize_circuit` function with `from&lt;&Circuit&gt;` ([#118](https://github.com/noir-lang/acvm-backend-barretenberg/issues/118)) ([94f83a7](https://github.com/noir-lang/acvm-backend-barretenberg/commit/94f83a78e32d91dfb7ae9824923695d9b4c425b0))
* Replace serialize_circuit function with `from&lt;&Circuit&gt;` ([94f83a7](https://github.com/noir-lang/acvm-backend-barretenberg/commit/94f83a78e32d91dfb7ae9824923695d9b4c425b0))
* Update bb-sys to resolve bugs in some environments ([#129](https://github.com/noir-lang/acvm-backend-barretenberg/issues/129)) ([e3d4504](https://github.com/noir-lang/acvm-backend-barretenberg/commit/e3d4504f15e1295e637c4da80b1d08c87c267c45))
* Update dependency containing pk write fix for large general circuits ([#78](https://github.com/noir-lang/acvm-backend-barretenberg/issues/78)) ([2cb523d](https://github.com/noir-lang/acvm-backend-barretenberg/commit/2cb523d2ab95249157b22e198d9dcd6841c3eed8))
* Update to bb-sys 0.1.1 and update bb in lockfile ([00bb157](https://github.com/noir-lang/acvm-backend-barretenberg/commit/00bb15779dfb64539eeb3f3bb4c4deeba106f2fe))
* update to bb-sys 0.1.1 and update bb in lockfile ([#111](https://github.com/noir-lang/acvm-backend-barretenberg/issues/111)) ([00bb157](https://github.com/noir-lang/acvm-backend-barretenberg/commit/00bb15779dfb64539eeb3f3bb4c4deeba106f2fe))
* use `Barretenberg.call` to query circuit size from wasm ([#121](https://github.com/noir-lang/acvm-backend-barretenberg/issues/121)) ([a775af1](https://github.com/noir-lang/acvm-backend-barretenberg/commit/a775af14137cc7bc2e9d8a063fa718a5a9abe6cb))


### Miscellaneous Chores

* Remove create_proof and verify functions ([#82](https://github.com/noir-lang/acvm-backend-barretenberg/issues/82)) ([ad0c422](https://github.com/noir-lang/acvm-backend-barretenberg/commit/ad0c4228488457bd155ff381186ecf583f18bfac))
* update to ACVM 0.7.0 ([#90](https://github.com/noir-lang/acvm-backend-barretenberg/issues/90)) ([6c03687](https://github.com/noir-lang/acvm-backend-barretenberg/commit/6c036870a6a8e26612ab8b4f90a162f7540b42e2))
