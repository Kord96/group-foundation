# Extraction integration and later consumer cutover

This extraction leaves the source consumer intact. Foundation depends downward
only on its two sibling packages, pinned at exact `0.1.0` versions. The runtime
imports and concrete admission bridge use their frozen actual exports; no
compatibility declarations or source links are part of the package.

## Integration assumptions

- Core exports native state/transition contracts, validators and member identity
  from its root. Native bindings remain at `group-core/native`, WASM at
  `group-core/native-wasm`. The founder adapter accepts minimal structural native
  handles so package type checking does not require generated assets.
- Generic admission exports `Scope`, `GroupAdmissionRuntime<Custody>`,
  `TransactionCompositionPort<Custody>`, canonical request encoding, policy ports
  and `installed`. HyperKey owns only its Copy binding and policy adapters.
- The consumer chooses a stable injective scope mapping and a shared millisecond
  clock for HyperKey/admission composition. The recipient signs the exact supplied
  installation timestamp and selected wire hash.
- The consumer owns fencing and one physical transaction for all staged effects,
  semantic state and outbox. HyperKey's sealed coordinator does not own admission's
  ledger and cannot independently transact it. Compose native/admission effects
  in the same consumer writer; do not nest two independently committing adapters.
- The consumer's MLS authenticator checks plaintext and persists state plus
  authentication retry metadata before returning. The Copy directory represents
  currently admitted members. These are trusted ports, not attestations produced
  by an untrusted peer.
- The browser artifact qualifies a fully independent founder workflow. Production
  Copy transport/authority is a consumer responsibility; no consumer stubs are
  imported by the example.

## Exact later Zagel cutover inventory

Do not remove these until a separate coherent consumer cutover uses the published
Foundation package and concrete consumer storage/native/admission adapters:

| Source export or file | Later action |
| --- | --- |
| `packages/hyperkey/**` (`@zagel/hyperkey`, root and `./testing`) | Remove copied runtime, old tests and manifests after replacing direct consumers with the immutable published package. |
| `packages/zagel/src/hyperkey/host.ts` | Remove local `HyperKeyHost`, `HyperKeyHostOptions`, `CreateLocalHyperKeyInput`, `LocalHyperKey`. |
| `packages/zagel/src/hyperkey/state.ts` | Remove local `HyperKeyDeviceState`, `HyperKeyDeviceStateOptions`, `StoredHyperKeyProduct` and lease/device-store adapter implementation. Supply consumer-owned neutral persistence/sealing/commit classification instead. |
| `packages/zagel/src/hyperkey/native-founder.ts` | Remove local `prepareNativeHyperKeyFounder`, `HyperKeyNativeModule`, `NativeHyperKeyFounderAuthority`; use Foundation's `hyperkey/native` export. |
| `packages/zagel/src/index.ts` | Remove the corresponding runtime/type re-exports from the three local HyperKey modules. |
| `packages/zagel/src/client/client.ts` | Remove local HyperKey import and `ZagelClientOptions.hyperKeys`, optional constructor argument, host construction, close handling and forwarding into `User`. |
| `packages/zagel/src/user/user.ts` | Remove local host import, optional constructor argument/property `User.hyperKeys` and assignment. Compose a standalone Foundation facade at the consuming application boundary. |
| `packages/zagel/tests/hyperkey-composition.test.mjs` | Move generic host/native/storage qualification to Foundation; retain only tests of intentional consumer adapters/composition. |
| `examples/browser-host/src/hyperkeys.ts` | Replace consumer-`User` controller/mount helpers with standalone Foundation composition or remove that embedded example. |
| `examples/browser-host/tests/support/hyperkey-preview.ts` and `.html` | Remove the consumer-native/host/device-store fixture and replace with the self-contained Foundation example as appropriate. |
| `examples/browser-host/tests/hyperkey-qualification.spec.ts` | Move/repoint qualification to Foundation's browser artifact; retain consumer shell checks only where explicitly intended. |
| `packages/zagel/package.json` | Remove `@zagel/hyperkey` workspace dependency; standalone application composition pins the published Foundation dependency. |
| Root `package.json` | Remove old `packages/hyperkey` steps from `build:domains`, `test:domains`, `check:types`. |
| `scripts/check-package-graph.mjs`, `scripts/check-module-boundaries.mjs`, `tests/integration/package-graph.test.mjs` | Remove local package/SDK dependency edges and update independent published Foundation boundaries. |
| `docs/public-api-inventory.json` | Remove retired SDK HyperKey exports/composition entries. |
| `pnpm-lock.yaml` and relevant browser/example manifests/configuration | Regenerate dependencies and remove stale workspace/alias links during cutover. |

Reset preview HyperKey records and protocol state. The new descriptor/profile,
delivery, transcript, persistence and native snapshot namespaces are incompatible;
there are no old-schema readers. Room-owned envelopes remain Room-owned and are
not renamed by this extraction.
