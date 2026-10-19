# Extraction integration and consumer cutover

Foundation depends downward only on its two sibling packages, pinned at exact
`0.3.0` versions. Its runtime imports use frozen public exports; no compatibility
declarations or source links are part of the package.

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

## Zagel consumer cutover

Zagel completed its clean Foundation cutover. `@zagel/hyperkey`, local HyperKey
hosts, device-state bindings, browser fixtures, root exports, workspace entries,
and source-relative asset paths have been removed. Zagel consumes only the
immutable `0.1.0` release closure under
`third_party/group-foundation/0.1.0`; its Room adapter composes Foundation
admission inside the Room-owned custody/state/outbox transaction.

This does not make HyperKey a Zagel runtime feature. Foundation's standalone
browser example is the supported qualification surface for the Copy workflow.
Future applications compose HyperKey through its neutral ports and pin an
immutable Foundation release. They must not restore an editable checkout,
workspace alias, copied Zagel implementation, or predecessor-state reader.

Preview records from the predecessor namespaces are rejected and reset. The
current descriptor, delivery, transcript, persistence, and native snapshot
namespaces have no conversion path. Room-owned envelopes remain owned by Room.
