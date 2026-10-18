# HyperKey

`@group-foundation/hyperkey@0.2.0` owns one immutable conventional Ed25519
key, its public descriptor and independently admitted Copies. Its only runtime
dependencies are exact `0.2.0` releases of `@group-foundation/group-core` and
`@group-foundation/group-admission`.

A Copy has an independent MLS identity, KeyPackage and X25519 delivery key. None
is derived from the conventional seed. The pinned profile is `hyperkey.v1`.
The seed cannot authorize admission and appears in transport only as an
individually encrypted private-delivery envelope.

## Composition

```ts
import { HyperKeyHost } from "@group-foundation/hyperkey";
import { prepareNativeHyperKeyFounder } from "@group-foundation/hyperkey/native";

// Initialize the group-core native module before preparing a founder.
const prepared = await prepareNativeHyperKeyFounder({
  native, evidence, copyId, recipientDeliveryKey, authority,
});
const host = new HyperKeyHost({
  persistence, sealing, commitOutcome,
  group: prepared.group,
  // candidates and admissions are explicit optional providers.
});
const key = await host.create({ founder: prepared.founder });
const signature = await key.sign(message);
await host.close();
```

The named values above are injected consumer ports, not globally available
services. Native authority verifies evidence and returns finite identity and
governance revisions/deadlines. An absent authority/provider fails closed with
`HyperKeyProviderUnavailableError`; `unavailableHyperKeyAuthority` rejects every
authority call. There is no implicit grant of admission or founder authority.

`HyperKeyHost.create/list/open` return public descriptors, Copy IDs and readiness.
The returned descriptor is frozen. `LocalHyperKey.sign` rereads committed custody,
checks the seed against the descriptor and refuses changed/missing/forgotten
custody. Ordinary handles never return a seed. Candidate preparation and low-level
custody ports are trusted composition APIs with explicit private inputs.

## Persistence ownership and recovery

`HyperKeyPersistencePort` exchanges only sealed bytes. The consumer owns the
physical transaction, writer fencing, conflict detection and durable outcome.
Its `transact(keys, callback)` supplies a mutable map scoped to the declared
keys and publishes that map with its own semantic state/outbox in one physical
transaction. The callback runs once. Callback or known commit failure rolls back
all writes. Never independently commit native custody from a staging callback.

`HyperKeySealingPort` owns independent device sealing keys. Group snapshots,
public/product records and conventional seed/candidate custody use different
purposes plus locator-bound associated data. Conventional seeds are not sealing
keys. HyperKey opens no writer lease or database. `close()` quiesces this
coordinator without closing consumer resources.

`HyperKeyCommitOutcomePort.isUncertain(error)` classifies consumer-specific
ambiguous commit failures. Once uncertain, all reads, signing and writes on that
coordinator fail. Close it and create a fresh host over a linearizable read of
committed persistence. Discover committed founders with `list/open`; do not
blindly generate a new founder. Resume exact staged transitions, deliveries and
installation receipts. No predecessor schema migration or fallback reader exists.

The sealed coordinator preserves the **1 MiB serialized plaintext record bound**,
512 declared records per transaction, 128 native outbox entries per transition,
and 256 entries per product/Copy index. Native snapshots include base64 encoding
inside that record bound. Larger native-core limits do not enlarge these limits.
Transactions fail before publication if any record exceeds its bound.

Consumers sharing a store must serialize ownership across host instances/tabs;
the coordinator's queue only serializes its own instance. Do not call another
public coordinator operation recursively inside its transaction callback.

## Admission integration

`GroupAdmissionHyperKeyProvider<Custody>` bridges the actual generic admission
runtime through `submit`, separate `approve` and `select`, authenticated
`acknowledgeInstallation`, and durable `installed`. It accepts the runtime,
its transaction read port and a mandatory `scopeFor(groupId, profile)` mapping.
This mapping must be stable and injective and bind the pinned profile. Generic
admission owns its ledger, authority checks, reservations, selection, publication
and installation authentication. HyperKey does not maintain a second ledger.

`HyperKeyGroupIdentityAdapter` and `HyperKeyGroupGovernanceAdapter` adapt explicit
Copy authorities to admission's actual candidate/governance ports. They check
persisted Copy bindings and exact opaque `hyperkey.admission-binding.v1` delivery
material. Governance receives the exact generic operation payload. The consumer
must still supply actor and installation signature verification, native staging,
delivery and one physical transaction spanning admission ledger plus native
custody and its own semantic/outbox writes.

HyperKey request and installation times use milliseconds; compose the generic
admission runtime in that same clock domain. `installedAtMs` is supplied by the
recipient before signing the generic installation transcript, so the proof binds
that exact timestamp. It is never invented after the proof is signed.

`HyperKeyCopyAdmissions` can also wrap another explicitly supplied
`HyperKeyAdmissionProvider`. That provider is trusted: it must authenticate the
candidate's MLS material, approval, selected Add and exact durable recipient
installation. Returning a Copy from an unverified transport ACK violates the
contract. Copy records must be available at each host that verifies requests or
creates deliveries; transfer them through authenticated consumer composition.

## Workflow

The host exposes `createCopyCandidate`, `requestCopy`, `approveCopy`,
`installCopyGroup`, `acknowledgeCopyInstallation`, `preparePrivateDelivery`,
`installPrivateDelivery`, `copyProgress`, `listCopies` and `forgetCopy`.
The candidate staging port generates independent MLS credentials/KeyPackages;
HyperKey generates its independent X25519 delivery key. A trusted native adapter
validates the selected Welcome before staging `installCopyGroup`.

Candidate creation atomically writes its native snapshot, sealed delivery private
key and public progress. Group installation atomically advances its snapshot and
progress. Seed installation atomically writes custody, descriptor/readiness,
exact receipt and ready progress, and deletes the temporary delivery private key.
A lost receipt recovers without another Add/Join/MLS receive or private delivery
key. Exact sender retries return the first durable encrypted envelope.

Local forgetting atomically deletes conventional seed custody, candidate custody
and the current local native snapshot, preserving a terminal tombstone. Stale
handles and delayed deliveries cannot revive the Copy. Other admitted Copies
retain their conventional key; forgetting is local suppression.

See [DELIVERY.md](DELIVERY.md), [v1 conformance](spec/conformance.md), and the
[self-contained browser qualification](../../examples/hyperkey-browser/README.md).

## Checks

With the two exact dependencies installed and core WASM built:

```sh
npm run check
npm run build
npm test
```

The native test resolves `group-core/native` and `group-core/native-wasm` through
published package exports. It fails explicitly when the WASM artifact is absent.
Fixtures under `./testing` and `tests/support` are qualification implementations;
they provide no production authority.
