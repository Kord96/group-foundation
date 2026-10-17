# Neutral product browser facade

`@group-foundation/group-core/native` exports `NativeProductClient` for adapters with their own
MLS product profile. It directly consumes Group's `ProductGroup` custody and
never imports product policy, credentials, transport envelopes, or sidecar
schemas. `NativeClient` is the separate generic pinned Group profile, with a distinct
snapshot format; it is not used to restore product custody.

## Custody and profile inputs

`new NativeProductClient()` generates an independent local MLS Ed25519 signer.
`ownSigner()` returns only its public key. `exportCustody()` and
`NativeProductClient.fromCustody(bytes)` use the exact bounded `GFC01` envelope:
magic, big endian u32 provider length, opaque `GFS01` provider state, then the
37 byte `GFI01` signing state. Truncation, trailing bytes, wrong versions,
and excessive lengths fail. Hosts must seal and authenticate custody before
persistence. Consumers own their outer snapshot envelopes.

`fromParts(providerState, signingState)` assembles current Group provider and
signing custody. `exportProviderState()` and `exportSigningState()` support hosts
that retain these opaque components separately. `inspect(groupId)` checks the
active local leaf against that signer before returning a projection.
`hasGroup(groupId)` returns whether complete local group state is installed,
including an inactive group after removal. It returns `false` only for complete
absence; invalid IDs, malformed or partially erased native state, and active
local signer mismatches fail. Both inspections leave source custody unchanged.

`ProductProfile` supplies exact TLS encodings of MLS capabilities, group context
extensions, and leaf extensions. `ProductLimits` supplies bounded past epoch and
receive ratchet limits. Create and KeyPackage inputs supply an exact MLS
Credential TLS encoding; Group pins its signature key to local custody. Product
adapters construct and validate their own opaque credential and extension bytes.

## Detached stages

Every `stage*` operation leaves its source client unchanged, including failures.
A caller installs a result only by restoring its returned `custody` after product
validation and an atomic host transaction.

| Method | Result |
| --- | --- |
| `stageCreate(groupId, credential, profile)` | New group custody and projection |
| `stageKeyPackage(credential, profile)` | Custody retaining private package state, public package, reference, and leaf |
| `stageJoin(welcome, limits)` | Decrypted Welcome installed into detached custody and authenticated projection |
| `stageCommit(groupId, request, aad)` | Exact authored commit, optional Welcome, pending custody, merged candidate custody and projection |
| `stageMergePending(groupId)` | Merged candidate from retained pending custody |
| `stageProcess(groupId, frame, mode)` | Authenticated message facts and detached candidate |
| `stageSeal(groupId, plaintext, aad)` | Application frame and advanced detached send ratchet |
| `stageSelfRemove(groupId, aad)` | SelfRemove proposal frame and detached custody |
| `stageDelete(groupId)` | Custody removing only the selected installed group's complete native namespace |
| `stageRecords(records)` | Custody containing opaque sidecar writes or removals |
| `stageCheckpoint(anchor, selected, groupId, sidecarKeys)` | Candidate replacing only one group's native namespace and the exact named sidecars |

`ProductCommitRequest` selects additions by public KeyPackage, removals by leaf,
opaque dictionary updates by component ID, and optional exact TLS proposal
references. An absent reference list includes all pending proposals; an empty
list selects none. Duplicate and absent selected references are rejected.

Message mode `member` accepts MLS proposals, commits, or applications.
`application` rejects handshakes before processing. `ownCommit` authenticates an
authored commit independently against its public parent and returns its resulting
context and resolved proposals without merging private state. Products compare
that authenticated context with their retained pending candidate, then install
that exact candidate's pending merge.

Authenticated message results include sender TLS, credential TLS, AAD, epoch,
resolved proposals, opaque component updates, and content kind. Applications also
return plaintext. Commits return resulting context and self removal status.
In `ownCommit` mode, `selfRemoved` is derived from authenticated resolved Remove
and SelfRemove proposals against the parent group's local leaf index. Additions,
dictionary changes, and removal of another member report `false`; a referenced
SelfRemove counts only when its authenticated member sender is that local leaf.
Component updates are collected internally during processing and become visible
only after MLS signature authentication succeeds. Incoming commits merge only on
the detached candidate. Proposal candidates retain their authenticated proposal
in the detached queue; products authorize it before installing that custody.

Every `ProductProposal` includes the authenticated OpenMLS `origin`: `inline`
for a proposal carried directly in a commit, or `reference` for a separately
authenticated proposal retained by reference. Only `reference` origin includes
the canonical exact TLS `reference`; inline proposals have no reference field.
These facts are also returned for queued proposals and `ownCommit` validation.
Products enforce their own lifecycle rules using these authenticated facts.

## Public projection and sidecars

`ProductProjection` contains decimal epoch, activity, own leaf, exact authenticated
group context, context extension TLS (`components`), ratchet tree TLS, public
member leaves (including credentials, keys, and leaf extension TLS), and queued
proposals with exact TLS references and senders. Product adapters interpret these
bytes and enforce identity, profile, authority, lifecycle, routing, and history
policy. MLS authentication alone does not establish those product decisions.

`readRecord(key)` reads opaque product records. `stageRecords` accepts exact
`group-foundation.sidecar.` namespace keys and bounded byte values; `null` removes a record.
`stageCheckpoint` rejects differences outside the selected group namespace and
explicit product keys, and rejects signer substitutions. It preserves unrelated
live records and returns detached custody for the host's physical compare and
swap transaction. The product must validate sidecar semantics against the
candidate projection and fence its own authority checks before persistence.

For terminal settlement, `stageDelete` accepts an active or inactive installed
group and removes its current, retained epoch, proposal, and pending native
records. It preserves local signing custody, unused KeyPackages, unrelated
groups, and every product sidecar. An absent group fails. Products stage exact
sidecar removals with `stageRecords`, then install the combined candidate with
`stageCheckpoint`. A terminal checkpoint requires the selected group to exist in
the authenticated anchor and to be completely absent from the candidate. It
rejects unknown terminal groups, partial deletion, and changes to another group
or an unnamed sidecar. Calling `inspect` on deleted custody fails; `hasGroup`
returns `false`. The consumer owns authorization and durable terminal settlement policy.

`exportSecret(groupId, label, context, length)` derives a bounded MLS exporter;
the product owns label meaning and authorization. `signProof(transcript)` signs a
bounded product domain transcript with the local MLS key and returns the public
key and signature. Products provide domain separation and proof policy.

## Bounds and qualification

Group IDs are 1–255 bytes. Credentials are bounded to 16 KiB of content. TLS
profile components and aggregate commit dictionary updates are bounded to 64 KiB.
MLS frames and applications are bounded to 4 MiB. Proposal and record arrays are
bounded to 1024 entries; custody provider storage is bounded to 16 MiB. Aggregate
input limits are checked while collecting requests, before MLS construction.

Run `pnpm --filter @group-foundation/group-core build:wasm` followed by
`node --test packages/group-core/tests/product-binding.test.mjs` and
`pnpm --filter @group-foundation/group-core test:browser`. These checks use the
package's generated web module and exercise real MLS across independent custody,
proposal selection, pending/own commit authentication, applications, sidecars,
foreign namespace rejection, and failure isolation.
Terminal qualification additionally covers active and inactive deletion,
retained/pending native record cleanup, exact named sidecar removal, partial
state rejection, and preservation of unrelated live ratchets and records.

A consumer mount supplies its own profile codecs and validators, event signing,
transport wrapping, governance, retained branch selection, sidecar semantics,
and physical revision compare and swap.
