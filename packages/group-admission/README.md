# Group admission

`@group-foundation/group-admission` provides generic invitation, candidate,
approval, reservation, Add/Remove selection, durable public outbox, and
installation receipt coordination. It depends only on
`@group-foundation/group-core@0.1.0` for member identity and canonical primitives.
It contains no native MLS implementation.

Scopes and identifiers are bounded opaque strings. A scope must bind all of the
host's relevant cryptographic group/context information. There is no assumed
Group ID encoding, profile label, delivery key algorithm, database, authority
service, or private snapshot format. All instants and `reservationDuration` use
the same host-selected clock domain and unit. That clock must remain comparable
across process restarts; deadlines are exclusive.

## Host ports

Construct `GroupAdmissionRuntime<Custody>` with explicit ports:

- `transactions`: the host's serializable physical transaction and durable read.
- `candidates`: verifies candidate evidence, KeyPackage/digest/member binding,
  scope, possession and current revocation, returning a revision and deadline.
- `actors`: authenticates the management actor, independently of the candidate.
- `governance`: authorizes current membership/policy with a revision and deadline.
- `selection`: prepares an exact Add or Remove on detached core custody.
- `installations`: authenticates the recipient's entire installation receipt.
- `delivery`: publishes an already durable exact public record, safely on retry.
- `digest`: a collision-resistant canonical digest function.
- `now` and `reservationDuration`: the host clock and lease configuration.

`TranscriptActorAuthentication` and `TranscriptInstallationAuthentication` adapt
an injected `SignatureVerificationPort` to neutral, validated transcripts. The
signature verifier must authenticate the claimed member's signing-key binding as
well as the signature. The generic package chooses no signature algorithm or
public-key representation. Core MLS `signMemberProof` can sign the exported
transcripts; the host supplies its verifier.

## Transaction composition

`createAdmissionLedger(cursor)` creates only admission accounting. Private
custody remains in the host. A transaction supplies `{ ledger, stageCustody }`.
`stageCustody` must validate the full staged core transition against current
custody: operation/candidate/target binding, expected revision/epoch and local
member, exact public Commit and Welcome bytes, and the `custodyDigest` covering
all opaque custody and core effects. It then composes custody and any core
outbox into the **same uncommitted physical transaction**. Returning from
`stageCustody` must never commit anything independently or publish bytes.

The physical writer atomically commits caller semantic state, private custody,
admission ledger, transition receipts, and public outboxes. Any callback failure
rolls all of them back. Governance/evidence ports must observe or fence the
writer's current authority snapshot, including external authority changes.
No callback may publish transport.

The convenience `select`/`remove` methods reserve, stage, and ask this host
transaction port to compose selection. For an existing caller writer use:

```ts
const ticket = await runtime.reserveAdd(requestId, actor, retryId);
if (!("wire" in ticket)) {
  const staged = await runtime.prepare(ticket);
  await hostWriter(async transaction => {
    // Compose caller semantic effects into this transaction first.
    await runtime.commitSelection(transaction, ticket, staged);
  });
}
```

Call `commitSelection` last in that writer, immediately before its physical
commit; do not delay it behind later asynchronous work. It recomputes exact
operation identity, checks revision/epoch, composes custody, rechecks candidate
and actor/governance authority, then consumes the invitation use and records
selection and outbox. The host must enforce the authority fences and deadlines
through the physical commit itself. Admission never creates its own database
or makes arbitrary opaque custody valid by itself.

`publish` and `recover` send only durable bytes. `acknowledgeInstallation`
authenticates a separate recipient receipt; `installed(operationId)` returns
the immutable request, selected public wire, and verified receipt for consumer
workflows. Installation does not imply publication acknowledgement.

See [the protocol and adapter contract](spec/admission.md) for wire formats,
retry rules, and the future Room adapter hooks. The `./testing` export contains
a test-only serializable composer and recording delivery.
