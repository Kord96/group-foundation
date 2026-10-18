# Generic admission v1

## Ownership and core contract

The package imports `MemberIdentity` (`signingKeyFingerprint: string`) from the
actual core public root and canonical JSON/base64url primitives from
`@group-foundation/group-core/encoding`. There are no temporary core declaration
stubs or fallback imports. Its own `GroupCursor` contains opaque `scope`, numeric
safe `revision`, decimal `epoch`, and opaque `predecessor`. Revision and MLS epoch
advance by exactly one for both Add and Remove. Large epochs remain decimal
strings and are compared using `BigInt`.

This cursor deliberately does not duplicate core `GroupContext`'s Group ID or
profile vocabulary. A host maps its authenticated core context to an opaque
scope. `StagedSelection<Custody>` is an explicit generic bridge contract: the
host can choose core `StagedNativeGroupTransition` as `Custody`, or a different
validated local representation. The required `custodyDigest` binds ALL staged
private custody and core effects, without exposing them on public wire. The
composer validates this digest and its exact correspondence to the selected
public MLS bytes. Admission interprets no core snapshot format.

## Neutral canonical wires

The only schemas are:

| Data | Schema |
| --- | --- |
| Candidate request | `group-foundation.admission.request.v1` |
| Removal request | `group-foundation.admission.removal.v1` |
| Public selected transition | `group-foundation.admission.outbox.v1` |
| Installation receipt | `group-foundation.admission.installation.v1` |
| Actor proof envelope | `group-foundation.admission.actor-proof.v1` |

Predecessor `zagel.*` schema values are rejected. Canonical UTF-8 JSON uses
lexicographically sorted object keys, safe integer numbers, exact field sets,
and unpadded canonical base64url for bytes. Decoders reject alternate whitespace
or ordering, duplicate keys, malformed UTF-8, extra fields, padded/alternate
base64 encodings, invalid deadlines, and oversized wires. No old-schema reader
or compatibility alias is provided.

A candidate binds request/invitation IDs, scope, opaque credential, KeyPackage
and digest, MLS member fingerprint, requested/expiry instants, and optional opaque
`deliveryBinding`. Absence of delivery binding is valid. Nothing treats it as an
X25519 key or a transport address. The evidence verifier authenticates every
binding and current validity/revocation.

Transcripts use these top-level `domain` values:

- `group-foundation.admission.candidate-proof.v1`: all candidate fields except
  proof itself; optional delivery binding is included when present.
- `group-foundation.admission.actor.v1`: action, target ID, complete current
  cursor, independently authenticated actor, exact operation payload, deadline.
- `group-foundation.admission.installation-proof.v1`: all receipt fields except
  acknowledgement itself.

Candidate and installation transcript builders accept unsigned inputs.
`encodeActorProof(signatureMaterial, expiresAt)` wraps opaque signature material.
`TranscriptActorAuthentication` checks canonical envelope, action, scope/cursor,
member, exact payload and configurable host-unit lifetime before invoking the
signature verifier. Membership and privileges remain governance decisions.

## Invitation and candidate lifecycle

Invitations have immutable scope, issuer, exclusive expiry, maximum uses, and
explicit or automatic approval. Reusing an ID with changed definition fails.
Revocation invalidates unselected reservations. Uses are never consumed by
submission, approval, reservation, or staging.

Requests are stored by ID, digest, and exact canonical bytes. Changed bytes fail
even if a digest port collided. Explicit approval, denial and cancellation are
management operations with separately authenticated actors. A selected Add is
immutable; later management retries cannot undo it.

`submit(exactRequest)` is the convenience transaction owner. It delegates to
the public `commitSubmission(transaction, exactRequest)` composition method.
The latter accepts canonical request bytes and performs decode, digest, scope,
exact-ID retry, expiry and current candidate verification inside the caller's
existing physical transaction. This lets a host commit a bootstrap-session
handoff and the admission ledger insertion as one atomic write. The adapter
must pass that existing transaction directly: it must not invoke `submit`, open
a nested/second transaction, or mirror the admission ledger mutation itself.
Any later callback failure rolls both effects back. An exact retry after an
ambiguous commit reply returns durable progress without repeating candidate
verification; changed bytes for the same request ID conflict first.

A reservation contains `retryId` and an exclusive deadline bounded by the lease,
candidate/request/invitation and governance deadlines. A different retry cannot
steal an active reservation. Capacity checks count consumed uses plus other live
reservations. Expired leases are reclaimable. Detached work that expires, loses
its reservation, is denied/cancelled, encounters revocation, or observes a stale
revision cannot consume a use or persist custody.

Automatic approval authorizes entry to selection only; physical Add always
reauthenticates the actor and rechecks current governance. Candidate authority
and governance revisions must match the stage ticket, and their deadlines must
still be live. The host fences these facts atomically with physical commit.

## Add and Remove selection

`reserveAdd` and `reserveRemove` return either a ticket for detached staging or
the previously durable selected record. The latter is public recovery and does
not reauthorize expired actor proofs or revalidate an expired request. It cannot
create a new transition or consume another use.

`prepare` has no persistence effects. Pure `validateStagedSelection` checks
operation/retry identity, expected cursor, successor revision/epoch/scope,
nonempty bounded Commit, opaque custody presence/digest, and Add/Remove public
shape. Add requires a Welcome and may include a ratchet tree; Remove must have
neither. The host staging port remains responsible for generating the MLS
transition for the exact requested candidate or removal target.

A removal has an immutable operation ID, scope, target member and expected full
cursor. It is authorized at staging and immediately before physical commit,
uses no invitation capacity, and advances custody and outbox in the same
transaction. A changed target or expected cursor under the same operation ID
fails. Concurrent Add and Remove selection on one cursor cannot both commit.

Selection records the operation hash, retry identity, exact public bytes, core
transition ID and custody digest. The canonical stage hash binds these fields.
Reusing the selected stage with changed public output, custody digest or retry
identity fails. A transition ID can be selected only once. Persisted admission
accounting and opaque custody are the host's atomic composition responsibility;
there is no database or native snapshot fallback in this package.

On a failed or ambiguous selection reply, the runtime reopens durable state and
requires the same stage hash, matching core transition receipt, and exact
canonical public wire/hash. It returns the already committed result instead of
preparing a second Add/Remove. If no matching durable result exists, the error
is propagated. Direct `commitSelection` callers can recover via their durable
transaction read and retry the exact same stage. Lease, evidence, or group
changes may require a new stage; an old stage is never silently rebased.

## Public outbox and installation

`publish` only receives durable public records. Publication failure leaves
`pending` work; recovery retries exactly those bytes. Transport deduplicates by
wire hash or operation ID. A send followed by a lost acknowledgement may be
repeated. Public outbox data contains Commit/Welcome/tree and authority versions,
never private MLS snapshots or provider state.

Installation requires an existing selected Add and a signed receipt binding
operation ID, scope, selected wire hash, successor, admitted recipient and
installation instant. Arbitrary acknowledgements are rejected by the required
authentication port. Changed receipt bytes after installation conflict. Exact
verified receipt retries survive request expiry without repeating evidence
validation. Installation is independent of publication state. Remove has no
recipient installation.

## Future Zagel Room adapter hooks

The Room adapter is a separate consumer lane after core/admission integration.
It must provide:

1. A stable injective scope mapping binding authenticated core Group ID and
   context/profile; Room aliases or invitation routes stay outside this package.
2. A persistent host clock mapping and reservation duration, with explicit
   conversion from Room timestamp units into the configured clock domain.
3. Candidate evidence and current revocation checks binding the exact MLS member,
   KeyPackage and digest, request scope, possession and opaque delivery material.
4. Actor proof verification and Room policy authorization, backed by the physical
   writer's membership/authority revision fences.
5. Detached native Add/Remove staging; a stable digest over private staged
   transition plus core effects; and `stageCustody` validation of local member,
   scope, expected revision/epoch, exact Commit/Welcome and digest.
6. One physical transaction for Room semantic state, core custody/transition
   receipts/core outbox, admission accounting and public outbox. Roll back all
   of these on validation failure and provide a durable read after lost replies.
7. Exact-byte delivery deduplication and authenticated recipient installation
   receipts. Mailboxes, transport addressing, UI and policy remain in Room.

## Focused verification

The admission tests adapt the predecessor lifecycle/canonical-wire/signature
coverage and add Remove, Add-vs-Remove contention, expiry/revoke during detached
work, expiry during custody composition, contention on a final use, changed
request/retry/custody bytes, stale identity/governance/revision/epoch, loss of
Add/Remove commit replies, altered recovery wire, selected Add recovery after
request expiry/revocation, caller-composed bootstrap handoff/submission rollback,
lost submission replies with exact idempotent recovery, and independent
authenticated installation.

The in-memory transaction export is a test helper with serializable cloned
drafts and atomic simulated custody. It does not claim disk durability or
replace the consumer's native/core transaction validation.
