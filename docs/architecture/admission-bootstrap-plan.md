# Foundation admission bootstrap implementation plan

Status: Foundation v2 presentation, encrypted channel, and admission handoff implemented; product adapters remain separate lanes.

## Boundary and invariants

- [x] Keep the protocol in `@group-foundation/group-admission/bootstrap` and export it from the package manifest and public root.
- [x] Keep QR rendering, camera acquisition, transport, UI copy, target routing, profile data, product roles, and governance policy outside Foundation.
- [x] Treat `admission-host` and `candidate` only as protocol roles. They convey no membership or authorization.
- [x] Preserve `GroupAdmissionRuntime` as the only admission ledger. Bootstrap retains exact presentation/request bytes and handoff receipts, never invitations, approvals, reservations, uses, MLS transitions, or admission decisions.
- [x] Define a structural `MembershipSubmissionPort.commitSubmission(transaction, exactRequest)` boundary matching the admission runtime without coupling bootstrap state to its generic custody type.
- [ ] In each product adapter, bind the bootstrap session handoff and `GroupAdmissionRuntime.commitSubmission(transaction, exactRequest)` in the same product physical transaction.

## Wire and cryptography

- [x] Define clean-break canonical schema `group-foundation.admission.bootstrap.presentation.v2` and reject predecessor wire.
- [x] Support `offer-target` only from an `admission-host`, with bounded opaque target material.
- [x] Support `request-membership` only from a `candidate`, without a target or premature `AdmissionRequest` in the presentation.
- [x] Bind a product-provided secure-channel suite and public offer in both signed presentation modes.
- [x] Use explicit nonnegative Unix-millisecond `createdAtMs` and exclusive `expiresAtMs`. Do not reuse the admission runtime's host-selected clock domain.
- [x] Require 256 bits of nonce entropy and 128–512 bits of session-ID entropy on decode; the authoring helper generates 256-bit values for both.
- [x] Sign a domain-separated transcript containing every field except the proof.
- [x] Carry a bounded suite identifier and verification key. Verification dispatch belongs to the injected verifier; untrusted wire never selects an implementation directly.
- [x] Require a CSPRNG source and reviewed signature implementation from the host. Pin durable fingerprints to injected SHA-256 with an exact 32-byte result.
- [x] Reject noncanonical JSON, malformed UTF-8/base64url, missing/extra fields, mismatched mode/role fields, invalid time order, and every oversized byte field.
- [x] Make inspection authenticate the presentation before returning metadata, and require the product to provide maximum lifetime and future-clock-skew policy explicitly.

## Durable session state

- [x] Define bounded phases: `open`, `request-ready`, `submitted`, `completed`, `cancelled`, and `expired`.
- [x] Bind every session snapshot to the exact presentation bytes and SHA-256 fingerprint.
- [x] Bind the first membership request to exact canonical bytes and SHA-256; allow only exact retries.
- [x] Bind submission identity to the embedded `AdmissionRequest.requestId`; reject changed retries.
- [x] Retain submitted sessions across presentation expiry because admission lifecycle ownership has transferred to `GroupAdmissionRuntime`.
- [x] Allow bootstrap cancellation only before submission. After handoff, approval/denial/cancellation uses the existing authenticated admission APIs.
- [x] Make exact request, submission, completion, cancellation, and resume retries idempotent; reject identity or byte changes as replay conflicts.
- [x] Convert live sessions to a durable `expired` phase at the exclusive deadline. Completed, cancelled, submitted, and already-expired states remain stable on resume.
- [x] Require exact signed presentation bytes during resume, preventing a reused session ID from rebinding a durable session.
- [x] Validate restored snapshot field sets and phase-dependent fields before every transition.

## Encrypted duplex channel

- [x] Inject reviewed encryption through a crypto port; Foundation owns no encryption or key-exchange implementation.
- [x] Keep rendering, camera access, transport, target selection UI, and product discovery behind product boundaries.
- [x] Require scanner-first encrypted hello and presenter response before application messages.
- [x] Bind every encrypted envelope to the presentation digest, session, sender role, sequence, deadline, suite, and per-direction transcript predecessor.
- [x] Support host target selection, candidate payload, acceptance/rejection, progress, and the exact final canonical admission request.
- [x] Enforce role and order: candidate-first target selection occurs after scanning; acceptance follows target and candidate evidence; exact request follows acceptance.
- [x] Make rejection and request handoff terminal, and reject duplicate, skipped, reordered, altered, cross-role, and expired messages.
- [x] Retain only target/candidate digests in channel state while retaining the exact final request needed for atomic admission handoff.

## Qualification and downstream work

- [x] Add focused tests for both modes, signatures, transcript coverage, canonical encoding, candidate-first target selection, encrypted duplex exchange, exact request handoff, roles, bounds, expiry, replay, resume, cancellation, submission, and completion.
- [x] Run the package TypeScript check and full group-admission tests.
- [x] Run package-boundary validation so Foundation remains independent of Hafez, Zagel, HyperKey changes, rendering libraries, and transports.
- [ ] Product lane: choose and document a reviewed signature suite and the identity/target binding it represents.
- [ ] Product lane: implement the crypto port with a reviewed authenticated hybrid-encryption construction and durable private-key custody.
- [ ] Product lane: implement a carrier with durable exact-envelope retry; do not create a second invitation protocol.
- [ ] Product lane: map scanned target material to an authenticated admission destination without treating display text or routing data as authority.
- [ ] Product lane: persist the bootstrap snapshot under a unique session-ID constraint and atomically compose request handoff with admission submission.
- [ ] Product lane: enforce a presentation size compatible with its chosen QR renderer; Foundation's protocol bound deliberately also permits non-QR presentation channels.
- [ ] Product lane: render human-verifiable context only after authenticated inspection, and make cancellation/resume behavior visible without exposing proof/key bytes.

