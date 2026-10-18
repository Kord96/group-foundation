# Admission bootstrap presentation v1

## Scope

The bootstrap subpath defines signed presentation bytes and a durable local handoff state machine. A presentation can be rendered as a QR code, copied, or conveyed by another product-selected channel. Foundation does not render or scan QR codes, open a transport, resolve a target, choose product policy, or grant membership.

Bootstrap protocol roles are `admission-host` and `candidate`. They describe which side presents or processes bytes. They are not group roles and do not authorize an actor. All candidate evidence, actor authentication, governance, invitation capacity, MLS staging, admission decisions, and installation remain owned by `GroupAdmissionRuntime` and its ports.

## Presentation modes

Both modes use schema `group-foundation.admission.bootstrap.presentation.v1`.

| Mode | Presenter | Payload | Scanner |
| --- | --- | --- | --- |
| `offer-target` | `admission-host` | Bounded opaque target material | `candidate` |
| `request-membership` | `candidate` | Exact canonical `AdmissionRequest` wire | `admission-host` |

Target material may describe an invitation or route to a product adapter, but Foundation does not interpret it. The consumer must authenticate and bind the target before using it. A membership request is decoded with the admission package's strict decoder before presentation creation or acceptance. Its own `requestedAt` and `expiresAt` remain in the admission host's configured clock domain; they are not compared with bootstrap time.

The common fields are `schema`, `mode`, `sessionId`, `presenterRole`, `createdAtMs`, `expiresAtMs`, `nonce`, `suite`, `verificationKey`, and `proof`, plus exactly one mode-specific payload. JSON keys are lexicographically sorted. Bytes use unpadded canonical base64url. Alternate whitespace, duplicate/extra fields, malformed UTF-8, and alternate base64 encodings are rejected.

`createdAtMs` and `expiresAtMs` are Unix milliseconds. Expiry is exclusive. The decoder enforces ordering and numeric bounds. Authenticated inspection additionally requires caller-selected `maxLifetimeMs` and `maxFutureSkewMs`; these are product acceptance policy and are not placed on wire.

## Cryptographic contract

The proof signs canonical JSON with domain `group-foundation.admission.bootstrap.presentation-proof.v1`. The transcript covers every presentation field except `proof`, including mode, role, both times, nonce, suite, verification key, and exact payload bytes.

Foundation injects cryptography rather than shipping a new key implementation:

- `BootstrapEntropyPort` must be a cryptographically secure random source and return exactly the requested length.
- `BootstrapPresentationSigner` owns signing custody and publishes its bounded suite name and verification key.
- `BootstrapPresentationVerifier` maps an allowed suite name to a reviewed implementation. It must reject unsupported suites; it must not infer an algorithm from attacker-controlled key bytes.
- `BootstrapSha256Port` is pinned to SHA-256 and must return exactly 32 bytes. It fingerprints exact presentation and request wires for durable replay checks.

The self-contained presentation proof establishes possession of the displayed verification key and detects wire mutation. A product must bind that key and the opaque target/request evidence to its identity and authorization model. The proof alone does not establish that the presenter is a current group member.

## Session state and replay

`BootstrapSessionSnapshot` is product-persisted local state. It records exact presentation bytes and SHA-256, local/remote protocol roles, the exclusive deadline, a monotonic revision, and phase-dependent handoff receipts. It contains no invitation accounting or admission decision.

```text
offer-target:        open -> request-ready -> submitted -> completed
request-membership:            request-ready -> submitted -> completed
                         \-> cancelled
                         \-> expired
```

Only an `admission-host` local session can record submission and completion. Submission ID must equal the canonical request's `requestId`. Presentation cancellation is allowed only before submission. Once submitted, cancellation or denial is an authenticated `GroupAdmissionRuntime` operation; the bootstrap state machine refuses to masquerade as that ledger.

An exact repeated request, submission, completion, cancellation, or resume returns the retained state with `replayed: true`. Changed bytes or identities fail with `replay`. Resume authenticates and hashes the supplied presentation again, then requires the exact retained bytes. A live state resumed at or beyond `expiresAtMs` advances once to `expired`. A submitted state remains submitted after presentation expiry because the durable admission handoff already occurred.

The snapshot is a portable contract, not a storage engine. The host must enforce a unique session-ID constraint and serialize revisions. A production adapter must atomically persist the session's submitted transition with `GroupAdmissionRuntime.commitSubmission(transaction, exactRequest)`. The structural `MembershipSubmissionPort` matches that method while leaving the product's physical transaction and result types generic; it must not be adapted to the convenience `submit`, which would open a second transaction.

## Size bounds

The protocol caps target bytes at 64 KiB, canonical admission request bytes at 512 KiB, signature verification keys at 8 KiB, proofs at 16 KiB, and total presentation wire at 768 KiB. These are parser and allocation bounds. A QR product must impose a smaller renderer-compatible bound before presentation. Renderability is not proof validity, and Foundation never selects QR version, correction level, camera behavior, or fallback transport.

