# Admission Guard

`@group-foundation/admission-guard` is a standalone policy and signed-evidence
boundary. It has no runtime dependencies, imports no product packages, and is
independent of `@group-foundation/group-admission`. It creates canonical,
short-lived requests and evaluates the exact requested claim disclosure through
host cryptographic verification ports.

The first release is `0.3.0`. Pin `@group-foundation/admission-guard@0.3.0`
exactly; the immutable three-package `0.2.0` Foundation closure does not include
this package.

Exports: the root combines `/contracts`, `/wire`, `/policy`, and `/guard`.
All policy and guard operations that hash data are asynchronous. Supply SHA-256
as a port; production code uses `Uint8Array`, `TextEncoder`, and plain JavaScript.

```ts
import {
  defineClaimPolicyV1, verifyAdmissionSignedEvidenceV1,
  type Sha256Port,
} from '@group-foundation/admission-guard';

const sha256: Sha256Port = {
  sha256: async bytes => new Uint8Array(
    await crypto.subtle.digest('SHA-256', new Uint8Array(bytes)),
  ),
};
const policy = await defineClaimPolicyV1({
  schema: 'group-foundation.claim-policy.v1',
  policyId: 'room-entry',
  revision: 1,
  claims: [{
    claimId: 'qualification',
    predicate: { kind: 'issuer-claim', issuer: 'credential-issuer', claim: 'qualified' },
    required: true,
    verification: { maximumAgeSeconds: 300, methods: ['signed-credential'] },
    disclosure: { assertion: true, rawValue: false, scopedIdentifier: false },
  }],
}, sha256);

// The host supplies its exact expected scope, canonical policy pin,
// independently generated 32-byte nonce, and opaque 32-byte subject commitment.
const result = await verifyAdmissionSignedEvidenceV1({
  policy, binding: expectedBinding,
  claims: [{ claimId: 'qualification', disclosure: policy.claims[0]!.disclosure }],
  presentation: signedPresentation, evidence: signedClaims, now,
  verifier: hostVerifier,
}, sha256);
// Atomically consume result.request.requestId with the host's durable effect.
```

`scopeId`, target, recipient, audience, purpose, policy ID/revision/digest, subject
commitment, nonce, lifetime, and disclosure are all bound into the request ID.
Scope strings are opaque; the host must encode every relevant tenant, group or
application boundary in its expected binding. Subject commitments, nonces and
digests use canonical unpadded base64url of 32 bytes. Scoped identifiers use
`v1.<scope-label>.<32-byte-base64url-digest>`. The host owns their derivation,
unpredictability, and cryptographic scope binding.

Times are nonnegative safe-integer Unix seconds. Deadlines are exclusive.
Requests last at most 900 seconds, and signed-presentation lifetime bounds their
window. Evaluation freshness is capped by the request, evidence lifetime,
verification expiry, and policy maximum verification age.

The host's presentation verifier authenticates the subject, signed lifetime and
**every expected binding field**. Its evidence verifier authenticates each signed
claim, predicate, subject, exact request ID/binding, issuer, method and timestamps
before projecting to `ClaimEvidenceV1`. Adapter failures become one opaque
`AdmissionGuardError`. Evidence adapters may be synchronous or asynchronous.
The guard verifies presentation before claims and refuses extra, missing,
duplicate, unauthorized, stale or overdisclosed evidence.

`evaluateAdmissionEvidenceV1` is a lower-level operation for already authenticated
and request-bound evidence. It requires an independent expected `binding`, as do
request/evaluation assertions. Wire parsers perform closed structural decoding;
request integrity verification only checks a digest. Neither establishes
cryptographic authenticity. An evaluation read from an untrusted channel must be
authenticated by the host before assertion; it is not a bearer credential.

The package owns no membership decision, durable replay ledger, subject key,
issuer trust store, policy store, storage or network. The host must load its
current policy, fence revocation/currentness through its physical commit, and
atomically consume the exact request ID with any durable admission effect.
`createClaimPolicyPinV1` rejects in-process rollback and same-revision forks;
restart safety and current policy selection remain host responsibilities.

Canonicalization uses fixed field order and code-unit sorting for claim IDs and
verification methods. The policy and request SHA-256 transcripts use separate
`group-foundation.*.v1` domains. This is a new wire vocabulary, with no implicit
compatibility with product-specific formats.
