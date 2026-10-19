/** Closed verification vocabulary, independent of caller actions. */
export type ClaimPredicateV1 = Readonly<{kind:'contact-possession';channel:'email'|'phone'}> | Readonly<{kind:'issuer-claim';issuer:string;claim:string}>;
export interface ClaimDisclosureV1 {readonly assertion:boolean;readonly rawValue:boolean;readonly scopedIdentifier:boolean;}
export interface ClaimRequirementV1 {
 readonly claimId:string;readonly predicate:ClaimPredicateV1;readonly required:boolean;
 readonly verification:Readonly<{maximumAgeSeconds:number;methods:readonly string[]}>;
 readonly disclosure:ClaimDisclosureV1;
}
export interface ClaimPolicyV1 {
 readonly schema:'group-foundation.claim-policy.v1';readonly policyId:string;readonly revision:number;readonly digest:string;
 readonly claims:readonly ClaimRequirementV1[];
}
export type ClaimPolicyDefinitionV1 = Omit<ClaimPolicyV1,'digest'>;
/** Consumer-selected scope and opaque subject binding, independent of identity authority type. */
export interface EvidenceRequestBindingV1 {
 readonly scopeId:string;readonly policyId:string;readonly policyRevision:number;readonly policyDigest:string;
 readonly target:string;readonly recipient:string;readonly audience:string;readonly purpose:string;
 readonly subjectCommitment:string;readonly nonce:string;
}
export interface ClaimReleaseConsentV1 {readonly scope:EvidenceRequestBindingV1;readonly claimId:string;readonly disclosure:ClaimDisclosureV1;}
export interface ClaimEvidenceV1 {
 readonly claimId:string;readonly assertion?:true;readonly value?:string;readonly privateIdentifier?:string;
 readonly verifiedAt:number;readonly verificationExpiresAt:number;readonly verificationMethod:string;readonly verificationIssuer?:string;readonly issuedAt:number;readonly expiresAt:number;
}


/** A consumer asks for an exact policy-authorized subset of one claim. */
export interface BouncerClaimRequestV1 {
  readonly claimId: string;
  readonly disclosure: ClaimDisclosureV1;
}

/**
 * The request is portable data. It is not an action or authority decision,
 * and has no storage, session, application, or identity-provider authority.
 */
export interface BouncerEvidenceRequestDefinitionV1 {
  readonly schema: 'group-foundation.bouncer-evidence-request.v1';
  readonly binding: EvidenceRequestBindingV1;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly claims: readonly BouncerClaimRequestV1[];
}

/**
 * `requestId` is a canonical digest of every request field, including policy
 * revision/digest, audience, purpose, target, recipient, subject commitment,
 * nonce, freshness window, and disclosure subset. Consumers atomically retain
 * this exact value if their operation must be one-use.
 */
export interface BouncerEvidenceRequestV1 extends BouncerEvidenceRequestDefinitionV1 {
  readonly requestId: string;
}

/** Only fields explicitly requested and allowed by the current policy appear. */
export interface BouncerClaimDisclosureV1 {
  readonly claimId: string;
  readonly assertion?: true;
  readonly value?: string;
  readonly privateIdentifier?: string;
}

/**
 * A decision binds the exact policy, request and supplied evidence without
 * carrying an action continuation. Only approved decisions carry disclosure
 * and freshness data. The caller owns replay consumption and every effect.
 */
export interface BouncerDecisionBaseV1 {
  readonly schema: 'group-foundation.bouncer-decision.v1';
  readonly decisionId: string;
  readonly requestId: string;
  readonly binding: EvidenceRequestBindingV1;
  readonly policyId: string;
  readonly policyRevision: number;
  readonly policyDigest: string;
  readonly evidenceDigest: string;
  readonly requestIssuedAt: number;
  readonly requestExpiresAt: number;
  readonly evaluatedAt: number;
}

export interface BouncerApprovedDecisionV1 extends BouncerDecisionBaseV1 {
  readonly outcome: 'approved';
  readonly evidenceFreshUntil: number;
  readonly disclosures: readonly BouncerClaimDisclosureV1[];
}

export interface BouncerDeniedDecisionV1 extends BouncerDecisionBaseV1 {
  readonly outcome: 'denied';
  readonly reason: 'evidence-requirements-not-satisfied';
}

export type BouncerDecisionV1 = BouncerApprovedDecisionV1 | BouncerDeniedDecisionV1;

export type BouncerEvidenceInputV1 = ClaimEvidenceV1;


/**
 * A consumer adapter's cryptographically verified presentation. Bouncer
 * uses its signed lifetime to bound the evidence request; `value` remains
 * opaque so the consumer can retain the presentation owner's currentness
 * fence around its own durable effect.
 */
export interface BouncerVerifiedPresentationV1<T> {
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly value: T;
}

/** A signed evidence item projected to the portable ClaimPolicy vocabulary. */
export interface BouncerVerifiedEvidenceV1<T> {
  readonly evidence: BouncerEvidenceInputV1;
  readonly value: T;
}

/**
 * Product-specific cryptography stays behind these ports. Bouncer
 * owns their ordering and supplies the exact expected binding to both.
 */
export interface BouncerSignedEvidenceVerifierV1<TPresentation, TEvidence> {
  verifyPresentation(presentation: unknown, binding: EvidenceRequestBindingV1): Promise<BouncerVerifiedPresentationV1<TPresentation>>;
  verifyEvidence(evidence: unknown, input: Readonly<{
    request: BouncerEvidenceRequestV1;
    policy: ClaimPolicyV1;
    now: number;
  }>): BouncerVerifiedEvidenceV1<TEvidence> | Promise<BouncerVerifiedEvidenceV1<TEvidence>>;
}

/** Verified inputs and the resulting immutable decision. */
export interface BouncerSignedEvidenceDecisionV1<TPresentation, TEvidence> {
  readonly request: BouncerEvidenceRequestV1;
  readonly decision: BouncerDecisionV1;
  readonly presentation: TPresentation;
  readonly evidence: readonly TEvidence[];
}

/** Explicit failure for malformed input or unavailable verification infrastructure. */
export class BouncerError extends Error {
  constructor() {
    super('bouncer-evidence-invalid');
    this.name = 'BouncerError';
  }
}

/** SHA-256 over exact bytes. Return exactly 32 bytes; implementations may use Web Crypto. */
export interface Sha256Port {
  sha256(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export class BouncerWireError extends Error {
  constructor() { super('bouncer-wire-invalid'); this.name = 'BouncerWireError'; }
}

export class ClaimPolicyError extends Error {
  constructor() { super('claim-policy-invalid'); this.name = 'ClaimPolicyError'; }
}
