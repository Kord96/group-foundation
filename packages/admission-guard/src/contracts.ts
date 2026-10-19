/** Closed verification vocabulary, independent of owner admission decisions. */
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
export interface AdmissionClaimRequestV1 {
  readonly claimId: string;
  readonly disclosure: ClaimDisclosureV1;
}

/**
 * The request is portable data. It is not an admission or membership decision,
 * and has no storage, session, application, or identity-provider authority.
 */
export interface AdmissionEvidenceRequestDefinitionV1 {
  readonly schema: 'group-foundation.admission-evidence-request.v1';
  readonly binding: EvidenceRequestBindingV1;
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly claims: readonly AdmissionClaimRequestV1[];
}

/**
 * `requestId` is a canonical digest of every request field, including policy
 * revision/digest, audience, purpose, target, recipient, subject commitment,
 * nonce, freshness window, and disclosure subset. Consumers atomically retain
 * this exact value if their operation must be one-use.
 */
export interface AdmissionEvidenceRequestV1 extends AdmissionEvidenceRequestDefinitionV1 {
  readonly requestId: string;
}

/** Only fields explicitly requested and allowed by the current policy appear. */
export interface AdmissionClaimDisclosureV1 {
  readonly claimId: string;
  readonly assertion?: true;
  readonly value?: string;
  readonly privateIdentifier?: string;
}

/**
 * A successful evidence evaluation. This proves only that supplied evidence
 * satisfies a portable request at `evaluatedAt`; the caller owns durable
 * replay consumption and any user/app/group/session decision.
 */
export interface AdmissionEvidenceEvaluationV1 {
  readonly schema: 'group-foundation.admission-evidence-evaluation.v1';
  readonly requestId: string;
  readonly binding: EvidenceRequestBindingV1;
  readonly requestIssuedAt: number;
  readonly requestExpiresAt: number;
  readonly evaluatedAt: number;
  readonly evidenceFreshUntil: number;
  readonly disclosures: readonly AdmissionClaimDisclosureV1[];
}

export type AdmissionEvidenceInputV1 = ClaimEvidenceV1;


/**
 * A consumer adapter's cryptographically verified presentation. The Guard
 * uses its signed lifetime to bound the evidence request; `value` remains
 * opaque so the consumer can retain the presentation owner's currentness
 * fence around its own durable effect.
 */
export interface AdmissionVerifiedPresentationV1<T> {
  readonly issuedAt: number;
  readonly expiresAt: number;
  readonly value: T;
}

/** A signed evidence item projected to the portable ClaimPolicy vocabulary. */
export interface AdmissionVerifiedEvidenceV1<T> {
  readonly evidence: AdmissionEvidenceInputV1;
  readonly value: T;
}

/**
 * Product-specific cryptography stays behind these ports. Admission Guard
 * owns their ordering and supplies the exact expected binding to both.
 */
export interface AdmissionSignedEvidenceVerifierV1<TPresentation, TEvidence> {
  verifyPresentation(presentation: unknown, binding: EvidenceRequestBindingV1): Promise<AdmissionVerifiedPresentationV1<TPresentation>>;
  verifyEvidence(evidence: unknown, input: Readonly<{
    request: AdmissionEvidenceRequestV1;
    policy: ClaimPolicyV1;
    now: number;
  }>): AdmissionVerifiedEvidenceV1<TEvidence> | Promise<AdmissionVerifiedEvidenceV1<TEvidence>>;
}

/** A verified presentation and complete signed evidence evaluation. */
export interface AdmissionSignedEvidenceEvaluationV1<TPresentation, TEvidence> {
  readonly request: AdmissionEvidenceRequestV1;
  readonly evaluation: AdmissionEvidenceEvaluationV1;
  readonly presentation: TPresentation;
  readonly evidence: readonly TEvidence[];
}

/** Deliberately opaque, fail-closed refusal for malformed, stale, substituted, or insufficient evidence. */
export class AdmissionGuardError extends Error {
  constructor() {
    super('admission-evidence-invalid');
    this.name = 'AdmissionGuardError';
  }
}

/** SHA-256 over exact bytes. Return exactly 32 bytes; implementations may use Web Crypto. */
export interface Sha256Port {
  sha256(bytes: Uint8Array): Uint8Array | Promise<Uint8Array>;
}

export class AdmissionWireError extends Error {
  constructor() { super('admission-wire-invalid'); this.name = 'AdmissionWireError'; }
}

export class ClaimPolicyError extends Error {
  constructor() { super('claim-policy-invalid'); this.name = 'ClaimPolicyError'; }
}
