import type { MemberIdentity } from "@group-foundation/group-core";
export type { MemberIdentity } from "@group-foundation/group-core";

export const ADMISSION_SCHEMA = "group-foundation.admission.request.v1" as const;
export const REMOVAL_SCHEMA = "group-foundation.admission.removal.v1" as const;
export const OUTBOX_SCHEMA = "group-foundation.admission.outbox.v1" as const;
export const INSTALLATION_SCHEMA = "group-foundation.admission.installation.v1" as const;
export const LIMITS = Object.freeze({ identifierChars: 1024, credentialBytes: 16 * 1024, keyPackageBytes: 256 * 1024, deliveryBindingBytes: 16 * 1024, proofBytes: 16 * 1024, wireBytes: 512 * 1024, outboxBytes: 2 * 1024 * 1024 });
/** Opaque host scope. No Group ID encoding, profile syntax, or consumer namespace is implied. */
export type Scope = string;
/** All times and durations use one host-selected monotonic clock domain, with no assumed unit. */
export type Instant = number;
export interface GroupCursor { readonly scope: Scope; readonly revision: number; readonly epoch: string; readonly predecessor: string; }
export type AdmissionAction = "issue" | "revoke" | "approve" | "deny" | "cancel" | "add" | "remove" | "accept";
export type RequestState = "pending" | "approved" | "denied" | "cancelled" | "reserved" | "selected";
export interface ActingMember { readonly member: MemberIdentity; readonly authentication: Uint8Array; }
export interface InvitationDefinition {
  readonly invitationId: string; readonly scope: Scope; readonly expiresAt: Instant;
  readonly maxUses: number; readonly approval: "automatic" | "required"; readonly issuedBy: MemberIdentity;
}
export interface AdmissionRequest {
  readonly schema: typeof ADMISSION_SCHEMA; readonly requestId: string; readonly invitationId: string;
  readonly scope: Scope; readonly member: MemberIdentity; readonly credential: Uint8Array;
  readonly keyPackage: Uint8Array; readonly keyPackageDigest: string;
  /** Opaque optional host delivery material; never interpreted as a key or transport address. */
  readonly deliveryBinding?: Uint8Array;
  readonly proof: Uint8Array; readonly requestedAt: Instant; readonly expiresAt: Instant;
}
export interface RemovalRequest {
  readonly schema: typeof REMOVAL_SCHEMA; readonly operationId: string; readonly scope: Scope;
  readonly member: MemberIdentity; readonly expected: GroupCursor;
}
export interface Authority { readonly revision: string; readonly validUntil: Instant; }
export interface VerifiedCandidate extends Authority { readonly member: MemberIdentity; }
export interface CandidateEvidencePort {
  /** Verify credential, KeyPackage/digest/MLS-member binding, proof, scope and current revocation. */
  verify(request: Readonly<AdmissionRequest>, now: Instant): Promise<VerifiedCandidate>;
}
export interface ActorAuthenticationInput {
  readonly action: AdmissionAction; readonly targetId: string; readonly group: GroupCursor;
  readonly actor: ActingMember; readonly payload: Uint8Array; readonly now: Instant;
}
export interface ActorAuthenticationPort { verify(input: ActorAuthenticationInput): Promise<MemberIdentity>; }
export interface GovernanceInput {
  readonly action: AdmissionAction; readonly group: GroupCursor; readonly actor: MemberIdentity;
  readonly payload: Uint8Array; readonly now: Instant;
}
export interface GovernancePort {
  /** Recheck current membership/policy and return a revision fence and exclusive deadline. */
  authorize(input: GovernanceInput): Promise<Authority>;
}
export interface SelectionInput {
  readonly kind: "add" | "remove"; readonly operationId: string; readonly operationHash: string;
  readonly retryId: string; readonly group: GroupCursor;
  readonly request?: AdmissionRequest; readonly removal?: RemovalRequest; readonly now: Instant;
}
/** Detached custody may be a core staged transition or a host reference; never goes on public wire. */
export interface StagedSelection<Custody> {
  readonly kind: "add" | "remove"; readonly operationId: string; readonly operationHash: string;
  readonly retryId: string; readonly transitionId: string; readonly expected: GroupCursor; readonly next: GroupCursor;
  readonly commit: Uint8Array; readonly welcome?: Uint8Array; readonly ratchetTree?: Uint8Array;
  /** Stable digest binding ALL opaque custody and exact core effects; validated by the host composer. */
  readonly custodyDigest: string; readonly custody: Custody;
}
export interface SelectionPort<Custody> { prepare(input: SelectionInput): Promise<StagedSelection<Custody>>; }
export interface PublicSelection {
  readonly schema: typeof OUTBOX_SCHEMA; readonly kind: "add" | "remove";
  readonly operationId: string; readonly operationHash: string; readonly retryId: string;
  readonly transitionId: string; readonly custodyDigest: string;
  readonly expected: GroupCursor; readonly next: GroupCursor;
  readonly authorityRevision: string; readonly candidateRevision?: string;
  readonly commit: Uint8Array; readonly welcome?: Uint8Array; readonly ratchetTree?: Uint8Array;
}
export interface AdmissionOutboxRecord {
  readonly selection: PublicSelection; readonly wire: Uint8Array; readonly wireHash: string;
  readonly stageHash: string;
}
export interface InstallationReceipt {
  readonly schema: typeof INSTALLATION_SCHEMA; readonly operationId: string; readonly scope: Scope;
  readonly selectedWireHash: string; readonly successor: string; readonly recipient: MemberIdentity;
  readonly installedAt: Instant; readonly acknowledgement: Uint8Array;
}
export interface InstallationAuthenticationPort {
  verify(input: { readonly receipt: InstallationReceipt; readonly request: AdmissionRequest; readonly selected: AdmissionOutboxRecord; readonly now: Instant }): Promise<void>;
}
export interface DeliveryPort { publish(record: Readonly<AdmissionOutboxRecord>): Promise<void>; }
export interface DigestPort { digest(bytes: Uint8Array): Promise<string>; }
export class AdmissionError extends Error {
  constructor(readonly code: string, message: string) { super(message); this.name = "AdmissionError"; }
}
