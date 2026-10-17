import type { MemberIdentity } from "@group-foundation/group-core";
import type { AdmissionAction, AdmissionRequest, GroupCursor, CandidateEvidencePort, GovernancePort, GovernanceInput, VerifiedCandidate, Scope } from "@group-foundation/group-admission";
import { decodeAdmissionRequest } from "@group-foundation/group-admission";
import { decodeHyperKeyAdmissionBinding } from "./group-admission-provider.js";

/** The product profile is pinned by HyperKey; callers cannot select it. */
export const HYPERKEY_GROUP_PROFILE = "hyperkey.v1" as const;

export type HyperKeyGroupId = string;
export type HyperKeyCopyId = string;
export type HyperKeyAdmissionId = string;
export type HyperKeySelectedCommitId = string;

/**
 * HyperKey's Copy identifier is product state. It is deliberately distinct
 * from the neutral MLS signing-key fingerprint which Group uses as a member.
 */
export interface CopyIdentity {
  readonly copyId: HyperKeyCopyId;
  readonly member: MemberIdentity;
  /** SHA-256 digest of this Copy's own KeyPackage. */
  readonly keyPackageDigest: string;
  /** This Copy's X25519 delivery public key, canonical 32-byte base64url. */
  readonly recipientDeliveryKey: string;
}

/** Product-owned durable binding retained alongside, but not inside, Group records. */
export interface HyperKeyCopyAdmissionRecord {
  readonly admissionId: HyperKeyAdmissionId;
  readonly groupId: HyperKeyGroupId;
  readonly profile: typeof HYPERKEY_GROUP_PROFILE;
  readonly copy: CopyIdentity;
}

export interface HyperKeyCopyAdmissionRecordStore {
  put(record: HyperKeyCopyAdmissionRecord, signal?: AbortSignal): Promise<void>;
  get(admissionId: HyperKeyAdmissionId, signal?: AbortSignal): Promise<HyperKeyCopyAdmissionRecord | undefined>;
}

/** Derived only after Group has selected the exact Add and stored recipient installation. */
export interface CanonicalCopyInstallation {
  readonly groupId: HyperKeyGroupId;
  readonly profile: typeof HYPERKEY_GROUP_PROFILE;
  readonly copy: CopyIdentity;
  readonly admissionId: HyperKeyAdmissionId;
  readonly selectedCommitId: HyperKeySelectedCommitId;
}

/** HyperKey evidence verification is adapted into the generic candidate port below. */
export interface HyperKeyIdentityAuthority {
  verifyCopyEvidence(input: Readonly<{
    request: AdmissionRequest;
    copy: CopyIdentity;
    evidence: Uint8Array;
    nowMs: number;
  }>, signal?: AbortSignal): Promise<Readonly<{ authorityRevision: string; validUntilMs: number }>>;
}

/** HyperKey policy remains product-owned while Group owns transition mechanics. */
export interface HyperKeyGovernanceAuthority {
  authorize(input: Readonly<{
    action: AdmissionAction;
    group: GroupCursor;
    actor?: MemberIdentity;
    /** Exact generic operation bytes, including invitation/removal/installation payloads. */
    payload: Uint8Array;
    copy?: CopyIdentity;
    request?: AdmissionRequest;
    nowMs: number;
  }>, signal?: AbortSignal): Promise<Readonly<{ authorityRevision: string; validUntilMs: number }>>;
}

export class HyperKeyProviderUnavailableError extends Error {
  override name = "HyperKeyProviderUnavailableError";
  constructor() { super("HyperKey provider is unavailable; supply explicit authority and admission providers"); }
}

/** Safe default for composition: every production authority operation fails closed. */
export const unavailableHyperKeyAuthority: HyperKeyIdentityAuthority & HyperKeyGovernanceAuthority = Object.freeze({
  async verifyCopyEvidence(): Promise<never> { throw new HyperKeyProviderUnavailableError(); },
  async authorize(): Promise<never> { throw new HyperKeyProviderUnavailableError(); },
});

/** Adapt Copy authority to the generic candidate verifier. */
export class HyperKeyGroupIdentityAdapter implements CandidateEvidencePort {
  constructor(private readonly authority: HyperKeyIdentityAuthority, private readonly records: HyperKeyCopyAdmissionRecordStore, private readonly scopeFor: (groupId: string, profile: typeof HYPERKEY_GROUP_PROFILE) => Scope) {}

  async verify(request: Readonly<AdmissionRequest>, nowMs: number): Promise<VerifiedCandidate> {
    const record = await this.records.get(request.requestId);
    if (!record || !recordMatchesRequest(record, request, this.scopeFor)) throw new HyperKeyGroupCompositionError("Copy admission binding is missing or differs from the Group request");
    const verified = await this.authority.verifyCopyEvidence({ request, copy: record.copy, evidence: new Uint8Array(request.credential), nowMs });
    if (!verified.authorityRevision || !Number.isSafeInteger(verified.validUntilMs) || verified.validUntilMs <= nowMs) throw new HyperKeyGroupCompositionError("HyperKey identity authority returned invalid verification");
    return Object.freeze({ member: request.member, revision: verified.authorityRevision, validUntil: verified.validUntilMs });
  }
}

/** Generic governance still authenticates the actor and exact operation payload. */
export class HyperKeyGroupGovernanceAdapter implements GovernancePort {
  constructor(private readonly authority: HyperKeyGovernanceAuthority, private readonly records: HyperKeyCopyAdmissionRecordStore, private readonly scopeFor: (groupId: string, profile: typeof HYPERKEY_GROUP_PROFILE) => Scope) {}

  async authorize(input: GovernanceInput): Promise<Readonly<{ revision: string; validUntil: number }>> {
    const request = ["approve", "deny", "cancel", "add"].includes(input.action) ? decodeAdmissionRequest(input.payload) : undefined;
    const record = request ? await this.records.get(request.requestId) : undefined;
    if (request && (!record || !recordMatchesRequest(record, request, this.scopeFor))) throw new HyperKeyGroupCompositionError("Copy admission binding is missing or differs from the Group request");
    const result = await this.authority.authorize({ action: input.action, group: input.group, actor: input.actor, payload: new Uint8Array(input.payload), nowMs: input.now, ...(request ? { request } : {}), ...(record ? { copy: record.copy } : {}) });
    if (!result.authorityRevision || !Number.isSafeInteger(result.validUntilMs) || result.validUntilMs <= input.now) throw new HyperKeyGroupCompositionError("HyperKey governance authority returned invalid authorization");
    return Object.freeze({ revision: result.authorityRevision, validUntil: result.validUntilMs });
  }
}

export function recordMatchesRequest(record: HyperKeyCopyAdmissionRecord, request: AdmissionRequest, scopeFor: (groupId: string, profile: typeof HYPERKEY_GROUP_PROFILE) => Scope): boolean {
  const binding = decodeHyperKeyAdmissionBinding(request);
  return record.admissionId === request.requestId
    && record.profile === HYPERKEY_GROUP_PROFILE
    && record.groupId === binding.groupId
    && request.scope === scopeFor(record.groupId, HYPERKEY_GROUP_PROFILE)
    && record.copy.copyId === binding.copyId
    && record.copy.member.signingKeyFingerprint === request.member.signingKeyFingerprint
    && record.copy.keyPackageDigest === request.keyPackageDigest
    && record.copy.recipientDeliveryKey === binding.recipientDeliveryKey;
}

export class HyperKeyGroupCompositionError extends Error { override name = "HyperKeyGroupCompositionError"; }
