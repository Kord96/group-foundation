import type { MemberIdentity } from "@group-foundation/group-core";
import type { Scope } from "@group-foundation/group-admission";
import { fromBase64url } from "./encoding.js";
import { HYPERKEY_GROUP_PROFILE, HyperKeyGroupCompositionError, type CanonicalCopyInstallation, type CopyIdentity, type HyperKeyCopyAdmissionRecord, type HyperKeyCopyAdmissionRecordStore } from "./group-ports.js";

export interface AuthenticatedCopyAdmissionRequest {
  readonly admissionId: string;
  readonly groupId: Scope;
  readonly invitationId: string;
  readonly copy: CopyIdentity;
  readonly evidence: Uint8Array;
  readonly keyPackage: Uint8Array;
  readonly proof: Uint8Array;
  readonly requestedAtMs: number;
  readonly expiresAtMs: number;
}

export interface HyperKeyActingMember {
  readonly member: MemberIdentity;
  readonly authentication: Uint8Array;
}

/**
 * Adapt the generic admission package to this product boundary. The provider
 * owns request encoding, approval/selection, and durable installation receipts.
 * It must verify the candidate's MLS material, selected commit and recipient
 * installation before returning a canonical installation. No seed is an input.
 */
export interface HyperKeyAdmissionProvider {
  submit(request: AuthenticatedCopyAdmissionRequest & Readonly<{ profile: typeof HYPERKEY_GROUP_PROFILE }>, signal?: AbortSignal): Promise<void>;
  approveAndSelect(input: Readonly<{ groupId: Scope; copy: CopyIdentity; admissionId: string; actors: Readonly<{ approval: HyperKeyActingMember; selection: HyperKeyActingMember }> }>, signal?: AbortSignal): Promise<Readonly<{ selectedCommitId: string }>>;
  acknowledgeInstallation(receipt: HyperKeyRecipientInstallation, signal?: AbortSignal): Promise<void>;
  canonicalInstallation(admissionId: string, signal?: AbortSignal): Promise<CanonicalCopyInstallation | undefined>;
}

/** Opaque admission proof is interpreted and verified by the provider. */
export interface HyperKeyRecipientInstallation {
  readonly admissionId: string;
  readonly groupId: Scope;
  readonly selectedCommitId: string;
  readonly recipient: MemberIdentity;
  readonly proof: Uint8Array;
  readonly installedAtMs: number;
}

/** HyperKey owns Copy bindings; generic admission mechanics stay in the provider. */
export class HyperKeyCopyAdmissions {
  constructor(private readonly provider: HyperKeyAdmissionProvider, private readonly records: HyperKeyCopyAdmissionRecordStore) {}

  async request(input: AuthenticatedCopyAdmissionRequest, signal?: AbortSignal): Promise<Readonly<{ admissionId: string }>> {
    signal?.throwIfAborted();
    if (!input || input.groupId.length < 16 || input.admissionId.length < 16 || input.copy.copyId.length < 16) throw new HyperKeyGroupCompositionError("HyperKey Copy admission identifiers are invalid");
    fromBase64url(input.copy.recipientDeliveryKey, 32);
    const owned = structuredClone(input);
    const record: HyperKeyCopyAdmissionRecord = Object.freeze({ admissionId: owned.admissionId, groupId: owned.groupId, profile: HYPERKEY_GROUP_PROFILE, copy: freezeCopy(owned.copy) });
    await this.records.put(record, signal);
    await this.provider.submit({ ...owned, profile: HYPERKEY_GROUP_PROFILE }, signal);
    return Object.freeze({ admissionId: owned.admissionId });
  }

  async approve(groupId: string, copyId: string, admissionId: string, actors: Readonly<{ approval: HyperKeyActingMember; selection: HyperKeyActingMember }>, signal?: AbortSignal): Promise<Readonly<{ selectedCommitId: string }>> {
    signal?.throwIfAborted();
    const record = await this.requiredRecord(admissionId, signal);
    if (record.groupId !== groupId || record.copy.copyId !== copyId) throw new HyperKeyGroupCompositionError("Copy approval does not match the authenticated admission");
    return this.provider.approveAndSelect({ groupId, copy: record.copy, admissionId, actors: structuredClone(actors) }, signal);
  }

  async acknowledgeCanonicalInstallation(input: HyperKeyRecipientInstallation, signal?: AbortSignal): Promise<void> {
    const record = await this.requiredRecord(input.admissionId, signal);
    if (input.groupId !== record.groupId || input.recipient.signingKeyFingerprint !== record.copy.member.signingKeyFingerprint) throw new HyperKeyGroupCompositionError("Recipient installation differs from Copy admission");
    await this.provider.acknowledgeInstallation(structuredClone(input), signal);
  }

  async assertCanonicalInstallation(expected: Readonly<{ groupId: string; copyId: string; admissionId: string; selectedCommitId: string; recipientDeliveryKey: string }>, signal?: AbortSignal): Promise<CanonicalCopyInstallation> {
    signal?.throwIfAborted();
    const record = await this.requiredRecord(expected.admissionId, signal);
    const installation = await this.provider.canonicalInstallation(expected.admissionId, signal);
    if (!installation) throw new HyperKeyGroupCompositionError("Group installation is not canonical and durable");
    if (record.profile !== HYPERKEY_GROUP_PROFILE || installation.profile !== HYPERKEY_GROUP_PROFILE
      || record.groupId !== expected.groupId || installation.groupId !== expected.groupId
      || record.copy.copyId !== expected.copyId || installation.copy.copyId !== expected.copyId
      || record.copy.recipientDeliveryKey !== expected.recipientDeliveryKey || installation.copy.recipientDeliveryKey !== expected.recipientDeliveryKey
      || installation.copy.member.signingKeyFingerprint !== record.copy.member.signingKeyFingerprint
      || installation.copy.keyPackageDigest !== record.copy.keyPackageDigest
      || installation.admissionId !== expected.admissionId || installation.selectedCommitId !== expected.selectedCommitId) {
      throw new HyperKeyGroupCompositionError("Group installation does not match HyperKey delivery bindings");
    }
    return Object.freeze({ ...installation, copy: freezeCopy(record.copy) });
  }

  private async requiredRecord(admissionId: string, signal?: AbortSignal): Promise<HyperKeyCopyAdmissionRecord> {
    const record = await this.records.get(admissionId, signal);
    if (!record) throw new HyperKeyGroupCompositionError("Authenticated Copy admission is not recorded");
    return record;
  }
}
function freezeCopy(copy: CopyIdentity): CopyIdentity { return Object.freeze({ ...copy, member: Object.freeze({ ...copy.member }) }); }
