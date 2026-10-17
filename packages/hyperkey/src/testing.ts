import type { HyperKeyCopyAdmissionRecord, HyperKeyCopyAdmissionRecordStore } from "./group-ports.js";
import type { HyperKeyAdmittedCopyDirectoryPort } from "./application-delivery.js";
import type { HyperKeyPrivateDeliveryOutboxPort, HyperKeyPrivateDeliveryOutboxRecord } from "./delivery.js";

/** Explicit test fixture for product-owned Copy bindings; it is not a Group substitute. */
export class InMemoryHyperKeyCopyAdmissionRecordStore implements HyperKeyCopyAdmissionRecordStore {
  readonly #records = new Map<string, HyperKeyCopyAdmissionRecord>();

  async put(record: HyperKeyCopyAdmissionRecord): Promise<void> {
    const prior = this.#records.get(record.admissionId);
    if (prior && !sameRecord(prior, record)) throw new Error("Test Copy admission record changed");
    this.#records.set(record.admissionId, structuredClone(record));
  }

  async get(admissionId: string): Promise<HyperKeyCopyAdmissionRecord | undefined> {
    const record = this.#records.get(admissionId);
    return record && structuredClone(record);
  }
}

function sameRecord(left: HyperKeyCopyAdmissionRecord, right: HyperKeyCopyAdmissionRecord): boolean {
  return left.admissionId === right.admissionId
    && left.groupId === right.groupId
    && left.profile === right.profile
    && left.copy.copyId === right.copy.copyId
    && left.copy.member.signingKeyFingerprint === right.copy.member.signingKeyFingerprint
    && left.copy.keyPackageDigest === right.copy.keyPackageDigest
    && left.copy.recipientDeliveryKey === right.copy.recipientDeliveryKey;
}

/** Test-only durable Copy directory standing in for admitted-membership state. */
export class InMemoryHyperKeyAdmittedCopyDirectory implements HyperKeyAdmittedCopyDirectoryPort {
  readonly #copies = new Map<string, HyperKeyCopyAdmissionRecord["copy"]>();
  put(groupId: string, copy: HyperKeyCopyAdmissionRecord["copy"]): void { this.#copies.set(`${groupId}:${copy.copyId}`, structuredClone(copy)); }
  async read(input: Readonly<{ groupId: string; profile: "hyperkey.v1"; copyId: string }>): Promise<HyperKeyCopyAdmissionRecord["copy"] | undefined> {
    const copy = this.#copies.get(`${input.groupId}:${input.copyId}`);
    return copy && structuredClone(copy);
  }
}

/** Test-only outbox that enforces first-write-wins and byte-identical retry. */
export class InMemoryHyperKeyPrivateDeliveryOutbox implements HyperKeyPrivateDeliveryOutboxPort {
  readonly #records = new Map<string, HyperKeyPrivateDeliveryOutboxRecord>();
  async read(deliveryId: string): Promise<HyperKeyPrivateDeliveryOutboxRecord | undefined> { const record = this.#records.get(deliveryId); return record && structuredClone(record); }
  async storeFirst(record: HyperKeyPrivateDeliveryOutboxRecord): Promise<HyperKeyPrivateDeliveryOutboxRecord> {
    const prior = this.#records.get(record.deliveryId);
    if (prior) {
      if (!sameOutboxRecord(prior, record)) throw new Error("Test private-delivery outbox received differing bytes for one delivery ID");
      return structuredClone(prior);
    }
    this.#records.set(record.deliveryId, structuredClone(record));
    return structuredClone(record);
  }
}

function sameOutboxRecord(left: HyperKeyPrivateDeliveryOutboxRecord, right: HyperKeyPrivateDeliveryOutboxRecord): boolean {
  return left.descriptorId === right.descriptorId && left.groupId === right.groupId && left.profile === right.profile && left.senderCopyId === right.senderCopyId && left.senderMemberSigningKeyFingerprint === right.senderMemberSigningKeyFingerprint && left.recipientCopyId === right.recipientCopyId && left.recipientMemberSigningKeyFingerprint === right.recipientMemberSigningKeyFingerprint && left.recipientDeliveryKey === right.recipientDeliveryKey && left.admissionId === right.admissionId && left.selectedCommitId === right.selectedCommitId && left.deliveryId === right.deliveryId && JSON.stringify(left.delivery) === JSON.stringify(right.delivery);
}
