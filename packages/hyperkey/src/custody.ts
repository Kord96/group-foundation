import { equalBytes, freeze, fromBase64url } from "./encoding.js";
import { type HyperKeyDescriptor, hyperKeyDescriptorId } from "./descriptor.js";
import { decryptPrivateSeedDelivery, deliveryBindingForEnvelope, type HyperKeyPrivateDelivery } from "./delivery.js";
import type { CanonicalCopyInstallation } from "./group-ports.js";
import type { HyperKeyCopyAdmissions } from "./admission.js";
import { assertAuthenticatedHyperKeyApplicationDeliveryFor, type AuthenticatedHyperKeyApplicationDelivery } from "./application-delivery.js";

export interface HyperKeyInstallationReceipt {
  readonly schema: "hyperkey.installation-receipt.v1";
  readonly descriptorId: string;
  readonly groupId: string;
  readonly profile: "hyperkey.v1";
  readonly copyId: string;
  readonly senderCopyId: string;
  readonly senderMemberSigningKeyFingerprint: string;
  readonly recipientMemberSigningKeyFingerprint: string;
  readonly deliveryId: string;
  readonly admissionId: string;
  readonly selectedCommitId: string;
  readonly recipientDeliveryKey: string;
  /** Public descriptor binding only; does not contain a seed or a delivery private key. */
  readonly seedPublicKey: string;
}

export interface HyperKeyCopyReadiness {
  readonly descriptorId: string;
  readonly groupId: string;
  readonly copyId: string;
  readonly status: "ready" | "forgotten";
  readonly receipt?: HyperKeyInstallationReceipt;
}

/** Durable product-owned record port. Its transaction is the local atomic writer boundary. */
export interface HyperKeyLocalStatePort {
  read(descriptorId: string, copyId: string, signal?: AbortSignal): Promise<HyperKeyCopyReadiness | undefined>;
  transaction<T>(operation: (state: HyperKeyLocalStateMutation) => Promise<T> | T, signal?: AbortSignal): Promise<T>;
}
export interface HyperKeyLocalStateMutation {
  read(descriptorId: string, copyId: string): HyperKeyCopyReadiness | undefined;
  write(record: HyperKeyCopyReadiness): void;
}

/** The seed stays behind this local interface after a verified install. */
export interface HyperKeySeedCustody {
  seal(input: Readonly<{ descriptorId: string; copyId: string; seed: Uint8Array }>, signal?: AbortSignal): Promise<void>;
  remove(input: Readonly<{ descriptorId: string; copyId: string }>, signal?: AbortSignal): Promise<void>;
  has(input: Readonly<{ descriptorId: string; copyId: string }>, signal?: AbortSignal): Promise<boolean>;
}

/**
 * Installs an envelope only once the exact selected Group installation exists.
 * Exact duplicate delivery is idempotent; a different delivery/material after
 * receipt is rejected, preventing an attacker from replacing local custody.
 */
export async function installPrivateSeedDelivery(input: Readonly<{
  delivery: HyperKeyPrivateDelivery;
  descriptor: HyperKeyDescriptor;
  /** Required only for a first installation; exact receipt recovery reads no seed. */
  recipientPrivateDeliveryKey?: CryptoKey;
  /** Authenticates the same MLS application message before the seed is decrypted. */
  authenticatedSender: AuthenticatedHyperKeyApplicationDelivery;
  admissions: HyperKeyCopyAdmissions;
  state: HyperKeyLocalStatePort;
  custody: HyperKeySeedCustody;
}>, signal?: AbortSignal, crypto: Crypto = globalThis.crypto): Promise<HyperKeyInstallationReceipt> {
  signal?.throwIfAborted();
  const { delivery, descriptor } = input;
  assertAuthenticatedHyperKeyApplicationDeliveryFor(input.authenticatedSender, deliveryBindingForEnvelope(delivery), "receive");
  const installation = await input.admissions.assertCanonicalInstallation({ groupId: descriptor.groupId, copyId: delivery.recipientCopyId, admissionId: delivery.admissionId, selectedCommitId: delivery.selectedCommitId, recipientDeliveryKey: delivery.recipientDeliveryKey }, signal);
  assertInstallationMatches(installation, delivery);
  if (installation.copy.member.signingKeyFingerprint !== input.authenticatedSender.recipientMemberSigningKeyFingerprint) throw new HyperKeyCustodyError("Authenticated recipient Copy differs from canonical Group installation");
  const descriptorId = await hyperKeyDescriptorId(descriptor, crypto);
  const receipt = receiptFor(descriptor, descriptorId, installation, delivery, input.authenticatedSender);
  const existing = await input.state.read(descriptorId, installation.copy.copyId, signal);
  if (existing) {
    const recovered = existingReceipt(existing, receipt);
    if (!await input.custody.has({ descriptorId, copyId: installation.copy.copyId }, signal)) throw new HyperKeyCopyUnavailableError("missing-custody");
    return recovered;
  }
  if (!input.recipientPrivateDeliveryKey) throw new HyperKeyCustodyError("Recipient private delivery key is required for first installation");
  const seed = await decryptPrivateSeedDelivery(delivery, descriptor, input.recipientPrivateDeliveryKey, { recipientCopyId: installation.copy.copyId, admissionId: installation.admissionId, selectedCommitId: installation.selectedCommitId }, crypto);
  try {
    return await input.state.transaction(async state => {
      const previous = state.read(descriptorId, installation.copy.copyId);
      if (previous) return existingReceipt(previous, receipt);
      const custodySeed = new Uint8Array(seed);
      try { await input.custody.seal({ descriptorId, copyId: installation.copy.copyId, seed: custodySeed }, signal); }
      finally { custodySeed.fill(0); }
      state.write(freeze({ descriptorId, groupId: descriptor.groupId, copyId: installation.copy.copyId, status: "ready", receipt }));
      return receipt;
    }, signal);
  } finally { seed.fill(0); }
}

/** Removes local seed custody and preserves a tombstone that rejects delayed/replayed delivery. */
export async function forgetHyperKeyLocally(input: Readonly<{ descriptorId: string; groupId: string; copyId: string; state: HyperKeyLocalStatePort; custody: HyperKeySeedCustody }>, signal?: AbortSignal): Promise<void> {
  await input.state.transaction(async state => {
    const previous = state.read(input.descriptorId, input.copyId);
    if (previous && (previous.groupId !== input.groupId || previous.copyId !== input.copyId)) throw new HyperKeyCustodyError("Local HyperKey state binding differs");
    await input.custody.remove({ descriptorId: input.descriptorId, copyId: input.copyId }, signal);
    state.write(freeze({ descriptorId: input.descriptorId, groupId: input.groupId, copyId: input.copyId, status: "forgotten" }));
  }, signal);
}

function receiptFor(descriptor: HyperKeyDescriptor, descriptorId: string, installation: CanonicalCopyInstallation, delivery: HyperKeyPrivateDelivery, authenticatedSender: AuthenticatedHyperKeyApplicationDelivery): HyperKeyInstallationReceipt {
  return freeze({ schema: "hyperkey.installation-receipt.v1", descriptorId, groupId: descriptor.groupId, profile: "hyperkey.v1", copyId: installation.copy.copyId, senderCopyId: delivery.senderCopyId, senderMemberSigningKeyFingerprint: authenticatedSender.senderMemberSigningKeyFingerprint, recipientMemberSigningKeyFingerprint: authenticatedSender.recipientMemberSigningKeyFingerprint, deliveryId: delivery.deliveryId, admissionId: installation.admissionId, selectedCommitId: installation.selectedCommitId, recipientDeliveryKey: delivery.recipientDeliveryKey, seedPublicKey: descriptor.publicKey });
}
function assertInstallationMatches(installation: CanonicalCopyInstallation, delivery: HyperKeyPrivateDelivery): void {
  if (installation.profile !== "hyperkey.v1" || installation.groupId !== delivery.groupId || installation.copy.copyId !== delivery.recipientCopyId || installation.copy.recipientDeliveryKey !== delivery.recipientDeliveryKey || installation.admissionId !== delivery.admissionId || installation.selectedCommitId !== delivery.selectedCommitId) throw new HyperKeyCustodyError("Group installation does not match private delivery");
}
function sameReceipt(left: HyperKeyInstallationReceipt, right: HyperKeyInstallationReceipt): boolean {
  return left.schema === "hyperkey.installation-receipt.v1" && right.schema === "hyperkey.installation-receipt.v1" && left.descriptorId === right.descriptorId && left.groupId === right.groupId && left.profile === right.profile && left.copyId === right.copyId && left.senderCopyId === right.senderCopyId && left.senderMemberSigningKeyFingerprint === right.senderMemberSigningKeyFingerprint && left.recipientMemberSigningKeyFingerprint === right.recipientMemberSigningKeyFingerprint && left.deliveryId === right.deliveryId && left.admissionId === right.admissionId && left.selectedCommitId === right.selectedCommitId && left.recipientDeliveryKey === right.recipientDeliveryKey && equalBytes(fromBase64url(left.seedPublicKey, 32), fromBase64url(right.seedPublicKey, 32));
}
function existingReceipt(previous: HyperKeyCopyReadiness, receipt: HyperKeyInstallationReceipt): HyperKeyInstallationReceipt {
  if (previous.status === "forgotten") throw new HyperKeyCustodyError("HyperKey is locally suppressed after forgetting");
  if (previous.receipt && sameReceipt(previous.receipt, receipt)) return previous.receipt;
  throw new HyperKeyCustodyError("A different private delivery cannot replace an installed HyperKey");
}

export class HyperKeyCustodyError extends Error { override name = "HyperKeyCustodyError"; }

export class HyperKeyCopyUnavailableError extends HyperKeyCustodyError {
  override name = "HyperKeyCopyUnavailableError";
  constructor(readonly reason: "not-ready" | "forgotten" | "missing-custody" | "changed-custody") {
    super(`HyperKey Copy is unavailable: ${reason}`);
  }
}

/** Explicitly limited test/local implementation; production injects sealed device custody. */
export class InMemoryHyperKeySeedCustody implements HyperKeySeedCustody {
  readonly #seeds = new Map<string, Uint8Array>();
  async seal({ descriptorId, copyId, seed }: Readonly<{ descriptorId: string; copyId: string; seed: Uint8Array }>): Promise<void> { this.#seeds.set(`${descriptorId}:${copyId}`, new Uint8Array(seed)); }
  async remove({ descriptorId, copyId }: Readonly<{ descriptorId: string; copyId: string }>): Promise<void> { const key = `${descriptorId}:${copyId}`, seed = this.#seeds.get(key); if (seed) seed.fill(0); this.#seeds.delete(key); }
  async has({ descriptorId, copyId }: Readonly<{ descriptorId: string; copyId: string }>): Promise<boolean> { return this.#seeds.has(`${descriptorId}:${copyId}`); }
  /** Test-only copy: a real custody adapter must not export this seed. */
  testingRead(descriptorId: string, copyId: string): Uint8Array | undefined { const value = this.#seeds.get(`${descriptorId}:${copyId}`); return value && new Uint8Array(value); }
}

export class InMemoryHyperKeyLocalState implements HyperKeyLocalStatePort {
  readonly #records = new Map<string, HyperKeyCopyReadiness>();
  async read(descriptorId: string, copyId: string): Promise<HyperKeyCopyReadiness | undefined> { return this.#records.get(`${descriptorId}:${copyId}`); }
  async transaction<T>(operation: (state: HyperKeyLocalStateMutation) => Promise<T> | T): Promise<T> {
    const staged = new Map(this.#records);
    const result = await operation({ read: (descriptorId, copyId) => staged.get(`${descriptorId}:${copyId}`), write: record => staged.set(`${record.descriptorId}:${record.copyId}`, record) });
    this.#records.clear(); for (const [key, record] of staged) this.#records.set(key, record); return result;
  }
}
