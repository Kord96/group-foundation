import { base64url, canonicalBytes, cryptoBytes, equalBytes, fromBase64url, freeze, sha256 } from "./encoding.js";
import { assertHyperKeyDescriptor, hyperKeyDescriptorId, type HyperKeyDescriptor } from "./descriptor.js";
import { publicKeyForEd25519Seed } from "./ed25519.js";
import type { HyperKeyAdmissionId, HyperKeyCopyId, HyperKeyGroupId, HyperKeySelectedCommitId } from "./group-ports.js";
import type { HyperKeyCopyAdmissions } from "./admission.js";
import { assertAuthenticatedHyperKeyApplicationDeliveryFor, type AuthenticatedHyperKeyApplicationDelivery, type HyperKeyApplicationDeliveryBinding } from "./application-delivery.js";

export const HYPERKEY_PRIVATE_DELIVERY_SCHEMA = "hyperkey.private-delivery.v1" as const;

/** A seed is only ever present in the authenticated ciphertext. */
export interface HyperKeyPrivateDelivery {
  readonly schema: typeof HYPERKEY_PRIVATE_DELIVERY_SCHEMA;
  readonly deliveryId: string;
  readonly descriptorId: string;
  readonly groupId: HyperKeyGroupId;
  readonly recipientCopyId: HyperKeyCopyId;
  readonly senderCopyId: HyperKeyCopyId;
  readonly admissionId: HyperKeyAdmissionId;
  readonly selectedCommitId: HyperKeySelectedCommitId;
  readonly recipientDeliveryKey: string;
  readonly senderEphemeralKey: string;
  readonly nonce: string;
  readonly ciphertext: string;
}

/** Durable sender record. Implementations atomically retain the first envelope for a delivery ID. */
export interface HyperKeyPrivateDeliveryOutboxRecord {
  readonly schema: "hyperkey.private-delivery-outbox.v1";
  readonly descriptorId: string;
  readonly groupId: HyperKeyGroupId;
  readonly profile: "hyperkey.v1";
  readonly senderCopyId: HyperKeyCopyId;
  readonly senderMemberSigningKeyFingerprint: string;
  readonly recipientCopyId: HyperKeyCopyId;
  readonly recipientMemberSigningKeyFingerprint: string;
  readonly recipientDeliveryKey: string;
  readonly admissionId: HyperKeyAdmissionId;
  readonly selectedCommitId: HyperKeySelectedCommitId;
  readonly deliveryId: string;
  readonly delivery: HyperKeyPrivateDelivery;
}

export interface HyperKeyPrivateDeliveryOutboxPort {
  read(deliveryId: string, signal?: AbortSignal): Promise<HyperKeyPrivateDeliveryOutboxRecord | undefined>;
  /** Atomically writes the first record, or returns that first record. Different bytes for one ID must fail. */
  storeFirst(record: HyperKeyPrivateDeliveryOutboxRecord, signal?: AbortSignal): Promise<HyperKeyPrivateDeliveryOutboxRecord>;
}

export interface PrivateDeliveryContext {
  readonly descriptor: HyperKeyDescriptor;
  /** The concrete Group composition must prove recipient installation first. */
  readonly admissions: HyperKeyCopyAdmissions;
  readonly recipientCopyId: HyperKeyCopyId;
  readonly senderCopyId: HyperKeyCopyId;
  readonly admissionId: HyperKeyAdmissionId;
  readonly selectedCommitId: HyperKeySelectedCommitId;
  readonly recipientDeliveryKey: Uint8Array;
  /** A unique 32-byte opaque value; retain the exact envelope for retries. */
  readonly deliveryId: Uint8Array;
  /** Obtained from HyperKeyApplicationDeliveryBoundary before encryption. */
  readonly authenticatedSender: AuthenticatedHyperKeyApplicationDelivery;
  readonly outbox: HyperKeyPrivateDeliveryOutboxPort;
}

export async function createPrivateSeedDelivery(context: PrivateDeliveryContext, seed: Uint8Array, crypto: Crypto = globalThis.crypto): Promise<HyperKeyPrivateDelivery> {
  assertContext(context); if (seed.length !== 32) throw new HyperKeyDeliveryError("HyperKey seed must be 32 bytes");
  const descriptorId = await hyperKeyDescriptorId(context.descriptor, crypto);
  const binding = deliveryBinding(context, descriptorId);
  assertAuthenticatedHyperKeyApplicationDeliveryFor(context.authenticatedSender, binding, "send");
  const existing = await context.outbox.read(binding.deliveryId);
  if (existing) {
    assertOutboxRecord(existing, binding, context.authenticatedSender);
    return existing.delivery;
  }
  const installation = await context.admissions.assertCanonicalInstallation({ groupId: context.descriptor.groupId, copyId: context.recipientCopyId, admissionId: context.admissionId, selectedCommitId: context.selectedCommitId, recipientDeliveryKey: base64url(context.recipientDeliveryKey) });
  if (installation.groupId !== context.descriptor.groupId || installation.copy.copyId !== context.recipientCopyId || installation.admissionId !== context.admissionId || installation.selectedCommitId !== context.selectedCommitId) throw new HyperKeyDeliveryError("Canonical Group installation differs from private delivery context");
  if (installation.copy.member.signingKeyFingerprint !== context.authenticatedSender.recipientMemberSigningKeyFingerprint) throw new HyperKeyDeliveryError("Authenticated recipient Copy differs from canonical Group installation");
  const recipient = await crypto.subtle.importKey("raw", cryptoBytes(context.recipientDeliveryKey), { name: "X25519" }, false, []);
  const ephemeral = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  if (!isKeyPair(ephemeral)) throw new HyperKeyDeliveryError("X25519 did not yield a key pair");
  const senderEphemeralKey = base64url(new Uint8Array(await crypto.subtle.exportKey("raw", ephemeral.publicKey)));
  const delivery = unsignedDelivery(context, descriptorId, senderEphemeralKey, new Uint8Array(crypto.getRandomValues(new Uint8Array(12))));
  const key = await deliveryKey(ephemeral.privateKey, recipient, delivery, crypto);
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv: cryptoBytes(fromBase64url(delivery.nonce, 12)), additionalData: cryptoBytes(deliveryAad(delivery)) }, key, cryptoBytes(seed)));
  const envelope = freeze({ ...delivery, ciphertext: base64url(ciphertext) });
  const stored = await context.outbox.storeFirst(outboxRecord(envelope, context.authenticatedSender));
  assertOutboxRecord(stored, binding, context.authenticatedSender);
  if (!sameDelivery(stored.delivery, envelope)) throw new HyperKeyDeliveryError("A differing encrypted envelope already exists for this delivery ID");
  return stored.delivery;
}

/** Decryption validates every binding before exposing the conventional seed. */
export async function decryptPrivateSeedDelivery(delivery: HyperKeyPrivateDelivery, descriptor: HyperKeyDescriptor, recipientPrivateDeliveryKey: CryptoKey, expected: Readonly<{ recipientCopyId: HyperKeyCopyId; admissionId: HyperKeyAdmissionId; selectedCommitId: HyperKeySelectedCommitId }>, crypto: Crypto = globalThis.crypto): Promise<Uint8Array> {
  assertDelivery(delivery); assertHyperKeyDescriptor(descriptor);
  if (delivery.groupId !== descriptor.groupId || delivery.descriptorId !== await hyperKeyDescriptorId(descriptor, crypto) || delivery.recipientCopyId !== expected.recipientCopyId || delivery.admissionId !== expected.admissionId || delivery.selectedCommitId !== expected.selectedCommitId) throw new HyperKeyDeliveryError("Private delivery binding differs");
  const sender = await crypto.subtle.importKey("raw", cryptoBytes(fromBase64url(delivery.senderEphemeralKey, 32)), { name: "X25519" }, false, []);
  const key = await deliveryKey(recipientPrivateDeliveryKey, sender, delivery, crypto);
  let seed: Uint8Array;
  try { seed = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: cryptoBytes(fromBase64url(delivery.nonce, 12)), additionalData: cryptoBytes(deliveryAad(delivery)) }, key, cryptoBytes(fromBase64url(delivery.ciphertext, 48)))); }
  catch { throw new HyperKeyDeliveryError("Private delivery authentication failed"); }
  try {
    const derived = await publicKeyForEd25519Seed(seed, crypto);
    if (!equalBytes(derived, fromBase64url(descriptor.publicKey, 32))) throw new HyperKeyDeliveryError("Delivered seed does not match immutable descriptor");
    return seed;
  } catch (cause) { seed.fill(0); throw cause; }
}

/** The same binding is carried by the MLS application-message transcript. */
export function deliveryBinding(context: Pick<PrivateDeliveryContext, "descriptor" | "recipientCopyId" | "senderCopyId" | "admissionId" | "selectedCommitId" | "recipientDeliveryKey" | "deliveryId">, descriptorId: string): HyperKeyApplicationDeliveryBinding {
  return freeze({ descriptorId, groupId: context.descriptor.groupId, profile: "hyperkey.v1", senderCopyId: context.senderCopyId, recipientCopyId: context.recipientCopyId, recipientDeliveryKey: base64url(context.recipientDeliveryKey), admissionId: context.admissionId, selectedCommitId: context.selectedCommitId, deliveryId: base64url(context.deliveryId) });
}

/** Reconstructs the binding used when authenticating a received envelope. */
export function deliveryBindingForEnvelope(delivery: HyperKeyPrivateDelivery): HyperKeyApplicationDeliveryBinding {
  return freeze({ descriptorId: delivery.descriptorId, groupId: delivery.groupId, profile: "hyperkey.v1", senderCopyId: delivery.senderCopyId, recipientCopyId: delivery.recipientCopyId, recipientDeliveryKey: delivery.recipientDeliveryKey, admissionId: delivery.admissionId, selectedCommitId: delivery.selectedCommitId, deliveryId: delivery.deliveryId });
}

function unsignedDelivery(context: PrivateDeliveryContext, descriptorId: string, senderEphemeralKey: string, nonce: Uint8Array): Omit<HyperKeyPrivateDelivery, "ciphertext"> {
  return { schema: HYPERKEY_PRIVATE_DELIVERY_SCHEMA, deliveryId: base64url(context.deliveryId), descriptorId, groupId: context.descriptor.groupId, recipientCopyId: context.recipientCopyId, senderCopyId: context.senderCopyId, admissionId: context.admissionId, selectedCommitId: context.selectedCommitId, recipientDeliveryKey: base64url(context.recipientDeliveryKey), senderEphemeralKey, nonce: base64url(nonce) };
}
function deliveryAad(delivery: Omit<HyperKeyPrivateDelivery, "ciphertext">): Uint8Array {
  const { ciphertext: _ignored, ...aad } = delivery as HyperKeyPrivateDelivery;
  return canonicalBytes(["hyperkey.private-delivery.aad.v1", aad]);
}
async function deliveryKey(privateKey: CryptoKey, publicKey: CryptoKey, delivery: Omit<HyperKeyPrivateDelivery, "ciphertext">, crypto: Crypto): Promise<CryptoKey> {
  const shared = await crypto.subtle.deriveBits({ name: "X25519", public: publicKey }, privateKey, 256);
  const salt = await sha256(deliveryAad(delivery), crypto);
  const base = await crypto.subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: cryptoBytes(salt), info: cryptoBytes(canonicalBytes(["hyperkey.private-delivery.key.v1", delivery.deliveryId])) }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
function assertContext(context: PrivateDeliveryContext): void {
  assertHyperKeyDescriptor(context.descriptor);
  for (const value of [context.recipientCopyId, context.senderCopyId, context.admissionId, context.selectedCommitId]) if (typeof value !== "string" || value.length < 1 || value.length > 256) throw new HyperKeyDeliveryError("Invalid delivery binding");
  if (!(context.recipientDeliveryKey instanceof Uint8Array) || context.recipientDeliveryKey.length !== 32 || !(context.deliveryId instanceof Uint8Array) || context.deliveryId.length !== 32) throw new HyperKeyDeliveryError("Delivery key and ID must be 32 bytes");
  if (!context.outbox || typeof context.outbox.read !== "function" || typeof context.outbox.storeFirst !== "function") throw new HyperKeyDeliveryError("A durable private-delivery outbox is required");
}

function outboxRecord(delivery: HyperKeyPrivateDelivery, authenticatedSender: AuthenticatedHyperKeyApplicationDelivery): HyperKeyPrivateDeliveryOutboxRecord {
  return freeze({ schema: "hyperkey.private-delivery-outbox.v1", ...authenticatedSender.binding, senderMemberSigningKeyFingerprint: authenticatedSender.senderMemberSigningKeyFingerprint, recipientMemberSigningKeyFingerprint: authenticatedSender.recipientMemberSigningKeyFingerprint, delivery });
}
function assertOutboxRecord(record: HyperKeyPrivateDeliveryOutboxRecord, binding: HyperKeyApplicationDeliveryBinding, authenticatedSender: AuthenticatedHyperKeyApplicationDelivery): void {
  if (!record || record.schema !== "hyperkey.private-delivery-outbox.v1" || record.descriptorId !== binding.descriptorId || record.groupId !== binding.groupId || record.profile !== binding.profile || record.senderCopyId !== binding.senderCopyId || record.senderMemberSigningKeyFingerprint !== authenticatedSender.senderMemberSigningKeyFingerprint || record.recipientCopyId !== binding.recipientCopyId || record.recipientMemberSigningKeyFingerprint !== authenticatedSender.recipientMemberSigningKeyFingerprint || record.recipientDeliveryKey !== binding.recipientDeliveryKey || record.admissionId !== binding.admissionId || record.selectedCommitId !== binding.selectedCommitId || record.deliveryId !== binding.deliveryId) throw new HyperKeyDeliveryError("Private-delivery outbox binding differs");
  assertDelivery(record.delivery);
  if (!sameDeliveryBinding(record.delivery, binding)) throw new HyperKeyDeliveryError("Private-delivery outbox envelope binding differs");
}
function sameDeliveryBinding(delivery: HyperKeyPrivateDelivery, binding: HyperKeyApplicationDeliveryBinding): boolean {
  return delivery.descriptorId === binding.descriptorId && delivery.groupId === binding.groupId && delivery.senderCopyId === binding.senderCopyId && delivery.recipientCopyId === binding.recipientCopyId && delivery.recipientDeliveryKey === binding.recipientDeliveryKey && delivery.admissionId === binding.admissionId && delivery.selectedCommitId === binding.selectedCommitId && delivery.deliveryId === binding.deliveryId;
}
function sameDelivery(left: HyperKeyPrivateDelivery, right: HyperKeyPrivateDelivery): boolean {
  return left.schema === right.schema && left.deliveryId === right.deliveryId && left.descriptorId === right.descriptorId && left.groupId === right.groupId && left.recipientCopyId === right.recipientCopyId && left.senderCopyId === right.senderCopyId && left.admissionId === right.admissionId && left.selectedCommitId === right.selectedCommitId && left.recipientDeliveryKey === right.recipientDeliveryKey && left.senderEphemeralKey === right.senderEphemeralKey && left.nonce === right.nonce && left.ciphertext === right.ciphertext;
}
function assertDelivery(delivery: HyperKeyPrivateDelivery): void {
  if (!delivery || typeof delivery !== "object" || Object.keys(delivery).sort().join(",") !== "admissionId,ciphertext,deliveryId,descriptorId,groupId,nonce,recipientCopyId,recipientDeliveryKey,schema,selectedCommitId,senderCopyId,senderEphemeralKey") throw new HyperKeyDeliveryError("Invalid private delivery fields");
  if (delivery.schema !== HYPERKEY_PRIVATE_DELIVERY_SCHEMA) throw new HyperKeyDeliveryError("Unknown private delivery schema");
  for (const value of [delivery.deliveryId, delivery.descriptorId, delivery.recipientDeliveryKey, delivery.senderEphemeralKey]) fromBase64url(value, 32);
  fromBase64url(delivery.nonce, 12); fromBase64url(delivery.ciphertext, 48);
}
export class HyperKeyDeliveryError extends Error { override name = "HyperKeyDeliveryError"; }

function isKeyPair(value: CryptoKey | CryptoKeyPair): value is CryptoKeyPair {
  return typeof value === "object" && value !== null && "privateKey" in value && "publicKey" in value;
}
