import { base64url, canonicalBytes, freeze, fromBase64url, sha256 } from "./encoding.js";
import { assertEd25519PublicKey, encodeEd25519PublicKey } from "./ed25519.js";
import type { HyperKeyGroupId } from "./group-ports.js";

export const HYPERKEY_DESCRIPTOR_SCHEMA = "hyperkey.descriptor.v1" as const;
export const HYPERKEY_ALGORITHM = "Ed25519" as const;
export const HYPERKEY_PURPOSE = "conventional-signing" as const;

/** Public, immutable identity of exactly one conventional Ed25519 signing key. */
export interface HyperKeyDescriptor {
  readonly schema: typeof HYPERKEY_DESCRIPTOR_SCHEMA;
  readonly groupId: HyperKeyGroupId;
  readonly algorithm: typeof HYPERKEY_ALGORITHM;
  readonly purpose: typeof HYPERKEY_PURPOSE;
  /** Canonical raw 32-byte Ed25519 public key, base64url encoded. */
  readonly publicKey: string;
}

export async function createHyperKeyDescriptor(groupId: HyperKeyGroupId, publicKey: Uint8Array, crypto: Crypto = globalThis.crypto): Promise<Readonly<{ descriptor: HyperKeyDescriptor; id: string }>> {
  if (!canonicalIdentifier(groupId)) throw new HyperKeyDescriptorError("Group ID must be a canonical nonempty identifier");
  const descriptor = freeze<HyperKeyDescriptor>({ schema: HYPERKEY_DESCRIPTOR_SCHEMA, groupId, algorithm: HYPERKEY_ALGORITHM, purpose: HYPERKEY_PURPOSE, publicKey: encodeEd25519PublicKey(publicKey) });
  return freeze({ descriptor, id: await hyperKeyDescriptorId(descriptor, crypto) });
}

export async function hyperKeyDescriptorId(descriptor: HyperKeyDescriptor, crypto: Crypto = globalThis.crypto): Promise<string> {
  assertHyperKeyDescriptor(descriptor);
  return base64url(await sha256(canonicalBytes(["hyperkey.descriptor-id.v1", descriptor.schema, descriptor.groupId, descriptor.algorithm, descriptor.purpose, descriptor.publicKey]), crypto));
}

export function descriptorCanonicalBytes(descriptor: HyperKeyDescriptor): Uint8Array {
  assertHyperKeyDescriptor(descriptor);
  return canonicalBytes(["hyperkey.descriptor.v1", descriptor.schema, descriptor.groupId, descriptor.algorithm, descriptor.purpose, descriptor.publicKey]);
}

export function assertHyperKeyDescriptor(value: unknown): asserts value is HyperKeyDescriptor {
  if (!value || typeof value !== "object" || Object.getPrototypeOf(value) !== Object.prototype || Object.keys(value).sort().join(",") !== "algorithm,groupId,publicKey,purpose,schema") throw new HyperKeyDescriptorError("Invalid HyperKey descriptor fields");
  const descriptor = value as HyperKeyDescriptor;
  if (descriptor.schema !== HYPERKEY_DESCRIPTOR_SCHEMA || descriptor.algorithm !== HYPERKEY_ALGORITHM || descriptor.purpose !== HYPERKEY_PURPOSE || !canonicalIdentifier(descriptor.groupId)) throw new HyperKeyDescriptorError("Invalid HyperKey descriptor profile");
  assertEd25519PublicKey(fromBase64url(descriptor.publicKey, 32));
}

function canonicalIdentifier(value: unknown): value is string {
  return typeof value === "string" && value.length >= 1 && value.length <= 256 && /^[A-Za-z0-9_-]+$/u.test(value);
}

export class HyperKeyDescriptorError extends Error { override name = "HyperKeyDescriptorError"; }
