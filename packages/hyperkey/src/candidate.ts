import { base64url, cryptoBytes } from "./encoding.js";
import { HYPERKEY_GROUP_PROFILE, type CopyIdentity } from "./group-ports.js";
import type { MemberIdentity, StagedNativeGroupTransition } from "@group-foundation/group-core";

/** The candidate owns an independent MLS client before it asks to join. */
export interface HyperKeyCandidateGroupPort {
  stageCandidate(input: Readonly<{ groupId: string; profile: typeof HYPERKEY_GROUP_PROFILE; copyId: string; recipientDeliveryKey: string; evidence: Uint8Array }>, signal?: AbortSignal): Promise<Readonly<{ member: MemberIdentity; keyPackage: Uint8Array; stagedGroup: StagedNativeGroupTransition }>>;
}

export interface HyperKeyPreparedCandidate {
  readonly copy: CopyIdentity;
  readonly keyPackage: Uint8Array;
  readonly stagedGroup: StagedNativeGroupTransition;
  /** Internal custody input. Public candidate views never expose it. */
  readonly deliveryPrivateKey: Uint8Array;
}

export async function prepareHyperKeyCandidate(input: Readonly<{ groupId: string; copyId: string; evidence: Uint8Array; group: HyperKeyCandidateGroupPort }>, signal?: AbortSignal, crypto: Crypto = globalThis.crypto): Promise<HyperKeyPreparedCandidate> {
  signal?.throwIfAborted();
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  if (!("privateKey" in pair)) throw new Error("X25519 generation did not return a key pair");
  const recipientDeliveryKey = base64url(new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)));
  const staged = await input.group.stageCandidate({ groupId: input.groupId, copyId: input.copyId, evidence: new Uint8Array(input.evidence), profile: HYPERKEY_GROUP_PROFILE, recipientDeliveryKey }, signal);
  if (staged.stagedGroup.kind !== "key-package" || staged.stagedGroup.expectedRevision !== null || staged.stagedGroup.next.groupId !== input.groupId || staged.stagedGroup.next.profile !== HYPERKEY_GROUP_PROFILE || staged.stagedGroup.next.member.signingKeyFingerprint !== staged.member.signingKeyFingerprint) throw new Error("Candidate Group staging differs from independent Copy");
  const copy: CopyIdentity = Object.freeze({ copyId: input.copyId, member: Object.freeze({ ...staged.member }), keyPackageDigest: base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", cryptoBytes(staged.keyPackage)))), recipientDeliveryKey });
  const deliveryPrivateKey = new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  return Object.freeze({ copy, keyPackage: new Uint8Array(staged.keyPackage), stagedGroup: staged.stagedGroup, deliveryPrivateKey });
}

export async function restoreCandidateDeliveryPrivateKey(bytes: Uint8Array, crypto: Crypto = globalThis.crypto): Promise<CryptoKey> {
  return crypto.subtle.importKey("pkcs8", cryptoBytes(bytes), { name: "X25519" }, false, ["deriveBits"]);
}
