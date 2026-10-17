import { base64url, freeze } from "./encoding.js";
import { createHyperKeyDescriptor, type HyperKeyDescriptor } from "./descriptor.js";
import { generateEd25519SeedPair } from "./ed25519.js";
import { HYPERKEY_GROUP_PROFILE, type CopyIdentity, type HyperKeyGroupId } from "./group-ports.js";
import type { HyperKeyCopyReadiness, HyperKeyInstallationReceipt } from "./custody.js";
import type { StagedNativeGroupTransition } from "@group-foundation/group-core";

export interface HyperKeyFounderGroupPort {
  /** Stages private Group state; persistence belongs to the consumer transaction. */
  stageFounder(input: Readonly<{ groupId: HyperKeyGroupId; profile: typeof HYPERKEY_GROUP_PROFILE; founder: CopyIdentity }>, signal?: AbortSignal): Promise<StagedNativeGroupTransition>;
}

/**
 * Application composition supplies one physical transaction spanning the Group
 * founder write, sealed product seed, descriptor and readiness record. This is
 * intentionally a port: HyperKey must not own Group persistence.
 */
export interface HyperKeyFounderAtomicPort {
  createAtomically(input: Readonly<{
    stagedGroup: StagedNativeGroupTransition;
    descriptor: HyperKeyDescriptor;
    descriptorId: string;
    seed: Uint8Array;
    readiness: HyperKeyCopyReadiness;
  }>, signal?: AbortSignal): Promise<void>;
}

export interface CreatedFounderHyperKey {
  readonly descriptor: HyperKeyDescriptor;
  readonly descriptorId: string;
  readonly groupId: HyperKeyGroupId;
  readonly readiness: HyperKeyCopyReadiness;
}

/**
 * Generates conventional material independently of MLS and only reports after
 * the composition-owned atomic transaction completes. The seed is zeroed once
 * handed to the sealed custody transaction.
 */
export async function createFounderHyperKey(input: Readonly<{ groupId: HyperKeyGroupId; founder: CopyIdentity; group: HyperKeyFounderGroupPort; atomic: HyperKeyFounderAtomicPort }>, signal?: AbortSignal, crypto: Crypto = globalThis.crypto): Promise<CreatedFounderHyperKey> {
  signal?.throwIfAborted();
  const conventional = await generateEd25519SeedPair(crypto);
  try {
    const { descriptor, id: descriptorId } = await createHyperKeyDescriptor(input.groupId, conventional.publicKey, crypto);
    const receipt: HyperKeyInstallationReceipt = freeze({ schema: "hyperkey.installation-receipt.v1", descriptorId, groupId: input.groupId, profile: HYPERKEY_GROUP_PROFILE, copyId: input.founder.copyId, senderCopyId: input.founder.copyId, senderMemberSigningKeyFingerprint: input.founder.member.signingKeyFingerprint, recipientMemberSigningKeyFingerprint: input.founder.member.signingKeyFingerprint, deliveryId: base64url(crypto.getRandomValues(new Uint8Array(32))), admissionId: "founder", selectedCommitId: "founder", recipientDeliveryKey: input.founder.recipientDeliveryKey, seedPublicKey: descriptor.publicKey });
    const readiness = freeze<HyperKeyCopyReadiness>({ descriptorId, groupId: input.groupId, copyId: input.founder.copyId, status: "ready", receipt });
    const stagedGroup = await input.group.stageFounder({ groupId: input.groupId, profile: HYPERKEY_GROUP_PROFILE, founder: input.founder }, signal);
    if (stagedGroup.kind !== "create" || stagedGroup.expectedRevision !== null || stagedGroup.next.groupId !== input.groupId || stagedGroup.next.profile !== HYPERKEY_GROUP_PROFILE || stagedGroup.next.member.signingKeyFingerprint !== input.founder.member.signingKeyFingerprint) throw new Error("Founder Group staging differs from HyperKey Copy");
    await input.atomic.createAtomically({ stagedGroup, descriptor, descriptorId, seed: conventional.seed, readiness }, signal);
    return freeze({ descriptor, descriptorId, groupId: input.groupId, readiness });
  } finally { conventional.seed.fill(0); }
}
