import { canonicalBytes, freeze } from "./encoding.js";
import { assertStagedNativeGroupTransition, type StagedNativeGroupTransition } from "@group-foundation/group-core";
import { HYPERKEY_GROUP_PROFILE, type CopyIdentity, type HyperKeyAdmissionId, type HyperKeyCopyId, type HyperKeyGroupId, type HyperKeySelectedCommitId } from "./group-ports.js";

/** Values that must be carried by the authenticated MLS application message. */
export interface HyperKeyApplicationDeliveryBinding {
  readonly descriptorId: string;
  readonly groupId: HyperKeyGroupId;
  readonly profile: typeof HYPERKEY_GROUP_PROFILE;
  readonly senderCopyId: HyperKeyCopyId;
  readonly recipientCopyId: HyperKeyCopyId;
  readonly recipientDeliveryKey: string;
  readonly admissionId: HyperKeyAdmissionId;
  readonly selectedCommitId: HyperKeySelectedCommitId;
  readonly deliveryId: string;
}

/**
 * Implemented by the persistent MLS integration. For send, return the exact
 * durable staged sealing result from the sender; never decrypt as a recipient.
 * For receive, open against the latest durable recipient state and atomically
 * persist the advanced ratchet before returning. Never restore an older
 * recipient snapshot to reauthenticate an already consumed frame.
 * It deliberately has no access to an Ed25519 HyperKey seed.
 */
export interface HyperKeyMlsApplicationMessagePort {
  authenticate(input: Readonly<{ direction: "send" | "receive"; applicationMessage: Uint8Array; expectedPlaintext: Uint8Array }>, signal?: AbortSignal): Promise<Readonly<{
    groupId: HyperKeyGroupId;
    profile: string;
    senderMemberSigningKeyFingerprint: string;
    /** The private state advance already committed with this exact frame. */
    transition: StagedNativeGroupTransition;
  }>>;
}

/** Current, product-owned Copy to admitted MLS Member mapping. */
export interface HyperKeyAdmittedCopyDirectoryPort {
  read(input: Readonly<{ groupId: HyperKeyGroupId; profile: typeof HYPERKEY_GROUP_PROFILE; copyId: HyperKeyCopyId }>, signal?: AbortSignal): Promise<CopyIdentity | undefined>;
}

/** An unforgeable result of authenticating an MLS application delivery message. */
export interface AuthenticatedHyperKeyApplicationDelivery {
  readonly binding: HyperKeyApplicationDeliveryBinding;
  readonly purpose: "send" | "receive";
  readonly senderMemberSigningKeyFingerprint: string;
  readonly recipientMemberSigningKeyFingerprint: string;
}

const authenticated = new WeakSet<object>();

/**
 * HyperKey's concrete boundary around an MLS application message. The caller
 * supplies the MLS verifier and current admitted Copy directory; this adapter
 * rejects both a substituted claimed Copy and a message from another Group.
 */
export class HyperKeyApplicationDeliveryBoundary {
  constructor(private readonly mls: HyperKeyMlsApplicationMessagePort, private readonly copies: HyperKeyAdmittedCopyDirectoryPort) {}

  async authenticateForSend(binding: HyperKeyApplicationDeliveryBinding, applicationMessage: Uint8Array, signal?: AbortSignal): Promise<AuthenticatedHyperKeyApplicationDelivery> {
    return this.authenticate(binding, applicationMessage, "send", signal);
  }

  async authenticateForReceive(binding: HyperKeyApplicationDeliveryBinding, applicationMessage: Uint8Array, signal?: AbortSignal): Promise<AuthenticatedHyperKeyApplicationDelivery> {
    return this.authenticate(binding, applicationMessage, "receive", signal);
  }

  private async authenticate(binding: HyperKeyApplicationDeliveryBinding, applicationMessage: Uint8Array, purpose: "send" | "receive", signal?: AbortSignal): Promise<AuthenticatedHyperKeyApplicationDelivery> {
    assertBinding(binding);
    if (!(applicationMessage instanceof Uint8Array) || applicationMessage.length === 0) throw new HyperKeyApplicationDeliveryError("An authenticated MLS application message is required");
    const expectedPlaintext = hyperKeyApplicationTranscript(binding);
    const message = await this.mls.authenticate({ direction: purpose, applicationMessage: new Uint8Array(applicationMessage), expectedPlaintext }, signal);
    assertStagedNativeGroupTransition(message.transition);
    if (message.transition.kind !== (purpose === "send" ? "application-send" : "application-receive") || message.transition.next.groupId !== binding.groupId || message.transition.next.profile !== binding.profile) throw new HyperKeyApplicationDeliveryError("MLS authentication has the wrong staged direction or scope");
    if (message.groupId !== binding.groupId || message.profile !== binding.profile) throw new HyperKeyApplicationDeliveryError("MLS application message Group or profile differs from delivery binding");
    const [sender, recipient] = await Promise.all([
      this.copies.read({ groupId: binding.groupId, profile: binding.profile, copyId: binding.senderCopyId }, signal),
      this.copies.read({ groupId: binding.groupId, profile: binding.profile, copyId: binding.recipientCopyId }, signal),
    ]);
    if (!sender || sender.member.signingKeyFingerprint !== message.senderMemberSigningKeyFingerprint) throw new HyperKeyApplicationDeliveryError("Claimed sender Copy is not the authenticated MLS sender");
    if (!recipient || recipient.recipientDeliveryKey !== binding.recipientDeliveryKey) throw new HyperKeyApplicationDeliveryError("Recipient Copy or delivery key is not currently admitted");
    const local = purpose === "send" ? sender : recipient;
    if (message.transition.next.member.signingKeyFingerprint !== local.member.signingKeyFingerprint) throw new HyperKeyApplicationDeliveryError("MLS staged state belongs to the wrong local Copy");
    if (purpose === "send" && !message.transition.outbox.some(record => record.kind === "application" && record.bytes.length === applicationMessage.length && record.bytes.every((byte, index) => byte === applicationMessage[index]))) throw new HyperKeyApplicationDeliveryError("MLS send authentication is not bound to its durable outbox frame");
    const result: AuthenticatedHyperKeyApplicationDelivery = freeze({ binding: freeze({ ...binding }), purpose, senderMemberSigningKeyFingerprint: sender.member.signingKeyFingerprint, recipientMemberSigningKeyFingerprint: recipient.member.signingKeyFingerprint });
    authenticated.add(result);
    return result;
  }
}

export function hyperKeyApplicationTranscript(binding: HyperKeyApplicationDeliveryBinding): Uint8Array {
  assertBinding(binding);
  return canonicalBytes(["hyperkey.application-delivery.v1", binding]);
}

/** Runtime guard used by envelope creation and installation, not just TypeScript. */
export function assertAuthenticatedHyperKeyApplicationDelivery(value: AuthenticatedHyperKeyApplicationDelivery, expected: HyperKeyApplicationDeliveryBinding): void {
  if (!authenticated.has(value) || !sameBinding(value.binding, expected)) throw new HyperKeyApplicationDeliveryError("Delivery is not bound to an authenticated MLS application message");
}

export function assertAuthenticatedHyperKeyApplicationDeliveryFor(value: AuthenticatedHyperKeyApplicationDelivery, expected: HyperKeyApplicationDeliveryBinding, purpose: "send" | "receive"): void {
  assertAuthenticatedHyperKeyApplicationDelivery(value, expected);
  if (value.purpose !== purpose) throw new HyperKeyApplicationDeliveryError("MLS application delivery context has the wrong direction");
}

export function sameBinding(left: HyperKeyApplicationDeliveryBinding, right: HyperKeyApplicationDeliveryBinding): boolean {
  return left.descriptorId === right.descriptorId && left.groupId === right.groupId && left.profile === right.profile && left.senderCopyId === right.senderCopyId && left.recipientCopyId === right.recipientCopyId && left.recipientDeliveryKey === right.recipientDeliveryKey && left.admissionId === right.admissionId && left.selectedCommitId === right.selectedCommitId && left.deliveryId === right.deliveryId;
}

function assertBinding(binding: HyperKeyApplicationDeliveryBinding): void {
  if (!binding || binding.profile !== HYPERKEY_GROUP_PROFILE) throw new HyperKeyApplicationDeliveryError("Invalid HyperKey application delivery profile");
  for (const value of [binding.descriptorId, binding.groupId, binding.senderCopyId, binding.recipientCopyId, binding.recipientDeliveryKey, binding.admissionId, binding.selectedCommitId, binding.deliveryId]) if (typeof value !== "string" || value.length < 1 || value.length > 256) throw new HyperKeyApplicationDeliveryError("Invalid application delivery binding");
}

export class HyperKeyApplicationDeliveryError extends Error { override name = "HyperKeyApplicationDeliveryError"; }
