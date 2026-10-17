import type { ActorAuthenticationInput, ActorAuthenticationPort, MemberIdentity, InstallationAuthenticationPort } from "./contracts.js";
import { LIMITS } from "./contracts.js";
import { encodeJson, bytesToBase64url, base64urlToBytes, instant, identifier, validateMember, validateCursor, sameBytes, byteField, fail, recipientInstallationTranscript } from "./wire.js";

const ACTOR_PROOF_SCHEMA = "group-foundation.admission.actor-proof.v1";
export interface SignatureVerificationPort {
  /** Must verify signature AND the claimed member's binding to its signing key. */
  verify(member: MemberIdentity, transcript: Uint8Array, proof: Uint8Array): Promise<void>;
}
/** Full operation, cursor, actor and deadline are signed; payload is exact canonical operation wire. */
export function actingMemberTranscript(input: Omit<ActorAuthenticationInput, "actor" | "now"> & { member: MemberIdentity; expiresAt: number }): Uint8Array {
  if (!["issue", "revoke", "approve", "deny", "cancel", "add", "remove", "accept"].includes(input.action)) fail("actor", "unknown management action");
  identifier(input.targetId); validateCursor(input.group); validateMember(input.member); instant(input.expiresAt); byteField(input.payload, LIMITS.wireBytes);
  return encodeJson({ domain: "group-foundation.admission.actor.v1", action: input.action, targetId: input.targetId, group: { ...input.group }, member: { ...input.member }, payload: bytesToBase64url(input.payload), expiresAt: input.expiresAt });
}
export function encodeActorProof(proof: Uint8Array, expiresAt: number): Uint8Array {
  instant(expiresAt); byteField(proof, LIMITS.proofBytes);
  return encodeJson({ schema: ACTOR_PROOF_SCHEMA, expiresAt, proof: bytesToBase64url(proof) });
}
export class TranscriptActorAuthentication implements ActorAuthenticationPort {
  constructor(private readonly signatures: SignatureVerificationPort, private readonly maxLifetime: number) { if (instant(maxLifetime) < 1) fail("actor", "proof lifetime must be positive"); }
  async verify(input: ActorAuthenticationInput): Promise<MemberIdentity> {
    byteField(input.actor.authentication, LIMITS.proofBytes);
    let row: { schema: string; expiresAt: number; proof: string };
    try { row = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(input.actor.authentication)); } catch { return fail("actor", "invalid actor proof"); }
    if (!row || typeof row !== "object" || Object.keys(row).sort().join(",") !== "expiresAt,proof,schema" || row.schema !== ACTOR_PROOF_SCHEMA) fail("actor", "unsupported actor proof");
    instant(row.expiresAt); instant(input.now);
    if (row.expiresAt <= input.now || row.expiresAt - input.now > this.maxLifetime || typeof row.proof !== "string") fail("actor", "actor proof expired or exceeds lifetime");
    let proof: Uint8Array;
    try { proof = base64urlToBytes(row.proof, LIMITS.proofBytes, "proof"); } catch { return fail("actor", "invalid actor proof bytes"); }
    if (!sameBytes(encodeActorProof(proof, row.expiresAt), input.actor.authentication)) fail("actor", "actor proof must be canonical");
    const member = validateMember(input.actor.member);
    await this.signatures.verify(member, actingMemberTranscript({ ...input, member, expiresAt: row.expiresAt }), proof);
    return member;
  }
}
export class TranscriptInstallationAuthentication implements InstallationAuthenticationPort {
  constructor(private readonly signatures: SignatureVerificationPort) {}
  async verify({ receipt, request, selected, now }: Parameters<InstallationAuthenticationPort["verify"]>[0]): Promise<void> {
    if (receipt.operationId !== request.requestId || receipt.operationId !== selected.selection.operationId || receipt.scope !== request.scope || receipt.scope !== selected.selection.next.scope || receipt.recipient.signingKeyFingerprint !== request.member.signingKeyFingerprint || receipt.selectedWireHash !== selected.wireHash || receipt.successor !== selected.selection.next.predecessor || receipt.installedAt > now || selected.selection.kind !== "add") fail("installation", "receipt differs from selected Add");
    await this.signatures.verify(receipt.recipient, recipientInstallationTranscript(receipt), receipt.acknowledgement);
  }
}
