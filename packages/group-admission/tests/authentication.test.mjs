import assert from "node:assert/strict";
import test from "node:test";
import { createHash, generateKeyPairSync, sign, verify } from "node:crypto";
import { ADMISSION_SCHEMA, INSTALLATION_SCHEMA, OUTBOX_SCHEMA, admissionRequestTranscript, actingMemberTranscript,
  recipientInstallationTranscript, encodeActorProof, TranscriptActorAuthentication, TranscriptInstallationAuthentication,
  encodeAdmissionRequest, encodePublicSelection } from "../dist/index.js";
const bytes = value => new TextEncoder().encode(value);
const member = { signingKeyFingerprint: "member:owner" };
const group = { scope: "generic scope", revision: 0, epoch: "0", predecessor: "initial" };
const candidate = { schema: ADMISSION_SCHEMA, requestId: "request", invitationId: "invitation", scope: group.scope,
  member: { signingKeyFingerprint: "member:candidate" }, credential: bytes("opaque credential"), keyPackage: bytes("key package"), keyPackageDigest: "digest", requestedAt: 1, expiresAt: 100, proof: bytes("proof") };
function signer(member) {
  const key = generateKeyPairSync("ed25519");
  return { sign(transcript) { return new Uint8Array(sign(null, transcript, key.privateKey)); },
    port: { async verify(expected, transcript, proof) {
      if (expected.signingKeyFingerprint !== member.signingKeyFingerprint || !verify(null, transcript, key.publicKey, proof)) throw new Error("member binding or signature invalid");
    } } };
}

test("candidate transcript binds every field including optional opaque delivery binding and excludes proof", () => {
  const transcript = admissionRequestTranscript(candidate);
  assert.deepEqual(admissionRequestTranscript({ ...candidate, proof: bytes("different proof") }), transcript);
  for (const change of [ { requestId: "changed" }, { scope: "changed" }, { invitationId: "changed" }, { member }, { credential: bytes("changed") },
    { keyPackage: bytes("changed") }, { keyPackageDigest: "changed" }, { requestedAt: 2 }, { expiresAt: 101 }, { deliveryBinding: bytes("arbitrary host binding") } ]) {
    assert.notDeepEqual(admissionRequestTranscript({ ...candidate, ...change }), transcript);
  }
  assert.match(new TextDecoder().decode(transcript), /group-foundation.admission.candidate-proof.v1/u);
});

test("real actor signatures bind action, target, cursor, exact operation payload, actor, deadline", async () => {
  const owner = signer(member), authentication = new TranscriptActorAuthentication(owner.port, 50);
  const input = { action: "add", targetId: candidate.requestId, group, member, payload: encodeAdmissionRequest(candidate), expiresAt: 40 };
  const actor = { member, authentication: encodeActorProof(owner.sign(actingMemberTranscript(input)), 40) };
  assert.deepEqual(await authentication.verify({ ...input, actor, now: 2 }), member);
  for (const change of [{ action: "approve" }, { action: "remove" }, { targetId: "other" }, { group: { ...group, revision: 1 } },
    { group: { ...group, epoch: "1" } }, { group: { ...group, predecessor: "changed" } }, { group: { ...group, scope: "changed" } },
    { payload: encodeAdmissionRequest({ ...candidate, keyPackage: bytes("substituted") }) }, { actor: { ...actor, member: candidate.member } }, { now: 40 }, { now: 0, actor: { ...actor, authentication: encodeActorProof(owner.sign(actingMemberTranscript({ ...input, expiresAt: 51 })), 51) } }]) {
    await assert.rejects(authentication.verify({ ...input, actor, now: 2, ...change }));
  }
  const old = bytes(JSON.stringify({ schema: "zagel.group.acting-member.v1", expiresAt: 40, proof: "AQ" }));
  await assert.rejects(authentication.verify({ ...input, actor: { ...actor, authentication: old }, now: 2 }));
});

test("installation transcript authenticates all receipt fields and proof holder independently of candidate expiry", async () => {
  const candidateSigner = signer(candidate.member), auth = new TranscriptInstallationAuthentication(candidateSigner.port);
  const selection = { schema: OUTBOX_SCHEMA, kind: "add", operationId: candidate.requestId, operationHash: "operation hash", retryId: "retry", transitionId: "transition",
    custodyDigest: "custody digest", expected: group, next: { ...group, revision: 1, epoch: "1", predecessor: "next" }, authorityRevision: "policy revision", candidateRevision: "candidate revision", commit: bytes("commit"), welcome: bytes("welcome") };
  const wire = encodePublicSelection(selection), selected = { selection, wire, wireHash: createHash("sha256").update(wire).digest("base64url"), stageHash: "stage" };
  const unsigned = { schema: INSTALLATION_SCHEMA, operationId: candidate.requestId, scope: group.scope, selectedWireHash: selected.wireHash, successor: "next", recipient: candidate.member, installedAt: 3 };
  const receipt = { ...unsigned, acknowledgement: candidateSigner.sign(recipientInstallationTranscript(unsigned)) };
  await auth.verify({ receipt, request: candidate, selected, now: 1000 });
  assert.deepEqual(recipientInstallationTranscript({ ...receipt, acknowledgement: bytes("not signed") }), recipientInstallationTranscript(unsigned));
  for (const mutation of [{ scope: "changed" }, { operationId: "changed" }, { selectedWireHash: "changed" }, { successor: "changed" },
    { recipient: member }, { installedAt: 4 }, { acknowledgement: bytes("forged") }]) {
    await assert.rejects(auth.verify({ receipt: { ...receipt, ...mutation }, request: candidate, selected, now: 1000 }));
  }
});
