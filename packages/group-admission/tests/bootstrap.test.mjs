import assert from "node:assert/strict";
import { constants, createCipheriv, createDecipheriv, createHash, generateKeyPairSync, privateDecrypt, publicEncrypt, randomBytes, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import test from "node:test";
import {
  ADMISSION_SCHEMA, encodeAdmissionRequest,
} from "../dist/index.js";
import {
  BootstrapError, BOOTSTRAP_LIMITS, BOOTSTRAP_PRESENTATION_SCHEMA,
  attachBootstrapMembershipRequest, bootstrapPresentationTranscript, cancelBootstrapSession,
  completeBootstrapSession, createBootstrapPresentation, createBootstrapSession, decodeBootstrapPresentation,
  createBootstrapChannelSession, emitBootstrapChannelMessage, handoffBootstrapChannelRequest,
  receiveBootstrapChannelMessage, BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA,
  encodeBootstrapPresentation, inspectBootstrapPresentation,
  recordBootstrapSubmission, resumeBootstrapSession,
} from "@group-foundation/group-admission/bootstrap";
import { canonicalJson, bytesToBase64url } from "@group-foundation/group-core/encoding";

const bytes = value => new TextEncoder().encode(value);
const now = 1_800_000_000_000;
const request = {
  schema: ADMISSION_SCHEMA, requestId: "request-1", invitationId: "invitation-1", scope: "scope-1",
  member: { signingKeyFingerprint: "candidate-fingerprint" }, credential: bytes("credential"),
  keyPackage: bytes("key-package"), keyPackageDigest: "key-package-digest", proof: bytes("candidate-proof"),
  requestedAt: 10, expiresAt: 100,
};
const requestWire = encodeAdmissionRequest(request);
const presentationChannel = { channelSuite: "test-channel-v1", channelOffer: bytes("test-channel-offer") };

function cryptoFixture() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const verificationKey = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
  return {
    entropy: { randomBytes: length => new Uint8Array(randomBytes(length)) },
    hashes: { sha256: async input => new Uint8Array(createHash("sha256").update(input).digest()) },
    signer: { suite: "ed25519-spki-v1", verificationKey, sign: async transcript => new Uint8Array(nodeSign(null, transcript, privateKey)) },
    verifier: { verify: async ({ suite, verificationKey: key, transcript, proof }) => {
      assert.equal(suite, "ed25519-spki-v1");
      assert(nodeVerify(null, transcript, { key: Buffer.from(key), type: "spki", format: "der" }, proof), "bad signature");
    } },
  };
}

function channelFixture(label) {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const offer = new Uint8Array(publicKey.export({ type: "spki", format: "der" }));
  return {
    offer, custodyId: label,
    crypto: {
      suite: "rsa-oaep-sha256-test-v1",
      seal: async ({ recipientOffer, plaintext, aad }) => {
        const key = randomBytes(32); const nonce = randomBytes(12);
        const cipher = createCipheriv("aes-256-gcm", key, nonce); cipher.setAAD(aad);
        const body = Buffer.concat([cipher.update(plaintext), cipher.final()]); const tag = cipher.getAuthTag();
        const wrapped = publicEncrypt({ key: Buffer.from(recipientOffer), type: "spki", format: "der", oaepHash: "sha256", padding: constants.RSA_PKCS1_OAEP_PADDING }, key);
        return new Uint8Array(Buffer.concat([wrapped, nonce, tag, body]));
      },
      open: async ({ localCustodyId, ciphertext, aad }) => {
        assert.equal(localCustodyId, label);
        const wire = Buffer.from(ciphertext); const key = privateDecrypt({ key: privateKey, oaepHash: "sha256", padding: constants.RSA_PKCS1_OAEP_PADDING }, wire.subarray(0, 256));
        const decipher = createDecipheriv("aes-256-gcm", key, wire.subarray(256, 268)); decipher.setAAD(aad); decipher.setAuthTag(wire.subarray(268, 284));
        return new Uint8Array(Buffer.concat([decipher.update(wire.subarray(284)), decipher.final()]));
      },
    },
  };
}

const policy = overrides => ({ nowMs: now + 1, maxLifetimeMs: 60_000, maxFutureSkewMs: 1_000, ...overrides });
const code = expected => error => error instanceof BootstrapError && error.code === expected;
const canonical = value => new TextEncoder().encode(canonicalJson(value));

test("offer-target presentation is canonical, signed, role-bound, and inspectable", async () => {
  const crypto = cryptoFixture();
  const artifact = await createBootstrapPresentation({ mode: "offer-target", target: bytes("opaque target"), ...presentationChannel, createdAtMs: now, expiresAtMs: now + 30_000 }, crypto);
  const inspection = await inspectBootstrapPresentation(artifact.wire, crypto, policy());
  assert.equal(inspection.presentation.mode, "offer-target");
  assert.equal(inspection.presentation.presenterRole, "admission-host");
  assert.equal(inspection.localRole, "candidate");
  assert.equal(inspection.remoteRole, "admission-host");
  assert.equal(inspection.wireSha256, artifact.wireSha256);
  assert.deepEqual(encodeBootstrapPresentation(decodeBootstrapPresentation(artifact.wire)), artifact.wire);
  assert.deepEqual(bootstrapPresentationTranscript(artifact.presentation), bootstrapPresentationTranscript({ ...artifact.presentation, proof: bytes("ignored") }));

  const object = JSON.parse(new TextDecoder().decode(artifact.wire));
  await assert.rejects(inspectBootstrapPresentation(bytes(`${JSON.stringify(object)}\n`), crypto, policy()), code("invalid-wire"));
  await assert.rejects(inspectBootstrapPresentation(canonical({ ...object, extra: true }), crypto, policy()), code("invalid-wire"));
  await assert.rejects(inspectBootstrapPresentation(canonical({ ...object, presenterRole: "candidate" }), crypto, policy()), code("role"));
  const proof = Buffer.from(object.proof, "base64url"); proof[0] ^= 1;
  await assert.rejects(inspectBootstrapPresentation(canonical({ ...object, proof: proof.toString("base64url") }), crypto, policy()), code("crypto"));
  await assert.rejects(inspectBootstrapPresentation(artifact.wire, crypto, policy({ nowMs: now + 30_000 })), code("expired"));
  await assert.rejects(inspectBootstrapPresentation(artifact.wire, crypto, policy({ maxLifetimeMs: 29_999 })), code("expired"));
  await assert.rejects(createBootstrapPresentation({ mode: "offer-target", target: new Uint8Array(BOOTSTRAP_LIMITS.targetBytes + 1), ...presentationChannel, createdAtMs: now, expiresAtMs: now + 1 }, crypto), code("bounds"));
});

test("request-membership presents only candidate bootstrap material before target selection", async () => {
  const crypto = cryptoFixture();
  const artifact = await createBootstrapPresentation({ mode: "request-membership", candidate: bytes("candidate rendezvous"), ...presentationChannel, createdAtMs: now, expiresAtMs: now + 20_000 }, crypto);
  const inspection = await inspectBootstrapPresentation(artifact.wire, crypto, policy());
  assert.equal(inspection.presentation.presenterRole, "candidate");
  assert.equal(inspection.localRole, "admission-host");
  assert.deepEqual(inspection.presentation.candidate, bytes("candidate rendezvous"));
  assert.equal("membershipRequest" in inspection.presentation, false);

  const object = JSON.parse(new TextDecoder().decode(artifact.wire));
  await assert.rejects(inspectBootstrapPresentation(canonical({ ...object, mode: "offer-target" }), crypto, policy()), code("invalid-wire"));
});

test("offer-target session hands off one exact request and replays exact transitions", async () => {
  const crypto = cryptoFixture();
  const artifact = await createBootstrapPresentation({ mode: "offer-target", target: bytes("target"), ...presentationChannel, createdAtMs: now, expiresAtMs: now + 10_000 }, crypto);
  const inspection = await inspectBootstrapPresentation(artifact.wire, crypto, policy());
  const candidate = createBootstrapSession(inspection, "candidate");
  assert.equal(candidate.phase, "open");
  const candidateReady = await attachBootstrapMembershipRequest(candidate, requestWire, crypto.hashes, now + 2);
  assert.equal(candidateReady.state.phase, "request-ready");
  await assert.rejects(async () => recordBootstrapSubmission(candidateReady.state, request.requestId, now + 3), code("role"));

  const host = createBootstrapSession(inspection, "admission-host");
  const ready = await attachBootstrapMembershipRequest(host, requestWire, crypto.hashes, now + 2);
  assert.equal(ready.replayed, false);
  const requestReplay = await attachBootstrapMembershipRequest(ready.state, requestWire, crypto.hashes, now + 3);
  assert.equal(requestReplay.replayed, true);
  const changed = encodeAdmissionRequest({ ...request, requestId: "request-2" });
  await assert.rejects(attachBootstrapMembershipRequest(ready.state, changed, crypto.hashes, now + 3), code("replay"));

  const submitted = recordBootstrapSubmission(ready.state, request.requestId, now + 4);
  assert.equal(submitted.state.phase, "submitted");
  assert.equal(recordBootstrapSubmission(submitted.state, request.requestId, now + 9_999).replayed, true);
  assert.throws(() => recordBootstrapSubmission(submitted.state, "other-request", now + 5), code("replay"));
  assert.throws(() => cancelBootstrapSession(submitted.state, "cancel-after-submit", "admission-host", now + 5), code("transition"));
  const completed = completeBootstrapSession(submitted.state, "admission-result-1", now + 20_000);
  assert.equal(completed.state.phase, "completed", "admission completion can outlive the presentation after durable handoff");
  assert.equal(completeBootstrapSession(completed.state, "admission-result-1", now + 30_000).replayed, true);
  assert.throws(() => completeBootstrapSession(completed.state, "changed-result", now + 30_000), code("replay"));
});

test("request-mode host session waits for the target-bound request", async () => {
  const crypto = cryptoFixture();
  const artifact = await createBootstrapPresentation({ mode: "request-membership", candidate: bytes("candidate"), ...presentationChannel, createdAtMs: now, expiresAtMs: now + 10_000 }, crypto);
  const inspection = await inspectBootstrapPresentation(artifact.wire, crypto, policy());
  const host = createBootstrapSession(inspection, "admission-host");
  assert.equal(host.phase, "open");
  const ready = await attachBootstrapMembershipRequest(host, requestWire, crypto.hashes, now + 2);
  assert.equal(ready.state.phase, "request-ready");
  assert.throws(() => recordBootstrapSubmission(ready.state, "different", now + 2), code("replay"));
  assert.equal(recordBootstrapSubmission(ready.state, request.requestId, now + 2).state.phase, "submitted");
});

test("resume detects reuse, expires live state, and cancellation is terminal and replay-safe", async () => {
  const crypto = cryptoFixture();
  const artifact = await createBootstrapPresentation({ mode: "offer-target", target: bytes("target"), ...presentationChannel, createdAtMs: now, expiresAtMs: now + 100 }, crypto);
  const inspection = await inspectBootstrapPresentation(artifact.wire, crypto, policy({ maxLifetimeMs: 100 }));
  const host = createBootstrapSession(inspection, "admission-host");
  const resumed = await resumeBootstrapSession(host, artifact.wire, crypto, now + 50);
  assert.equal(resumed.replayed, true);
  const expired = await resumeBootstrapSession(host, artifact.wire, crypto, now + 100);
  assert.equal(expired.state.phase, "expired");
  assert.equal((await resumeBootstrapSession(expired.state, artifact.wire, crypto, now + 200)).replayed, true);

  const cancelled = cancelBootstrapSession(host, "cancel-1", "admission-host", now + 50);
  assert.equal(cancelled.state.phase, "cancelled");
  assert.equal(cancelBootstrapSession(cancelled.state, "cancel-1", "admission-host", now + 60).replayed, true);
  assert.throws(() => cancelBootstrapSession(cancelled.state, "cancel-2", "admission-host", now + 60), code("replay"));

  const alternateUnsigned = { ...artifact.presentation, target: bytes("changed target") };
  const alternate = { ...alternateUnsigned, proof: await crypto.signer.sign(bootstrapPresentationTranscript(alternateUnsigned)) };
  const alternateWire = encodeBootstrapPresentation(alternate);
  await assert.rejects(resumeBootstrapSession(host, alternateWire, crypto, now + 50), code("replay"));

  const object = JSON.parse(new TextDecoder().decode(artifact.wire));
  assert.equal(object.schema, BOOTSTRAP_PRESENTATION_SCHEMA);
  assert.equal(bytesToBase64url(Buffer.from(object.sessionId, "base64url")), object.sessionId);
});

test("candidate-first encrypted channel selects target before exact admission handoff", async () => {
  const signing = cryptoFixture(); const candidateKeys = channelFixture("candidate-custody"); const hostKeys = channelFixture("host-custody");
  const artifact = await createBootstrapPresentation({
    mode: "request-membership", candidate: bytes("candidate rendezvous only"), channelSuite: candidateKeys.crypto.suite,
    channelOffer: candidateKeys.offer, createdAtMs: now, expiresAtMs: now + 20_000,
  }, signing);
  const inspection = await inspectBootstrapPresentation(artifact.wire, signing, policy());
  let candidate = await createBootstrapChannelSession(inspection, "candidate", { custodyId: candidateKeys.custodyId, offer: candidateKeys.offer, suite: candidateKeys.crypto.suite }, signing.hashes);
  let host = await createBootstrapChannelSession(inspection, "admission-host", { custodyId: hostKeys.custodyId, offer: hostKeys.offer, suite: hostKeys.crypto.suite }, signing.hashes);
  const candidateDeps = { crypto: candidateKeys.crypto, hashes: signing.hashes };
  const hostDeps = { crypto: hostKeys.crypto, hashes: signing.hashes };

  const hostHello = await emitBootstrapChannelMessage(host, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "peer-hello", channelOffer: hostKeys.offer }, hostDeps, now + 2);
  host = hostHello.state;
  const alteredPredecessor = JSON.parse(new TextDecoder().decode(hostHello.wire));
  alteredPredecessor.previousTranscriptSha256 = bytesToBase64url(new Uint8Array(32));
  await assert.rejects(receiveBootstrapChannelMessage(candidate, canonical(alteredPredecessor), candidateDeps, now + 3), code("replay"));
  const alteredCiphertext = JSON.parse(new TextDecoder().decode(hostHello.wire));
  const alteredBytes = Buffer.from(alteredCiphertext.ciphertext, "base64url"); alteredBytes[alteredBytes.length - 1] ^= 1;
  alteredCiphertext.ciphertext = alteredBytes.toString("base64url");
  await assert.rejects(receiveBootstrapChannelMessage(candidate, canonical(alteredCiphertext), candidateDeps, now + 3), code("crypto"));
  const candidateHelloReceived = await receiveBootstrapChannelMessage(candidate, hostHello.wire, candidateDeps, now + 3);
  candidate = candidateHelloReceived.state;
  await assert.rejects(receiveBootstrapChannelMessage(candidate, hostHello.wire, candidateDeps, now + 3), code("replay"));

  const candidateHello = await emitBootstrapChannelMessage(candidate, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "peer-hello", channelOffer: candidateKeys.offer }, candidateDeps, now + 4);
  candidate = candidateHello.state;
  host = (await receiveBootstrapChannelMessage(host, candidateHello.wire, hostDeps, now + 5)).state;

  const target = await emitBootstrapChannelMessage(host, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "target-selection", target: bytes("host-selected target") }, hostDeps, now + 6);
  host = target.state;
  assert.equal(new TextDecoder().decode(target.wire).includes("host-selected target"), false, "target stays encrypted");
  candidate = (await receiveBootstrapChannelMessage(candidate, target.wire, candidateDeps, now + 7)).state;

  const candidatePayload = await emitBootstrapChannelMessage(candidate, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "candidate-payload", candidate: bytes("target-bound candidate evidence") }, candidateDeps, now + 8);
  candidate = candidatePayload.state;
  host = (await receiveBootstrapChannelMessage(host, candidatePayload.wire, hostDeps, now + 9)).state;

  const accepted = await emitBootstrapChannelMessage(host, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "acceptance", acceptance: bytes("candidate accepted for request construction") }, hostDeps, now + 10);
  host = accepted.state;
  candidate = (await receiveBootstrapChannelMessage(candidate, accepted.wire, candidateDeps, now + 11)).state;

  const requestEmission = await emitBootstrapChannelMessage(candidate, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "admission-request", request: requestWire }, candidateDeps, now + 12);
  candidate = requestEmission.state;
  const requestReception = await receiveBootstrapChannelMessage(host, requestEmission.wire, hostDeps, now + 13);
  host = requestReception.state;
  assert.equal(requestReception.admissionRequest.requestId, request.requestId);
  assert.deepEqual(host.requestWire, requestWire);
  assert.equal(candidate.terminal, true);

  const admissionHost = createBootstrapSession(inspection, "admission-host");
  const ready = await handoffBootstrapChannelRequest(host, admissionHost, signing.hashes, now + 14);
  assert.equal(ready.state.phase, "request-ready");
  assert.deepEqual(ready.state.requestWire, requestWire);
});

test("offer-target channel preserves host-presented direction and terminal rejection", async () => {
  const signing = cryptoFixture(); const hostKeys = channelFixture("offer-host"); const candidateKeys = channelFixture("offer-candidate");
  const artifact = await createBootstrapPresentation({ mode: "offer-target", target: bytes("offered target"), channelSuite: hostKeys.crypto.suite, channelOffer: hostKeys.offer, createdAtMs: now, expiresAtMs: now + 1_000 }, signing);
  const inspection = await inspectBootstrapPresentation(artifact.wire, signing, policy());
  let host = await createBootstrapChannelSession(inspection, "admission-host", { custodyId: hostKeys.custodyId, offer: hostKeys.offer, suite: hostKeys.crypto.suite }, signing.hashes);
  let candidate = await createBootstrapChannelSession(inspection, "candidate", { custodyId: candidateKeys.custodyId, offer: candidateKeys.offer, suite: candidateKeys.crypto.suite }, signing.hashes);
  const hostDeps = { crypto: hostKeys.crypto, hashes: signing.hashes }; const candidateDeps = { crypto: candidateKeys.crypto, hashes: signing.hashes };
  await assert.rejects(emitBootstrapChannelMessage(candidate, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "peer-hello", channelOffer: candidateKeys.offer }, candidateDeps, now + 1_000), code("expired"));

  const candidateHello = await emitBootstrapChannelMessage(candidate, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "peer-hello", channelOffer: candidateKeys.offer }, candidateDeps, now + 1);
  candidate = candidateHello.state; host = (await receiveBootstrapChannelMessage(host, candidateHello.wire, hostDeps, now + 2)).state;
  const hostHello = await emitBootstrapChannelMessage(host, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "peer-hello", channelOffer: hostKeys.offer }, hostDeps, now + 3);
  host = hostHello.state; candidate = (await receiveBootstrapChannelMessage(candidate, hostHello.wire, candidateDeps, now + 4)).state;
  await assert.rejects(emitBootstrapChannelMessage(candidate, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "target-selection", target: bytes("changed") }, candidateDeps, now + 5), code("role"));

  const payload = await emitBootstrapChannelMessage(candidate, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "candidate-payload", candidate: bytes("candidate evidence") }, candidateDeps, now + 6);
  candidate = payload.state; host = (await receiveBootstrapChannelMessage(host, payload.wire, hostDeps, now + 7)).state;
  const rejection = await emitBootstrapChannelMessage(host, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "rejection", rejectionCode: "product-policy" }, hostDeps, now + 8);
  host = rejection.state; candidate = (await receiveBootstrapChannelMessage(candidate, rejection.wire, candidateDeps, now + 9)).state;
  assert.equal(host.terminal, true); assert.equal(candidate.decision, "rejected");
  await assert.rejects(emitBootstrapChannelMessage(candidate, { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: "progress", progressCode: "late" }, candidateDeps, now + 10), code("transition"));
});
