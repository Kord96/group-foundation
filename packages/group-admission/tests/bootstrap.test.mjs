import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, randomBytes, sign as nodeSign, verify as nodeVerify } from "node:crypto";
import test from "node:test";
import {
  ADMISSION_SCHEMA, encodeAdmissionRequest,
} from "../dist/index.js";
import {
  BootstrapError, BOOTSTRAP_LIMITS, BOOTSTRAP_PRESENTATION_SCHEMA,
  attachBootstrapMembershipRequest, bootstrapPresentationTranscript, cancelBootstrapSession,
  completeBootstrapSession, createBootstrapPresentation, createBootstrapSession, decodeBootstrapPresentation,
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

const policy = overrides => ({ nowMs: now + 1, maxLifetimeMs: 60_000, maxFutureSkewMs: 1_000, ...overrides });
const code = expected => error => error instanceof BootstrapError && error.code === expected;
const canonical = value => new TextEncoder().encode(canonicalJson(value));

test("offer-target presentation is canonical, signed, role-bound, and inspectable", async () => {
  const crypto = cryptoFixture();
  const artifact = await createBootstrapPresentation({ mode: "offer-target", target: bytes("opaque target"), createdAtMs: now, expiresAtMs: now + 30_000 }, crypto);
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
  await assert.rejects(createBootstrapPresentation({ mode: "offer-target", target: new Uint8Array(BOOTSTRAP_LIMITS.targetBytes + 1), createdAtMs: now, expiresAtMs: now + 1 }, crypto), code("bounds"));
});

test("request-membership embeds one exact canonical AdmissionRequest", async () => {
  const crypto = cryptoFixture();
  const artifact = await createBootstrapPresentation({ mode: "request-membership", membershipRequest: requestWire, createdAtMs: now, expiresAtMs: now + 20_000 }, crypto);
  const inspection = await inspectBootstrapPresentation(artifact.wire, crypto, policy());
  assert.equal(inspection.presentation.presenterRole, "candidate");
  assert.equal(inspection.localRole, "admission-host");
  assert.equal(inspection.membershipRequest.requestId, request.requestId);
  assert.deepEqual(inspection.presentation.membershipRequest, requestWire);

  const noncanonicalRequest = bytes(new TextDecoder().decode(requestWire) + "\n");
  await assert.rejects(createBootstrapPresentation({ mode: "request-membership", membershipRequest: noncanonicalRequest, createdAtMs: now, expiresAtMs: now + 1 }, crypto), error => error.code === "invalid-wire");
  const object = JSON.parse(new TextDecoder().decode(artifact.wire));
  await assert.rejects(inspectBootstrapPresentation(canonical({ ...object, mode: "offer-target" }), crypto, policy()), code("invalid-wire"));
});

test("offer-target session hands off one exact request and replays exact transitions", async () => {
  const crypto = cryptoFixture();
  const artifact = await createBootstrapPresentation({ mode: "offer-target", target: bytes("target"), createdAtMs: now, expiresAtMs: now + 10_000 }, crypto);
  const inspection = await inspectBootstrapPresentation(artifact.wire, crypto, policy());
  const candidate = await createBootstrapSession(inspection, "candidate", crypto.hashes);
  assert.equal(candidate.phase, "open");
  const candidateReady = await attachBootstrapMembershipRequest(candidate, requestWire, crypto.hashes, now + 2);
  assert.equal(candidateReady.state.phase, "request-ready");
  await assert.rejects(async () => recordBootstrapSubmission(candidateReady.state, request.requestId, now + 3), code("role"));

  const host = await createBootstrapSession(inspection, "admission-host", crypto.hashes);
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

test("request-mode host session starts ready and submission is bound to request ID", async () => {
  const crypto = cryptoFixture();
  const artifact = await createBootstrapPresentation({ mode: "request-membership", membershipRequest: requestWire, createdAtMs: now, expiresAtMs: now + 10_000 }, crypto);
  const inspection = await inspectBootstrapPresentation(artifact.wire, crypto, policy());
  const host = await createBootstrapSession(inspection, "admission-host", crypto.hashes);
  assert.equal(host.phase, "request-ready");
  assert.deepEqual(host.requestWire, requestWire);
  assert.throws(() => recordBootstrapSubmission(host, "different", now + 2), code("replay"));
  assert.equal(recordBootstrapSubmission(host, request.requestId, now + 2).state.phase, "submitted");
  await assert.rejects(attachBootstrapMembershipRequest(host, requestWire, crypto.hashes, now + 2), code("transition"));
});

test("resume detects reuse, expires live state, and cancellation is terminal and replay-safe", async () => {
  const crypto = cryptoFixture();
  const artifact = await createBootstrapPresentation({ mode: "offer-target", target: bytes("target"), createdAtMs: now, expiresAtMs: now + 100 }, crypto);
  const inspection = await inspectBootstrapPresentation(artifact.wire, crypto, policy({ maxLifetimeMs: 100 }));
  const host = await createBootstrapSession(inspection, "admission-host", crypto.hashes);
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
