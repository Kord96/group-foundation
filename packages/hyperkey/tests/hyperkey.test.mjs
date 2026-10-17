import assert from "node:assert/strict";
import test from "node:test";

const hyperkey = await import(new URL("../dist/index.js", import.meta.url));
const testing = await import(new URL("../dist/testing.js", import.meta.url));
import { AdmissionProviderFixture } from "./support/admission-provider.mjs";

const identifier = () => hyperkey.base64url(crypto.getRandomValues(new Uint8Array(32)));
const bytes = value => new TextEncoder().encode(value);
const acting = {member:{signingKeyFingerprint:identifier()},authentication:bytes("explicit-test-actor")};
function stagedAuthentication(direction, binding, message, sender) {
 return {schema:"group-foundation.group.native-transition.v1",transitionId:identifier(),kind:direction === "send" ? "application-send" : "application-receive",expectedRevision:0,next:{schema:"group-foundation.group.native-state.v1",groupId:binding.groupId,profile:binding.profile,member:{signingKeyFingerprint:sender},revision:1,epoch:"1",snapshot:bytes("explicit-test-native-state")},outbox:direction === "send" ? [{id:identifier(),kind:"application",bytes:message,digest:identifier()}] : []};
}
async function acknowledge(flow, admissionId) {
 const request = flow.provider.requests.get(admissionId);
 return flow.admissions.acknowledgeCanonicalInstallation({admissionId,groupId:request.groupId,selectedCommitId:flow.provider.selected.get(admissionId),recipient:request.copy.member,proof:bytes("explicit-test-installation-proof"),installedAtMs:1000});
}

async function deliveryKeyPair() {
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}
async function enrolledCopy() {
  const key = await deliveryKeyPair();
  return { key, copy: { copyId: identifier(), member: { signingKeyFingerprint: identifier() }, keyPackageDigest: identifier(), recipientDeliveryKey: hyperkey.base64url(key.publicKey) } };
}
async function context(descriptor, flow, recipient, sender, admissionId, selectedCommitId, deliveryId = crypto.getRandomValues(new Uint8Array(32))) {
  flow.directory.put(descriptor.groupId, sender.copy);
  flow.directory.put(descriptor.groupId, recipient.copy);
  const descriptorId = await hyperkey.hyperKeyDescriptorId(descriptor);
  const binding = { descriptorId, groupId: descriptor.groupId, profile: hyperkey.HYPERKEY_GROUP_PROFILE, senderCopyId: sender.copy.copyId, recipientCopyId: recipient.copy.copyId, recipientDeliveryKey: hyperkey.base64url(recipient.key.publicKey), admissionId, selectedCommitId, deliveryId: hyperkey.base64url(deliveryId) };
  const applicationMessage = hyperkey.hyperKeyApplicationTranscript(binding);
  flow.setMlsSender(sender.copy.member.signingKeyFingerprint);
  const authenticatedSender = await flow.boundary.authenticateForSend(binding, applicationMessage);
  const authenticatedRecipient = await flow.boundary.authenticateForReceive(binding, applicationMessage);
  return { descriptor, admissions: flow.admissions, recipientCopyId: recipient.copy.copyId, senderCopyId: sender.copy.copyId, admissionId, selectedCommitId, recipientDeliveryKey: recipient.key.publicKey, deliveryId, authenticatedSender, authenticatedRecipient, outbox: flow.outbox, applicationMessage };
}

/** Explicit admission provider fixture; generic admission has its own tests. */
async function composeAdmissions(groupId) {
  let clock = 1_000;
  const records = new testing.InMemoryHyperKeyCopyAdmissionRecordStore();
  const directory = new testing.InMemoryHyperKeyAdmittedCopyDirectory();
  const outbox = new testing.InMemoryHyperKeyPrivateDeliveryOutbox();
  const provider = new AdmissionProviderFixture();
  const invitationId = identifier();
  let mlsSender;
  const mls = { async authenticate({ direction, applicationMessage, expectedPlaintext }) {
    assert.deepEqual(applicationMessage, expectedPlaintext, "fixture only accepts an authenticated MLS application payload");
    const [, binding] = JSON.parse(new TextDecoder().decode(applicationMessage));
    const local = direction === "send" ? mlsSender : (await directory.read({groupId:binding.groupId,profile:binding.profile,copyId:binding.recipientCopyId})).member.signingKeyFingerprint;
    return { groupId: binding.groupId, profile: binding.profile, senderMemberSigningKeyFingerprint: mlsSender,transition:stagedAuthentication(direction,binding,applicationMessage,local) };
  } };
  const boundary = new hyperkey.HyperKeyApplicationDeliveryBoundary(mls, directory);
  return { admissions: new hyperkey.HyperKeyCopyAdmissions(provider, records), provider, invitationId, now: () => clock++, directory, outbox, boundary, setMlsSender(value) { mlsSender = value; } };
}

async function admit(admissions, invitationId, groupId, recipient, now) {
  const admissionId = identifier();
  await admissions.request({ admissionId, groupId, invitationId, copy: recipient.copy, evidence: new Uint8Array([7, 8]), keyPackage: bytes("candidate-key-package"), proof: bytes("candidate-proof"), requestedAtMs: now(), expiresAtMs: 7_000 });
  const { selectedCommitId } = await admissions.approve(groupId, recipient.copy.copyId, admissionId, {approval:acting,selection:acting});
  return { admissionId, selectedCommitId };
}

test("a Copy reaches HyperKey custody only after the provider confirms durable installation", async () => {
  const founder = await enrolledCopy(), recipient = await enrolledCopy(), groupId = identifier();
  assert.notEqual(recipient.copy.copyId, recipient.copy.member.signingKeyFingerprint, "Copy identity is not Group member identity");
  const conventional = await hyperkey.generateEd25519SeedPair();
  const { descriptor, id: descriptorId } = await hyperkey.createHyperKeyDescriptor(groupId, conventional.publicKey);
  const flow = await composeAdmissions(groupId);
  const admitted = await admit(flow.admissions, flow.invitationId, groupId, recipient, flow.now);
  const deliveryContext = await context(descriptor, flow, recipient, founder, admitted.admissionId, admitted.selectedCommitId);

  await assert.rejects(hyperkey.createPrivateSeedDelivery(deliveryContext, conventional.seed), /not canonical and durable/u, "the conventional seed cannot authorize admission or premature delivery");
  await acknowledge(flow, admitted.admissionId, flow.now());
  const delivery = await hyperkey.createPrivateSeedDelivery(deliveryContext, conventional.seed);
  const custody = new hyperkey.InMemoryHyperKeySeedCustody();
  const receipt = await hyperkey.installPrivateSeedDelivery({ delivery, descriptor, recipientPrivateDeliveryKey: recipient.key.privateKey, authenticatedSender: deliveryContext.authenticatedRecipient, admissions: flow.admissions, state: new hyperkey.InMemoryHyperKeyLocalState(), custody });

  assert.equal(flow.provider.installed.get(admitted.admissionId).recipient.signingKeyFingerprint, recipient.copy.member.signingKeyFingerprint);
  assert.equal(receipt.copyId, recipient.copy.copyId);
  assert.deepEqual(custody.testingRead(descriptorId, recipient.copy.copyId), conventional.seed);
});

test("independently enrolled Copies retain distinct Group members while receiving one immutable HyperKey", async () => {
  const founder = await enrolledCopy(), first = await enrolledCopy(), second = await enrolledCopy(), groupId = identifier();
  const conventional = await hyperkey.generateEd25519SeedPair(), { descriptor, id } = await hyperkey.createHyperKeyDescriptor(groupId, conventional.publicKey);
  const flow = await composeAdmissions(groupId);
  const firstAdmission = await admit(flow.admissions, flow.invitationId, groupId, first, flow.now);
  const secondAdmission = await admit(flow.admissions, flow.invitationId, groupId, second, flow.now);
  await acknowledge(flow, firstAdmission.admissionId, flow.now());
  await acknowledge(flow, secondAdmission.admissionId, flow.now());
  const firstContext = await context(descriptor, flow, first, founder, firstAdmission.admissionId, firstAdmission.selectedCommitId);
  const secondContext = await context(descriptor, flow, second, founder, secondAdmission.admissionId, secondAdmission.selectedCommitId);
  const firstDelivery = await hyperkey.createPrivateSeedDelivery(firstContext, conventional.seed);
  const secondDelivery = await hyperkey.createPrivateSeedDelivery(secondContext, conventional.seed);
  const firstCustody = new hyperkey.InMemoryHyperKeySeedCustody(), secondCustody = new hyperkey.InMemoryHyperKeySeedCustody();
  await hyperkey.installPrivateSeedDelivery({ delivery: firstDelivery, descriptor, recipientPrivateDeliveryKey: first.key.privateKey, authenticatedSender: firstContext.authenticatedRecipient, admissions: flow.admissions, state: new hyperkey.InMemoryHyperKeyLocalState(), custody: firstCustody });
  await hyperkey.installPrivateSeedDelivery({ delivery: secondDelivery, descriptor, recipientPrivateDeliveryKey: second.key.privateKey, authenticatedSender: secondContext.authenticatedRecipient, admissions: flow.admissions, state: new hyperkey.InMemoryHyperKeyLocalState(), custody: secondCustody });
  assert.notEqual(first.copy.copyId, second.copy.copyId);
  assert.notEqual(first.copy.member.signingKeyFingerprint, second.copy.member.signingKeyFingerprint);
  assert.deepEqual(firstCustody.testingRead(id, first.copy.copyId), conventional.seed);
  assert.deepEqual(secondCustody.testingRead(id, second.copy.copyId), conventional.seed);
  const message = bytes("one logical conventional signing key");
  const firstSeed = firstCustody.testingRead(id, first.copy.copyId), secondSeed = secondCustody.testingRead(id, second.copy.copyId);
  try {
    const firstSignature = await hyperkey.signEd25519(firstSeed, message);
    const secondSignature = await hyperkey.signEd25519(secondSeed, message);
    assert.deepEqual(firstSignature, secondSignature);
    assert.equal(await hyperkey.verifyEd25519(conventional.publicKey, message, firstSignature), true);
    assert.equal(await hyperkey.verifyEd25519(conventional.publicKey, message, secondSignature), true);
  } finally { firstSeed.fill(0); secondSeed.fill(0); }
});

test("exact Group-backed delivery retries idempotently, but altered ciphertext and changed envelope fail", async () => {
  const founder = await enrolledCopy(), recipient = await enrolledCopy(), groupId = identifier();
  const conventional = await hyperkey.generateEd25519SeedPair();
  const { descriptor } = await hyperkey.createHyperKeyDescriptor(groupId, conventional.publicKey);
  const flow = await composeAdmissions(groupId), admitted = await admit(flow.admissions, flow.invitationId, groupId, recipient, flow.now);
  await acknowledge(flow, admitted.admissionId, flow.now());
  const deliveryContext = await context(descriptor, flow, recipient, founder, admitted.admissionId, admitted.selectedCommitId);
  const delivery = await hyperkey.createPrivateSeedDelivery(deliveryContext, conventional.seed);
  const retry = await hyperkey.createPrivateSeedDelivery(deliveryContext, new Uint8Array(32));
  assert.deepEqual(retry, delivery, "a sender retry returns the durable original ciphertext without using the replacement seed");
  const state = new hyperkey.InMemoryHyperKeyLocalState(), custody = new hyperkey.InMemoryHyperKeySeedCustody();
  const input = { delivery, descriptor, recipientPrivateDeliveryKey: recipient.key.privateKey, authenticatedSender: deliveryContext.authenticatedRecipient, admissions: flow.admissions, state, custody };
  const receipt = await hyperkey.installPrivateSeedDelivery(input);
  assert.deepEqual(await hyperkey.installPrivateSeedDelivery(input), receipt);
  const altered = { ...delivery, ciphertext: `${delivery.ciphertext.slice(0, -1)}${delivery.ciphertext.endsWith("A") ? "B" : "A"}` };
  await assert.rejects(hyperkey.decryptPrivateSeedDelivery(altered, descriptor, recipient.key.privateKey, { recipientCopyId: recipient.copy.copyId, admissionId: delivery.admissionId, selectedCommitId: delivery.selectedCommitId }), /authentication/u);
  const changedContext = await context(descriptor, flow, recipient, founder, admitted.admissionId, admitted.selectedCommitId);
  const changed = await hyperkey.createPrivateSeedDelivery(changedContext, conventional.seed);
  await assert.rejects(hyperkey.installPrivateSeedDelivery({ ...input, delivery: changed, authenticatedSender: changedContext.authenticatedRecipient }), /cannot replace/u);
  const record = await flow.outbox.read(delivery.deliveryId);
  await assert.rejects(flow.outbox.storeFirst({ ...record, delivery: { ...record.delivery, ciphertext: `${record.delivery.ciphertext.slice(0, -1)}${record.delivery.ciphertext.endsWith("A") ? "B" : "A"}` } }), /differing bytes/u, "one delivery ID cannot acquire a different encrypted envelope");
});

test("application boundary rejects authenticated-message sender substitution and recipient key substitution", async () => {
  const sender = await enrolledCopy(), recipient = await enrolledCopy(), substitute = await enrolledCopy(), groupId = identifier();
  const { descriptor, id: descriptorId } = await hyperkey.createHyperKeyDescriptor(groupId, (await hyperkey.generateEd25519SeedPair()).publicKey);
  const directory = new testing.InMemoryHyperKeyAdmittedCopyDirectory();
  directory.put(groupId, sender.copy); directory.put(groupId, recipient.copy);
  const binding = { descriptorId, groupId, profile: hyperkey.HYPERKEY_GROUP_PROFILE, senderCopyId: sender.copy.copyId, recipientCopyId: recipient.copy.copyId, recipientDeliveryKey: recipient.copy.recipientDeliveryKey, admissionId: identifier(), selectedCommitId: identifier(), deliveryId: identifier() };
  const message = hyperkey.hyperKeyApplicationTranscript(binding);
  const substitutedSender = new hyperkey.HyperKeyApplicationDeliveryBoundary({ async authenticate({direction,applicationMessage,expectedPlaintext}) { return { groupId, profile: hyperkey.HYPERKEY_GROUP_PROFILE, senderMemberSigningKeyFingerprint: substitute.copy.member.signingKeyFingerprint, plaintext: expectedPlaintext,transition:stagedAuthentication(direction,binding,applicationMessage,substitute.copy.member.signingKeyFingerprint) }; } }, directory);
  await assert.rejects(substitutedSender.authenticateForSend(binding, message), /Claimed sender Copy/u);
  const wrongRecipientBinding = { ...binding, recipientDeliveryKey: substitute.copy.recipientDeliveryKey };
  const rightSender = new hyperkey.HyperKeyApplicationDeliveryBoundary({ async authenticate({direction,applicationMessage}) { return { groupId, profile: hyperkey.HYPERKEY_GROUP_PROFILE, senderMemberSigningKeyFingerprint: sender.copy.member.signingKeyFingerprint,transition:stagedAuthentication(direction,wrongRecipientBinding,applicationMessage,recipient.copy.member.signingKeyFingerprint) }; } }, directory);
  await assert.rejects(rightSender.authenticateForReceive(wrongRecipientBinding, hyperkey.hyperKeyApplicationTranscript(wrongRecipientBinding)), /Recipient Copy or delivery key/u);
});

test("lost recipient ACK is recovered from the durable installation receipt without another MLS installation", async () => {
  const founder = await enrolledCopy(), recipient = await enrolledCopy(), groupId = identifier();
  const conventional = await hyperkey.generateEd25519SeedPair(), { descriptor } = await hyperkey.createHyperKeyDescriptor(groupId, conventional.publicKey);
  const flow = await composeAdmissions(groupId), admitted = await admit(flow.admissions, flow.invitationId, groupId, recipient, flow.now);
  await acknowledge(flow, admitted.admissionId, flow.now());
  const deliveryContext = await context(descriptor, flow, recipient, founder, admitted.admissionId, admitted.selectedCommitId);
  const delivery = await hyperkey.createPrivateSeedDelivery(deliveryContext, conventional.seed);
  const state = new hyperkey.InMemoryHyperKeyLocalState(), custody = new hyperkey.InMemoryHyperKeySeedCustody();
  const first = await hyperkey.installPrivateSeedDelivery({ delivery, descriptor, recipientPrivateDeliveryKey: recipient.key.privateKey, authenticatedSender: deliveryContext.authenticatedRecipient, admissions: flow.admissions, state, custody });
  // The sender did not receive `first`; it retries the same envelope and the recipient re-authenticates its MLS message.
  const retryDelivery = await hyperkey.createPrivateSeedDelivery(deliveryContext, conventional.seed);
  const retryContext = await flow.boundary.authenticateForReceive(hyperkey.deliveryBindingForEnvelope(retryDelivery), deliveryContext.applicationMessage);
  const recovered = await hyperkey.installPrivateSeedDelivery({ delivery: retryDelivery, descriptor, recipientPrivateDeliveryKey: undefined, authenticatedSender: retryContext, admissions: flow.admissions, state, custody });
  assert.deepEqual(recovered, first);
  assert.equal(flow.provider.installed.get(admitted.admissionId).selectedCommitId, admitted.selectedCommitId, "recovery only reads the original MLS installation");
  assert.equal(first.senderCopyId, founder.copy.copyId);
  assert.equal(first.recipientDeliveryKey, recipient.copy.recipientDeliveryKey);
});

test("forgetting preserves the Group-backed local suppression tombstone", async () => {
  const founder = await enrolledCopy(), recipient = await enrolledCopy(), groupId = identifier();
  const conventional = await hyperkey.generateEd25519SeedPair(), { descriptor, id } = await hyperkey.createHyperKeyDescriptor(groupId, conventional.publicKey);
  const flow = await composeAdmissions(groupId), admitted = await admit(flow.admissions, flow.invitationId, groupId, recipient, flow.now);
  await acknowledge(flow, admitted.admissionId, flow.now());
  const deliveryContext = await context(descriptor, flow, recipient, founder, admitted.admissionId, admitted.selectedCommitId);
  const delivery = await hyperkey.createPrivateSeedDelivery(deliveryContext, conventional.seed);
  const state = new hyperkey.InMemoryHyperKeyLocalState(), custody = new hyperkey.InMemoryHyperKeySeedCustody();
  const input = { delivery, descriptor, recipientPrivateDeliveryKey: recipient.key.privateKey, authenticatedSender: deliveryContext.authenticatedRecipient, admissions: flow.admissions, state, custody };
  await hyperkey.installPrivateSeedDelivery(input);
  await hyperkey.forgetHyperKeyLocally({ descriptorId: id, groupId, copyId: recipient.copy.copyId, state, custody });
  assert.equal(await custody.has({ descriptorId: id, copyId: recipient.copy.copyId }), false);
  await assert.rejects(hyperkey.installPrivateSeedDelivery(input), /suppressed/u);
});

test("the default authority fails closed", async () => {
  await assert.rejects(hyperkey.unavailableHyperKeyAuthority.authorize({ action: "approve", group: { scope: identifier(), revision: 0, epoch: "0", predecessor: identifier() }, payload: bytes("explicit operation"), nowMs: 1_000 }), hyperkey.HyperKeyProviderUnavailableError);
});

test("founder creation delegates the Group and sealed readiness writes to one explicit atomic port", async () => {
  const founder = await enrolledCopy(), groupId = identifier();
  let groupCreated = false, captured;
  const founderGroup = { async stageFounder(input) { groupCreated = true; assert.equal(input.groupId, groupId); assert.equal(input.profile, hyperkey.HYPERKEY_GROUP_PROFILE); return { schema:"group-foundation.group.native-transition.v1", transitionId:identifier(),kind:"create",expectedRevision:null,next:{schema:"group-foundation.group.native-state.v1",groupId,profile:input.profile,member:input.founder.member,revision:0,epoch:"0",snapshot:new Uint8Array([1])},outbox:[] }; } };
  const atomic = { async createAtomically(input) {
    captured = input;
    assert.equal(input.stagedGroup.next.groupId, groupId);
    assert.equal(input.readiness.status, "ready");
    assert.deepEqual(await hyperkey.publicKeyForEd25519Seed(input.seed), hyperkey.fromBase64url(input.descriptor.publicKey, 32));
  } };
  const created = await hyperkey.createFounderHyperKey({ groupId, founder: founder.copy, group: founderGroup, atomic });
  assert.equal(groupCreated, true);
  assert.equal(captured.descriptorId, created.descriptorId);
  assert.equal(created.readiness.copyId, founder.copy.copyId);
});
