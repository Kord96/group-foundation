import assert from "node:assert/strict";
import { access, readFile } from "node:fs/promises";
import test from "node:test";

const hyperkey = await import(new URL("../dist/index.js", import.meta.url));
const testing = await import(new URL("../dist/testing.js", import.meta.url));
import { AdmissionProviderFixture } from "./support/admission-provider.mjs";

const generatedModule = new URL(import.meta.resolve("@group-foundation/group-core/native"));
const generatedWasm = new URL(import.meta.resolve("@group-foundation/group-core/native-wasm"));
let native;
try {
  await Promise.all([access(generatedModule), access(generatedWasm)]);
  native = await import(generatedModule.href);
  // wasm-bindgen's web target accepts bytes in Node, avoiding fetch(file:...).
  await native.default({ module_or_path: await readFile(generatedWasm) });
} catch (error) {
  throw new Error("@group-foundation/group-core native WebAssembly binding is required for this qualification test; run pnpm --filter @group-foundation/group-core build:wasm", { cause: error });
}

const encoder = new TextEncoder();
const bytes = value => encoder.encode(value);
const identifier = () => hyperkey.base64url(crypto.getRandomValues(new Uint8Array(32)));
const byteArray = value => [...value];
const equalBytes = (actual, expected, message) => assert.deepEqual(byteArray(actual), byteArray(expected), message);
const containsBytes = (haystack, needle) => needle.length <= haystack.length && haystack.some((_, start) => start + needle.length <= haystack.length && needle.every((byte, index) => haystack[start + index] === byte));
const digest = async value => hyperkey.base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", value)));

async function deliveryKeyPair() {
  const pair = await crypto.subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  return { privateKey: pair.privateKey, publicKey: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)) };
}

async function nativeCopy(client, keyPackage) {
  const delivery = await deliveryKeyPair();
  return {
    delivery,
    copy: {
      copyId: identifier(),
      member: { signingKeyFingerprint: hyperkey.base64url(client.memberId()) },
      keyPackageDigest: await digest(keyPackage),
      recipientDeliveryKey: hyperkey.base64url(delivery.publicKey),
    },
  };
}

/** Real directional MLS integration. Each staged snapshot is committed in this
 * explicit test store before auth returns; duplicate envelopes reuse that
 * durable authentication record instead of replaying against an old ratchet. */
class NativeRecipientApplicationAuthenticator {
  constructor(senderSnapshot, recipientSnapshot, groupId, profile, authority, clock) {
    this.sender = native.NativeClient.fromSnapshot(senderSnapshot);
    this.recipient = native.NativeClient.fromSnapshot(recipientSnapshot);
    this.groupId = groupId; this.profile = profile; this.authority = authority; this.clock = clock;
    this.opens = 0; this.sends = new Map(); this.receives = new Map(); this.revisions = {send:0,receive:0};
  }
  async seal(plaintext) {
    const output = this.sender.stageSealApplication(bytes(this.groupId), bytes(this.profile), plaintext, this.authority, BigInt(this.clock()));
    this.sender = native.NativeClient.fromSnapshot(output.snapshot);
    const transition = await this.transition("send", output, output.message);
    this.sends.set(await digest(output.message), { plaintext, sender: hyperkey.base64url(this.sender.memberId()), transition });
    return output;
  }
  async transition(direction, output, message) {
    const revision = ++this.revisions[direction];
    return { schema:"group-foundation.group.native-transition.v1", transitionId: identifier(), kind: direction === "send" ? "application-send" : "application-receive", expectedRevision:revision-1,
      next:{schema:"group-foundation.group.native-state.v1", groupId:this.groupId, profile:this.profile, member:{ signingKeyFingerprint:hyperkey.base64url((direction === "send" ? this.sender : this.recipient).memberId()) },revision,epoch:output.epoch,snapshot:output.snapshot},
      outbox:direction === "send" ? [{id:identifier(),kind:"application",bytes:message,digest:await digest(message)}] : [] };
  }
  async authenticate({ direction, applicationMessage, expectedPlaintext }) {
    const key = await digest(applicationMessage);
    let record = (direction === "send" ? this.sends : this.receives).get(key);
    if (!record && direction === "receive") {
      const opened = this.recipient.stageOpenApplication(bytes(this.groupId), bytes(this.profile), applicationMessage);
      this.recipient = native.NativeClient.fromSnapshot(opened.snapshot);
      this.opens++;
      record = {plaintext:opened.plaintext,sender:hyperkey.base64url(opened.sender),transition:await this.transition("receive",opened,applicationMessage)};
      this.receives.set(key,record);
    }
    assert.ok(record,"send authentication requires its own durable native sealing output");
    equalBytes(record.plaintext, expectedPlaintext, "native MLS authenticated a different application plaintext");
    return { groupId:this.groupId,profile:this.profile,senderMemberSigningKeyFingerprint:record.sender,transition:record.transition };
  }
}

/** A new adapter instance over this map models restarting the recipient process. */
class RestartableLocalState {
  constructor(records) { this.records = records; }
  async read(descriptorId, copyId) {
    const record = this.records.get(`${descriptorId}:${copyId}`);
    return record && structuredClone(record);
  }
  async transaction(operation) {
    const staged = new Map(this.records);
    const result = await operation({
      read: (descriptorId, copyId) => {
        const record = staged.get(`${descriptorId}:${copyId}`);
        return record && structuredClone(record);
      },
      write: record => staged.set(`${record.descriptorId}:${record.copyId}`, structuredClone(record)),
    });
    this.records.clear();
    for (const [key, record] of staged) this.records.set(key, record);
    return result;
  }
}

class CountingCustody extends hyperkey.InMemoryHyperKeySeedCustody {
  seals = 0;
  async seal(input) { this.seals++; return super.seal(input); }
}

test("native MLS and the explicit admission provider qualify private-seed delivery end to end", async () => {
  const groupId = identifier();
  const profile = hyperkey.HYPERKEY_GROUP_PROFILE;
  const authority = new native.NativeAuthorityFacts(1n, 9_999_999n, 1n, 9_999_999n);
  let now = 1_000;
  const nextNow = () => now++;

  let founderClient = new native.NativeClient(bytes("qualification:founder"));
  const founderPackage = founderClient.createKeyPackage(bytes(profile));
  founderClient = native.NativeClient.fromSnapshot(founderPackage.snapshot);
  const created = founderClient.createGroup(bytes(groupId), bytes(profile), authority, BigInt(nextNow()));
  founderClient = native.NativeClient.fromSnapshot(created.snapshot);

  let recipientClient = new native.NativeClient(bytes("qualification:recipient"));
  const recipientPackage = recipientClient.createKeyPackage(bytes(profile));
  recipientClient = native.NativeClient.fromSnapshot(recipientPackage.snapshot);
  const founder = await nativeCopy(founderClient, founderPackage.keyPackage);
  const recipient = await nativeCopy(recipientClient, recipientPackage.keyPackage);
  assert.notEqual(founder.copy.copyId, founder.copy.member.signingKeyFingerprint, "a Copy ID is distinct from its real MLS member fingerprint");
  assert.notEqual(recipient.copy.copyId, recipient.copy.member.signingKeyFingerprint, "a Copy ID is distinct from its real MLS member fingerprint");
  assert.notDeepEqual(byteArray(founderClient.memberId()), byteArray(recipientClient.memberId()), "founder and recipient have independent native MLS identities");
  assert.notDeepEqual(byteArray(founderClient.exportSnapshot()), byteArray(recipientClient.exportSnapshot()), "founder and recipient retain independent native MLS state");

  const records = new testing.InMemoryHyperKeyCopyAdmissionRecordStore();
  const directory = new testing.InMemoryHyperKeyAdmittedCopyDirectory();
  const outbox = new testing.InMemoryHyperKeyPrivateDeliveryOutbox();
  const provider = new AdmissionProviderFixture();
  let stagedAdds = 0;
  let selected;
  provider.approveAndSelect = async ({admissionId}) => {
    const request = provider.requests.get(admissionId);
    equalBytes(request.keyPackage, recipientPackage.keyPackage, "provider receives the native recipient KeyPackage");
    const detached = native.NativeClient.fromSnapshot(founderClient.exportSnapshot());
    try {
      const staged = detached.stageAdd(bytes(groupId), bytes(profile), request.keyPackage, authority, BigInt(nextNow()));
      stagedAdds++;
      selected = { ...staged, successor: await digest(staged.snapshot) };
      provider.selected.set(admissionId, selected.successor);
      founderClient.free();
      founderClient = native.NativeClient.fromSnapshot(staged.snapshot);
      return { selectedCommitId: selected.successor };
    } finally { detached.free(); }
  };
  const admissions = new hyperkey.HyperKeyCopyAdmissions(provider, records);
  const invitationId = identifier(), admissionId = identifier();
  await admissions.request({ admissionId, groupId, invitationId, copy: recipient.copy, evidence: bytes("qualification-copy-evidence"), keyPackage: recipientPackage.keyPackage, proof: bytes("qualification-proof"), requestedAtMs: nextNow(), expiresAtMs: 8_000_000 });
  const actor = { member: founder.copy.member, authentication: bytes("explicit-qualification-actor") };
  const { selectedCommitId } = await admissions.approve(groupId, recipient.copy.copyId, admissionId, { approval: actor, selection: actor });
  assert.equal(stagedAdds, 1);
  assert.throws(() => recipientClient.stageJoin(bytes(identifier()), bytes(profile), selected.welcome, selected.ratchetTree, authority, BigInt(nextNow())), "native Group rejects a Welcome for another group");
  assert.throws(() => recipientClient.stageJoin(bytes(groupId), bytes("hyperkey.v2"), selected.welcome, selected.ratchetTree, authority, BigInt(nextNow())), "native Group rejects a Welcome with another profile");
  let stagedJoins = 0;
  const joined = recipientClient.stageJoin(bytes(groupId), bytes(profile), selected.welcome, selected.ratchetTree, authority, BigInt(nextNow()));
  stagedJoins++;
  recipientClient = native.NativeClient.fromSnapshot(joined.snapshot);
  assert.equal(hyperkey.base64url(recipientClient.memberId()), recipient.copy.member.signingKeyFingerprint, "Join preserves the recipient Copy's real native member fingerprint");

  const conventional = await hyperkey.generateEd25519SeedPair();
  const { descriptor, id: descriptorId } = await hyperkey.createHyperKeyDescriptor(groupId, conventional.publicKey);
  assert.equal(Object.isFrozen(descriptor), true, "the HyperKey descriptor is immutable");
  const deliveryId = crypto.getRandomValues(new Uint8Array(32));
  const binding = {
    descriptorId,
    groupId,
    profile,
    senderCopyId: founder.copy.copyId,
    recipientCopyId: recipient.copy.copyId,
    recipientDeliveryKey: recipient.copy.recipientDeliveryKey,
    admissionId,
    selectedCommitId,
    deliveryId: hyperkey.base64url(deliveryId),
  };
  const transcript = hyperkey.hyperKeyApplicationTranscript(binding);
  const verifier = new NativeRecipientApplicationAuthenticator(founderClient.exportSnapshot(), recipientClient.exportSnapshot(), groupId, profile, authority, nextNow);
  const boundary = new hyperkey.HyperKeyApplicationDeliveryBoundary(verifier, directory);
  // Native Join has established the current Copy/member mapping, but the
  // separate durable Group-installation acknowledgement has not happened yet.
  directory.put(groupId, founder.copy);
  directory.put(groupId, recipient.copy);
  const sealedBeforeAcknowledgement = await verifier.seal(transcript);
  const authenticatedBeforeAcknowledgement = await boundary.authenticateForSend(binding, sealedBeforeAcknowledgement.message);
  await assert.rejects(hyperkey.createPrivateSeedDelivery({ descriptor, admissions, recipientCopyId: recipient.copy.copyId, senderCopyId: founder.copy.copyId, admissionId, selectedCommitId, recipientDeliveryKey: recipient.delivery.publicKey, deliveryId, authenticatedSender: authenticatedBeforeAcknowledgement, outbox }, conventional.seed), /not canonical and durable/u, "a native-authenticated frame cannot create delivery before canonical Group installation");

  const installation = { admissionId, groupId, selectedCommitId, recipient: recipient.copy.member, proof: bytes("explicit-qualification-installation"), installedAtMs:nextNow() };
  await assert.rejects(admissions.acknowledgeCanonicalInstallation({...installation,proof:new Uint8Array()}),/proof/u);
  await assert.rejects(admissions.acknowledgeCanonicalInstallation({...installation,selectedCommitId:identifier()}));
  await admissions.acknowledgeCanonicalInstallation(installation);

  const sealed = await verifier.seal(transcript);
  assert.throws(() => recipientClient.stageOpenApplication(bytes(identifier()), bytes(profile), sealed.message), "native MLS rejects an application frame for the wrong group");
  assert.throws(() => recipientClient.stageOpenApplication(bytes(groupId), bytes("hyperkey.v2"), sealed.message), "native MLS rejects an application frame for the wrong profile");
  const nativeOpened = native.NativeClient.fromSnapshot(recipientClient.exportSnapshot()).stageOpenApplication(bytes(groupId), bytes(profile), sealed.message);
  equalBytes(nativeOpened.plaintext, transcript, "the native application plaintext is exactly the delivery binding");
  assert.equal(new TextDecoder().decode(nativeOpened.plaintext).includes(recipient.copy.recipientDeliveryKey), true, "the application plaintext carries the recipient delivery binding");
  assert.equal(containsBytes(nativeOpened.plaintext, conventional.seed), false, "the conventional seed is absent from Group application plaintext");
  for (const publicGroupBytes of [selected.commit, selected.welcome, selected.ratchetTree]) assert.equal(containsBytes(publicGroupBytes, conventional.seed), false, "the conventional seed is absent from selected Group transport material");

  let impostorClient = new native.NativeClient(bytes("qualification:impostor"));
  const impostorPackage = impostorClient.createKeyPackage(bytes(profile));
  impostorClient = native.NativeClient.fromSnapshot(impostorPackage.snapshot);
  const impostor = await nativeCopy(impostorClient, impostorPackage.keyPackage);
  directory.put(groupId, impostor.copy);
  const claimedSenderBinding = { ...binding, senderCopyId: impostor.copy.copyId };
  const claimedSenderFrame = await verifier.seal(hyperkey.hyperKeyApplicationTranscript(claimedSenderBinding));
  await assert.rejects(boundary.authenticateForSend(claimedSenderBinding, claimedSenderFrame.message), /Claimed sender Copy/u, "the boundary rejects a claimed Copy that is not the native MLS sender");
  const wrongDeliveryBinding = { ...binding, recipientDeliveryKey: impostor.copy.recipientDeliveryKey };
  const wrongDeliveryFrame = await verifier.seal(hyperkey.hyperKeyApplicationTranscript(wrongDeliveryBinding));
  await assert.rejects(boundary.authenticateForReceive(wrongDeliveryBinding, wrongDeliveryFrame.message), /Recipient Copy or delivery key/u, "the boundary rejects a substituted recipient delivery key after native authentication");

  const authenticatedSender = await boundary.authenticateForSend(binding, sealed.message);
  const delivery = await hyperkey.createPrivateSeedDelivery({ descriptor, admissions, recipientCopyId: recipient.copy.copyId, senderCopyId: founder.copy.copyId, admissionId, selectedCommitId, recipientDeliveryKey: recipient.delivery.publicKey, deliveryId, authenticatedSender, outbox }, conventional.seed);
  const differentFrameBinding = { ...binding, deliveryId: identifier() };
  const differentFrame = await verifier.seal(hyperkey.hyperKeyApplicationTranscript(differentFrameBinding));
  const authenticatedDifferentFrame = await boundary.authenticateForReceive(differentFrameBinding, differentFrame.message);
  const durableRecords = new Map();
  let localState = new RestartableLocalState(durableRecords);
  const custody = new CountingCustody();
  await assert.rejects(hyperkey.installPrivateSeedDelivery({ delivery, descriptor, recipientPrivateDeliveryKey: recipient.delivery.privateKey, authenticatedSender: authenticatedDifferentFrame, admissions, state: localState, custody }), /not bound to an authenticated MLS application message/u, "custody rejects even a real native MLS frame unless it authenticates this exact delivery binding");

  const authenticatedRecipient = await boundary.authenticateForReceive(binding, sealed.message);
  const firstReceipt = await hyperkey.installPrivateSeedDelivery({ delivery, descriptor, recipientPrivateDeliveryKey: recipient.delivery.privateKey, authenticatedSender: authenticatedRecipient, admissions, state: localState, custody });
  equalBytes(custody.testingRead(descriptorId, recipient.copy.copyId), conventional.seed, "founder and recipient share the one conventional HyperKey seed");
  assert.equal(custody.seals, 1, "only one conventional seed installation occurred");

  // Lost receipt: a fresh custody adapter reuses the durable authenticated frame
  // and gets the original receipt without resetting MLS state or another Add/Join.
  localState = new RestartableLocalState(durableRecords);
  const retry = await hyperkey.createPrivateSeedDelivery({ descriptor, admissions, recipientCopyId: recipient.copy.copyId, senderCopyId: founder.copy.copyId, admissionId, selectedCommitId, recipientDeliveryKey: recipient.delivery.publicKey, deliveryId, authenticatedSender, outbox }, crypto.getRandomValues(new Uint8Array(32)));
  assert.deepEqual(retry, delivery, "sender retry returns the original durable encrypted envelope");
  const opensBeforeRetry = verifier.opens;
  const retryAuthentication = await boundary.authenticateForReceive(binding, sealed.message);
  assert.equal(verifier.opens,opensBeforeRetry,"exact retry reuses durable authentication instead of rewinding recipient MLS state");
  const recoveredReceipt = await hyperkey.installPrivateSeedDelivery({ delivery: retry, descriptor, recipientPrivateDeliveryKey: undefined, authenticatedSender: retryAuthentication, admissions, state: localState, custody });
  assert.deepEqual(recoveredReceipt, firstReceipt, "restart retry returns the original HyperKey installation receipt");
  assert.equal(stagedAdds, 1, "lost receipt retry did not stage MLS Add again");
  assert.equal(stagedJoins, 1, "lost receipt retry did not join MLS again");
  assert.equal(custody.seals, 1, "lost receipt retry did not reinstall the conventional seed");
  assert.equal(verifier.opens,3,"only three distinct receive frames advance the recipient ratchet; send validation never opens recipient state");
});
