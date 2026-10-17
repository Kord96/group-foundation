import assert from "node:assert/strict";
import test from "node:test";
import * as admission from "@group-foundation/group-admission";
import { InMemoryAdmissionTransactions, RecordingDelivery } from "@group-foundation/group-admission/testing";
import * as hyperkey from "../dist/index.js";
import { InMemoryHyperKeyCopyAdmissionRecordStore } from "../dist/testing.js";
const bytes = value => new TextEncoder().encode(value);
const id = () => hyperkey.base64url(crypto.getRandomValues(new Uint8Array(32)));
const digest = async value => hyperkey.base64url(new Uint8Array(await crypto.subtle.digest("SHA-256",value)));

test("real admission runtime binds Copy identity, exact selected Add and authenticated durable installation", async () => {
  const groupId = id(), copy = {copyId:id(),member:{signingKeyFingerprint:id()},keyPackageDigest:id(),recipientDeliveryKey:id()};
  const scopeFor = (groupId, profile) => `${profile}:${groupId}`;
  const scope = scopeFor(groupId,hyperkey.HYPERKEY_GROUP_PROFILE), records = new InMemoryHyperKeyCopyAdmissionRecordStore();
  const transactions = new InMemoryAdmissionTransactions(admission.createAdmissionLedger({scope,revision:0,epoch:"0",predecessor:id()}), {revision:0}, async (current,stage) => {
    assert.equal(stage.custody.revision,current.revision+1);
    return stage.custody;
  });
  let selections = 0, clock = 1000;
  const actor = {member:{signingKeyFingerprint:id()},authentication:bytes("explicit actor proof")};
  const runtime = new admission.GroupAdmissionRuntime({
    transactions,
    candidates: new hyperkey.HyperKeyGroupIdentityAdapter({async verifyCopyEvidence(input) {
      assert.deepEqual(input.copy,copy);
      assert.deepEqual(input.evidence,bytes("Copy authority credential"));
      return {authorityRevision:"identity-1",validUntilMs:9000};
    }},records,scopeFor),
    governance: new hyperkey.HyperKeyGroupGovernanceAdapter({async authorize(input) {
      assert.equal(input.actor.signingKeyFingerprint,input.action === "accept" ? copy.member.signingKeyFingerprint : actor.member.signingKeyFingerprint);
      if (input.request) assert.deepEqual(input.copy,copy);
      return {authorityRevision:"policy-1",validUntilMs:9000};
    }},records,scopeFor),
    actors:{async verify(input) { assert.deepEqual(input.actor.authentication,bytes("explicit actor proof"));return input.actor.member; }},
    installations:{async verify({receipt}) {assert.deepEqual(receipt.acknowledgement,bytes("recipient installation proof"));}},
    selection:{async prepare(input) {
      selections++;
      return {kind:input.kind,operationId:input.operationId,operationHash:input.operationHash,retryId:input.retryId,transitionId:id(),expected:input.group,next:{...input.group,revision:input.group.revision+1,epoch:String(BigInt(input.group.epoch)+1n),predecessor:id()},commit:bytes("native commit"),welcome:bytes("native welcome"),ratchetTree:bytes("native tree"),custodyDigest:id(),custody:{revision:input.group.revision+1}};
    }},delivery:new RecordingDelivery(),digest:{digest},now:()=>clock++,reservationDuration:500,
  });
  const invitationId=id(), admissionId=id();
  await runtime.issue({invitationId,scope,expiresAt:9000,maxUses:1,approval:"required",issuedBy:actor.member},actor);
  const provider = new hyperkey.GroupAdmissionHyperKeyProvider({runtime,transactions,scopeFor});
  const flow = new hyperkey.HyperKeyCopyAdmissions(provider,records);
  const request = {groupId,copy,admissionId,invitationId,evidence:bytes("Copy authority credential"),keyPackage:bytes("independent KeyPackage"),proof:bytes("candidate proof"),requestedAtMs:1000,expiresAtMs:8000};
  await flow.request(request);
  const stored = admission.decodeAdmissionRequest((await transactions.read()).requests[admissionId].wire);
  assert.deepEqual(hyperkey.decodeHyperKeyAdmissionBinding(stored),{groupId,copyId:copy.copyId,recipientDeliveryKey:copy.recipientDeliveryKey});
  await assert.rejects(flow.request({...request,evidence:bytes("changed retry")}),/different|changed|conflict/i);
  const {selectedCommitId} = await flow.approve(groupId,copy.copyId,admissionId,{approval:actor,selection:actor});
  const expected = {groupId,copyId:copy.copyId,admissionId,selectedCommitId,recipientDeliveryKey:copy.recipientDeliveryKey};
  await assert.rejects(flow.assertCanonicalInstallation(expected),/not canonical and durable/);
  const installedAtMs = clock;
  await assert.rejects(flow.acknowledgeCanonicalInstallation({groupId,admissionId,selectedCommitId,recipient:copy.member,proof:bytes("arbitrary proof"),installedAtMs}));
  await flow.acknowledgeCanonicalInstallation({groupId,admissionId,selectedCommitId,recipient:copy.member,proof:bytes("recipient installation proof"),installedAtMs});
  assert.deepEqual(await flow.assertCanonicalInstallation(expected),{groupId,profile:hyperkey.HYPERKEY_GROUP_PROFILE,copy,admissionId,selectedCommitId});
  const restarted = new hyperkey.HyperKeyCopyAdmissions(new hyperkey.GroupAdmissionHyperKeyProvider({runtime,transactions,scopeFor}),records);
  assert.deepEqual(await restarted.assertCanonicalInstallation(expected),await flow.assertCanonicalInstallation(expected));
  await assert.rejects(restarted.assertCanonicalInstallation({...expected,selectedCommitId:id()}),/bindings/);
  await assert.rejects(restarted.assertCanonicalInstallation({...expected,recipientDeliveryKey:id()}),/bindings/);
  assert.equal(selections,1);
  assert.equal((await transactions.readCustody()).revision,1);
  const prior = {...stored,deliveryBinding:bytes(JSON.stringify(["zagel.hyperkey.admission-binding.v1",{groupId,profile:"zagel.hyperkey.v1",copyId:copy.copyId,recipientDeliveryKey:copy.recipientDeliveryKey}]))};
  assert.throws(()=>hyperkey.decodeHyperKeyAdmissionBinding(prior),/Invalid HyperKey admission binding/);
});
