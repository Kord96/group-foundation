import assert from "node:assert/strict";
import test from "node:test";
import { HyperKeyDeviceState, HyperKeyHost, HyperKeyProviderUnavailableError, HyperKeyCopyUnavailableError, fromBase64url, verifyEd25519 } from "../dist/index.js";
import { MemoryPhysicalStore as InMemoryStateStore, MemorySealing as InMemoryDeviceKeyStore, commitOutcome } from "./support/persistence.mjs";
const text = new TextEncoder();
const copy = suffix => ({ copyId:`copy_${suffix}_012345678901234567890123456789`,member:{signingKeyFingerprint:`member_${suffix}_012345678901234567890123456`},keyPackageDigest:`key_package_${suffix}_012345678901234567890`,recipientDeliveryKey:Buffer.alloc(32,suffix.length).toString("base64url") });
const stagedFounder = input => ({schema:"group-foundation.group.native-transition.v1",transitionId:`founder_${input.groupId}`,kind:"create",expectedRevision:null,next:{schema:"group-foundation.group.native-state.v1",groupId:input.groupId,profile:input.profile,member:input.founder.member,revision:0,epoch:"0",snapshot:text.encode(`independent-mls-fixture-${input.founder.member.signingKeyFingerprint}`)},outbox:[]});
function composition(state, keys, created) {return new HyperKeyHost({persistence:state,sealing:keys,commitOutcome,group:{async stageFounder(input){created.push(structuredClone(input));return stagedFounder(input);}}});}
test("HyperKey host persists independently keyed Group/product records across restart-like reopen", async () => {
  const state = new InMemoryStateStore(), keys = new InMemoryDeviceKeyStore(), created = [];
  const first = composition(state, keys, created);
  const alpha = await first.create({ groupId: "group_alpha_012345678901234567890123", founder: copy("alpha") });
  const beta = await first.create({ groupId: "group_beta_0123456789012345678901234", founder: copy("beta") });
  assert.notEqual(alpha.id, beta.id);
  assert.equal((await first.list()).length, 2);
  assert.equal(created.length, 2);
  await first.close();

  const reopened = composition(state, keys, created);
  const listed = await reopened.list();
  assert.deepEqual(listed.map(value => value.id).sort(), [alpha.id, beta.id].sort());
  assert.equal((await reopened.open(alpha.id))?.descriptor.groupId, "group_alpha_012345678901234567890123");
  assert.equal((await reopened.open(beta.id, copy("beta").copyId))?.status, "ready");
  await reopened.close();
});

test("ready Copy signs conventionally after reopen and stale handles fail after atomic forgetting", async () => {
  const state = new InMemoryStateStore(), keys = new InMemoryDeviceKeyStore(), created = [];
  const first = composition(state, keys, created);
  const key = await first.create({ groupId: "group_signing_012345678901234567890", founder: copy("signing") });
  const message = text.encode("ordinary application signing");
  const signature = await key.sign(message);
  assert.equal(await verifyEd25519(fromBase64url(key.descriptor.publicKey, 32), message, signature), true);
  assert.equal(await verifyEd25519(fromBase64url(key.descriptor.publicKey, 32), text.encode("changed"), signature), false);
  assert.equal(JSON.stringify(key).includes("seed"), false);
  assert.equal(Object.keys(key).some(name => /private|secret|custody/i.test(name)), false);
  await first.close();

  const reopened = composition(state, keys, created);
  const local = await reopened.open(key.id, key.copyId);
  assert.deepEqual(await local.sign(message), signature);
  assert.equal((await reopened.listCopies())[0].step, "ready");
  const nativeStorage = reopened.state.nativeGroupStorage();
  const nativeState = await nativeStorage.read(key.descriptor.groupId, copy("signing").member);
  const advanced = { schema: "group-foundation.group.native-transition.v1", transitionId: "advance-before-forget", kind: "commit", expectedRevision: 0, next: { ...nativeState, revision: 1, epoch: "1" }, outbox: [] };
  await nativeStorage.commit(advanced);
  await local.forget();
  assert.equal((await reopened.copyProgress(key.id, key.copyId)).step, "forgotten");
  assert.equal((await reopened.state.nativeGroupStorage().read(key.descriptor.groupId, copy("signing").member)), undefined);
  await assert.rejects(local.sign(message), error => error instanceof HyperKeyCopyUnavailableError && error.reason === "forgotten");
  await assert.rejects(reopened.state.custody(key.id, key.copyId).has({ descriptorId: key.id, copyId: key.copyId }).then(has => { assert.equal(has, false); return local.sign(message); }), HyperKeyCopyUnavailableError);
  await reopened.close();
});

test("missing and changed sealed custody never silently regenerate the conventional key", async () => {
  const host = composition(new InMemoryStateStore(), new InMemoryDeviceKeyStore(), []);
  const key = await host.create({ groupId: "group_custody_012345678901234567890", founder: copy("custody") });
  const custody = host.state.custody(key.id, key.copyId);
  await custody.seal({ descriptorId: key.id, copyId: key.copyId, seed: crypto.getRandomValues(new Uint8Array(32)) });
  await assert.rejects(key.sign(text.encode("must fail")), error => error instanceof HyperKeyCopyUnavailableError && error.reason === "changed-custody");
  await custody.remove({ descriptorId: key.id, copyId: key.copyId });
  await assert.rejects(key.sign(text.encode("must fail")), error => error instanceof HyperKeyCopyUnavailableError && error.reason === "missing-custody");
  assert.equal((await host.open(key.id)).descriptor.publicKey, key.descriptor.publicKey);
  await host.close();
});

test("founder native Group and product records commit atomically and oversized native state fails closed", async () => {
  class FailingStore extends InMemoryStateStore {
    fail = true;
    async transact(keys, operation) { if (this.fail) throw new Error("injected physical failure"); return super.transact(keys, operation); }
  }
  const state = new FailingStore(), host = composition(state, new InMemoryDeviceKeyStore(), []);
  const founder = copy("atomic"), groupId = "group_atomic_012345678901234567890";
  await assert.rejects(host.create({ groupId, founder }), /injected physical failure/);
  assert.equal((await host.list()).length, 0);
  assert.equal(await host.state.nativeGroupStorage().read(groupId, founder.member), undefined);
  state.fail = false;
  await host.create({ groupId, founder });
  assert.equal((await host.state.nativeGroupStorage().read(groupId, founder.member)).revision, 0);
  await host.close();

  const oversized = new HyperKeyHost({
    persistence: new InMemoryStateStore(), sealing: new InMemoryDeviceKeyStore(), commitOutcome,
    group: { async stageFounder(input) { const transition = stagedFounder(input); transition.next.snapshot = new Uint8Array(1_048_576); return transition; } },
  });
  await assert.rejects(oversized.create({ groupId, founder }), /record exceeds its bound/);
  assert.equal((await oversized.list()).length, 0);
  assert.equal(await oversized.state.nativeGroupStorage().read(groupId, founder.member), undefined);
  await oversized.close();
});

test("native Group storage retains exact retries and rejects stale or changed transitions", async () => {
  const host = composition(new InMemoryStateStore(), new InMemoryDeviceKeyStore(), []);
  const transition = stagedFounder({ groupId: "group_native_cas_01234567890123456789", profile: "hyperkey.v1", founder: copy("nativecas") });
  const storage = host.state.nativeGroupStorage();
  await assert.rejects(storage.commit({...transition,next:{...transition.next,profile:"hyperkey.v2"}}), /pinned HyperKey profile/);
  assert.equal((await storage.commit(transition)).replayed, false);
  assert.equal((await storage.commit(structuredClone(transition))).replayed, true);
  const changed = structuredClone(transition); changed.next.snapshot[0] ^= 1;
  await assert.rejects(storage.commit(changed), /retry differs/);
  const stale = structuredClone(transition); stale.transitionId = "different-transition";
  await assert.rejects(storage.commit(stale), /lost its predecessor/);
  const wrongDigest = structuredClone(transition); wrongDigest.transitionId = "bad-outbox"; wrongDigest.expectedRevision = 0; wrongDigest.next.revision = 1;
  wrongDigest.outbox = [{ id: "application", kind: "application", bytes: text.encode("sealed bytes"), digest: "wrong" }];
  await assert.rejects(storage.commit(wrongDigest), /digest differs/);
  await host.close();
});

test("Copy candidates retain independent Group and delivery keys across reopen without exposing private custody", async () => {
  const physical = new InMemoryStateStore(), keys = new InMemoryDeviceKeyStore();
  const founder = composition(physical, keys, []);
  const key = await founder.create({ groupId: "group_candidate_012345678901234567890", founder: copy("founder") });
  const descriptor = key.descriptor;
  await founder.close();
  const options = {
    persistence: physical, sealing: keys, commitOutcome, group: { async stageFounder(input) { return stagedFounder(input); } },
    candidates: { async stageCandidate(input) {
      const member = { signingKeyFingerprint: `independent_${input.copyId}` };
      return { member, keyPackage: crypto.getRandomValues(new Uint8Array(64)), stagedGroup: { schema: "group-foundation.group.native-transition.v1", transitionId: input.copyId, kind: "key-package", expectedRevision: null, next: { schema: "group-foundation.group.native-state.v1", groupId: input.groupId, profile: input.profile, member, revision: 0, epoch: "0", snapshot: crypto.getRandomValues(new Uint8Array(64)) }, outbox: [] } };
    } },
  };
  const host = new HyperKeyHost(options);
  const one = await host.createCopyCandidate({ descriptor, evidence: text.encode("explicit qualification"), copyId: "candidate_copy_one_0123456789012345678" });
  const two = await host.createCopyCandidate({ descriptor, evidence: text.encode("explicit qualification"), copyId: "candidate_copy_two_0123456789012345678" });
  assert.notEqual(one.copy.member.signingKeyFingerprint, two.copy.member.signingKeyFingerprint);
  assert.notEqual(one.copy.recipientDeliveryKey, two.copy.recipientDeliveryKey);
  assert.notEqual(one.copy.keyPackageDigest, two.copy.keyPackageDigest);
  assert.equal(Object.keys(one).some(name => /private|secret|seed/i.test(name)), false);
  await assert.rejects(host.requestCopy({ descriptorId: key.id, copyId: one.copy.copyId }), HyperKeyProviderUnavailableError);
  await host.close();

  const reopened = new HyperKeyHost(options);
  assert.equal((await reopened.copyProgress(key.id, one.copy.copyId)).step, "candidate");
  assert.equal((await reopened.state.candidateDeliveryKey(key.id, one.copy.copyId)).extractable, false);
  await reopened.forgetCopy(key.id, one.copy.copyId);
  assert.equal(await reopened.state.candidateDeliveryKey(key.id, one.copy.copyId), undefined);
  assert.equal(await reopened.state.nativeGroupStorage().read(descriptor.groupId, one.copy.member), undefined);
  await assert.rejects(reopened.state.copyProgress().write({ ...one, step: "requested", admissionId: "delayed-request" }), /cannot move/);
  assert.equal((await reopened.copyProgress(key.id, two.copy.copyId)).step, "candidate");
  await reopened.close();
});

test("uncertain founder commit quiesces every queued operation until a fresh coordinator reopens committed state", async () => {
  const state = new InMemoryStateStore(), keys = new InMemoryDeviceKeyStore();
  const uncertain = Object.assign(new Error("lost durable reply"), {code:"unknown-physical-commit"});
  const host = composition(state, keys, []);
  state.uncertain = uncertain;
  await assert.rejects(host.create({groupId:"uncertain_founder_01234567890123456789",founder:copy("unknown")}), error => error === uncertain);
  await assert.rejects(host.list(), /closed; reopen/);
  await assert.rejects(host.state.nativeGroupStorage().read("uncertain_founder_01234567890123456789", copy("unknown").member), /closed; reopen/);
  assert.equal(state.semanticRevision, 1, "consumer semantic revision and all HyperKey records committed together");
  state.uncertain = undefined;
  const reopened = composition(state, keys, []);
  const [key] = await reopened.list();
  const message = text.encode("after lost founder reply");
  assert.equal(await verifyEd25519(fromBase64url(key.descriptor.publicKey,32),message,await key.sign(message)),true);
  state.uncertain = uncertain;
  await assert.rejects(key.forget(), error => error === uncertain);
  await assert.rejects(key.sign(message), /closed; reopen/);
  state.uncertain = undefined;
  const recovered = composition(state, keys, []);
  const forgotten = await recovered.open(key.id,key.copyId);
  assert.equal(forgotten.status,"forgotten");
  assert.equal(await recovered.state.nativeGroupStorage().read(key.descriptor.groupId,copy("unknown").member),undefined);
  assert.equal(await recovered.state.custody(key.id,key.copyId).has({descriptorId:key.id,copyId:key.copyId}),false);
  await assert.rejects(forgotten.sign(message), error => error.reason === "forgotten");
});

test("failed forgetting rolls back custody, progress, native state and consumer semantic state", async () => {
  const state = new InMemoryStateStore(), keys = new InMemoryDeviceKeyStore(), host = composition(state,keys,[]);
  const founder = copy("rollback");
  const key = await host.create({groupId:"atomic_forget_01234567890123456789",founder});
  const before = structuredClone(state.records), revision = state.semanticRevision;
  state.failure = true;
  await assert.rejects(key.forget(),/physical failure/);
  assert.deepEqual(state.records,before);
  assert.equal(state.semanticRevision,revision);
  assert.equal((await host.copyProgress(key.id,key.copyId)).step,"ready");
  assert.equal((await host.state.nativeGroupStorage().read(key.descriptor.groupId,founder.member)).revision,0);
  assert.equal((await key.sign(text.encode("still ready"))).length,64);
  state.failure = false;
  await key.forget();
  assert.equal(state.semanticRevision,revision+1);
});

test("sealed records bind purpose and locator, and opened plaintext is wiped", async () => {
  const state = new InMemoryStateStore(), keys = new InMemoryDeviceKeyStore(), host = composition(state,keys,[]);
  const key = await host.create({groupId:"seal_scope_01234567890123456789",founder:copy("seal")});
  assert.ok([...state.records.keys()].every(key => key.startsWith("hyperkey/")));
  assert.deepEqual([...keys.keys.keys()].sort(),["hyperkey-custody-v1","hyperkey-group-client-v1","hyperkey-product-v1"]);
  const productEntry = [...state.records].find(([key]) => key.startsWith("hyperkey/product/"));
  const custodyEntry = [...state.records].find(([key]) => key.startsWith("hyperkey/custody/"));
  state.records.set(custodyEntry[0],productEntry[1]);
  await assert.rejects(key.sign(text.encode("wrong sealed purpose")));
  state.records.set(custodyEntry[0],custodyEntry[1]);
  await key.sign(text.encode("correct custody"));
  assert.ok(keys.opened.every(value => value.every(byte => byte === 0)), "all decrypted serialization buffers were cleared");
});

test("predecessor descriptors, delivery schemas, progress and persisted records are rejected", async () => {
  const { assertHyperKeyDescriptor, assertHyperKeyCopyProgress } = await import("../dist/index.js");
  const state = new InMemoryStateStore(), keys = new InMemoryDeviceKeyStore(), host = composition(state,keys,[]);
  const key = await host.create({groupId:"schema_reject_01234567890123456789",founder:copy("schema")});
  assert.throws(() => assertHyperKeyDescriptor({...key.descriptor,schema:"zagel.hyperkey.descriptor.v1"}),/profile/);
  const progress = await host.copyProgress(key.id,key.copyId);
  assert.throws(() => assertHyperKeyCopyProgress({...progress,schema:"zagel.hyperkey.copy-progress.v1"}),/binding/);
  const entry = [...state.records].find(([key]) => key.startsWith("hyperkey/product/"));
  await host.state.transaction([entry[0]],records => { const product = records.get(entry[0]); product.schema = "zagel.hyperkey.product-state.v1"; });
  await assert.rejects(host.open(key.id,key.copyId), /product record is invalid/);
});

test("Copy installation atomically replaces candidate custody and recovers an uncertain durable reply", async () => {
  const hk = await import("../dist/index.js"), fixtures = await import("../dist/testing.js");
  const { AdmissionProviderFixture } = await import("./support/admission-provider.mjs");
  const provider = new AdmissionProviderFixture();
  const senderStore = new InMemoryStateStore(), senderKeys = new InMemoryDeviceKeyStore();
  const sender = new HyperKeyHost({persistence:senderStore,sealing:senderKeys,commitOutcome,admissions:provider,group:{async stageFounder(input){return stagedFounder(input);}}});
  const founder = copy("sender"), key = await sender.create({groupId:"atomic_install_01234567890123456789",founder});
  const recipientStore = new InMemoryStateStore(), recipientKeys = new InMemoryDeviceKeyStore();
  const recipientOptions = {persistence:recipientStore,sealing:recipientKeys,commitOutcome,admissions:provider,group:{async stageFounder(input){return stagedFounder(input);}},candidates:{async stageCandidate(input) {
    const member = {signingKeyFingerprint:Buffer.alloc(32,71).toString("base64url")};
    return {member,keyPackage:text.encode("independent recipient KeyPackage"),stagedGroup:{...stagedFounder({...input,founder:{member}}),kind:"key-package",transitionId:"independent-candidate"}};
  }}};
  const recipient = new HyperKeyHost(recipientOptions);
  const candidate = await recipient.createCopyCandidate({descriptor:key.descriptor,evidence:text.encode("candidate evidence"),copyId:"candidate_atomic_01234567890123456789"});
  const admissionId="admission_atomic_01234567890123456789";
  await recipient.requestCopy({descriptorId:key.id,copyId:candidate.copy.copyId,admissionId,invitationId:"invitation_atomic_01234567890123456789",evidence:text.encode("candidate evidence"),proof:text.encode("candidate proof"),requestedAtMs:1000,expiresAtMs:9000});
  const actor = {member:founder.member,authentication:text.encode("actor proof")};
  const {selectedCommitId}=await recipient.approveCopy(key.descriptor.groupId,candidate.copy.copyId,admissionId,{approval:actor,selection:actor});
  const prior = await recipient.state.nativeGroupStorage().read(key.descriptor.groupId,candidate.copy.member);
  await recipient.installCopyGroup({descriptorId:key.id,copyId:candidate.copy.copyId,admissionId,selectedCommitId,transition:{schema:"group-foundation.group.native-transition.v1",transitionId:"installed-recipient-join",kind:"join",expectedRevision:0,next:{...prior,revision:1,epoch:"1"},outbox:[]}});
  await recipient.acknowledgeCopyInstallation({groupId:key.descriptor.groupId,admissionId,selectedCommitId,recipient:candidate.copy.member,proof:text.encode("recipient proof"),installedAtMs:1001});
  const directory = new fixtures.InMemoryHyperKeyAdmittedCopyDirectory();
  directory.put(key.descriptor.groupId,founder);directory.put(key.descriptor.groupId,candidate.copy);
  const binding={descriptorId:key.id,groupId:key.descriptor.groupId,profile:hk.HYPERKEY_GROUP_PROFILE,senderCopyId:founder.copyId,recipientCopyId:candidate.copy.copyId,recipientDeliveryKey:candidate.copy.recipientDeliveryKey,admissionId,selectedCommitId,deliveryId:Buffer.alloc(32,91).toString("base64url")};
  const applicationMessage=hk.hyperKeyApplicationTranscript(binding);
  const boundary=new hk.HyperKeyApplicationDeliveryBoundary({async authenticate({direction}) {
    const member=direction === "send" ? founder.member : candidate.copy.member;
    return {groupId:binding.groupId,profile:binding.profile,senderMemberSigningKeyFingerprint:founder.member.signingKeyFingerprint,transition:{schema:"group-foundation.group.native-transition.v1",transitionId:`authenticated-${direction}`,kind:direction === "send" ? "application-send" : "application-receive",expectedRevision:1,next:{schema:"group-foundation.group.native-state.v1",groupId:binding.groupId,profile:binding.profile,member,revision:2,epoch:"1",snapshot:text.encode("explicit durable authenticated state")},outbox:direction === "send" ? [{id:"sealed-frame",kind:"application",bytes:applicationMessage,digest:Buffer.alloc(32,92).toString("base64url")}] : []}};
  }},directory);
  await sender.state.copyAdmissionRecords().put({admissionId,groupId:binding.groupId,profile:hk.HYPERKEY_GROUP_PROFILE,copy:candidate.copy});
  const sendAuthentication=await boundary.authenticateForSend(binding,applicationMessage);
  const delivery=await sender.preparePrivateDelivery({descriptor:key.descriptor,recipientCopyId:candidate.copy.copyId,senderCopyId:founder.copyId,admissionId,selectedCommitId,recipientDeliveryKey:fromBase64url(candidate.copy.recipientDeliveryKey,32),deliveryId:fromBase64url(binding.deliveryId,32),authenticatedSender:sendAuthentication});
  const authenticatedSender=await boundary.authenticateForReceive(binding,applicationMessage);
  const before=structuredClone(recipientStore.records),revision=recipientStore.semanticRevision;
  recipientStore.failure=true;
  await assert.rejects(recipient.installPrivateDelivery({delivery,authenticatedSender}),/physical failure/);
  assert.deepEqual(recipientStore.records,before);
  assert.equal(recipientStore.semanticRevision,revision);
  assert.equal(await recipient.open(key.id,candidate.copy.copyId),undefined);
  assert.ok(await recipient.state.candidateDeliveryKey(key.id,candidate.copy.copyId));
  recipientStore.failure=false;
  recipientStore.uncertain=Object.assign(new Error("lost recipient install reply"),{code:"unknown-physical-commit"});
  await assert.rejects(recipient.installPrivateDelivery({delivery,authenticatedSender}),/lost recipient install reply/);
  await assert.rejects(recipient.list(),/closed; reopen/);
  recipientStore.uncertain=undefined;
  const reopened = new HyperKeyHost(recipientOptions);
  const installed=await reopened.installPrivateDelivery({delivery,authenticatedSender});
  assert.equal(installed.status,"ready");
  assert.equal(await reopened.state.candidateDeliveryKey(key.id,candidate.copy.copyId),undefined);
  assert.equal((await reopened.copyProgress(key.id,candidate.copy.copyId)).step,"ready");
  assert.deepEqual(await installed.sign(text.encode("same key")),await key.sign(text.encode("same key")));
  const altered={...delivery,schema:"zagel.hyperkey.private-delivery.v1"};
  await assert.rejects(hk.decryptPrivateSeedDelivery(altered,key.descriptor,{}, {recipientCopyId:candidate.copy.copyId,admissionId,selectedCommitId}),/schema/);
});

test("product and Copy index capacity fail before any staged record becomes visible",async()=>{
  for(const indexName of ["product-index","copy-index"]){
    const store=new InMemoryStateStore(),sealing=new InMemoryDeviceKeyStore(),host=composition(store,sealing,[]);
    const key=await host.create({groupId:`index_bound_${indexName.replaceAll("-","_")}_0123456789`,founder:copy("capacity")});
    const indexKey=[...store.records.keys()].find(key=>key.endsWith(`hyperkey/${indexName}/v1`));
    await host.state.transaction([indexKey],records=>records.set(indexKey,{schema:"hyperkey.product-index.v1",entries:Array.from({length:256},(_,index)=>({descriptorId:key.id,copyId:`bounded_copy_${index}`}))}));
    const before=structuredClone(store.records),revision=store.semanticRevision;
    await assert.rejects(host.create({groupId:`new_index_bound_${indexName.replaceAll("-","_")}_0123456789`,founder:copy("extra")}),/index exceeds its bound/);
    assert.deepEqual(store.records,before);assert.equal(store.semanticRevision,revision);
  }
});
