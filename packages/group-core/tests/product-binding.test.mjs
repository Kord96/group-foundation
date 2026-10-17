import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { createPublicKey, verify } from 'node:crypto';
import test from 'node:test';
import * as native from '../generated/foundation_group.js';
await native.default({ module_or_path: await readFile(new URL('../generated/foundation_group_bg.wasm', import.meta.url)) });
const b = value => new TextEncoder().encode(value);
const u = (...value) => new Uint8Array(value);
const empty = () => u();
const limits = { maxPastEpochs: 4, outOfOrderTolerance: 4, maxForwardDistance: 32 };
// Exact MLS TLS encodings: version 1, suite 1, dictionary extension 6,
// AppDataUpdate 8 and SelfRemove 10, BasicCredential 1; empty dictionary.
const profile = { ...limits, capabilities: u(2,0,1,2,0,1,2,0,6,4,0,8,0,10,2,0,1), contextExtensions: u(4,0,6,1,0), leafExtensions: u(0) };
const credential = value => { const data=b(value); return u(0,1,data.length,...data); };
const request = extra => ({ additions: [], removals: [], componentUpdates: [], ...extra });
const restore = stage => native.NativeProductClient.fromCustody(stage.custody);
const equal = (a,b) => assert.deepEqual(a,b);
function pair() {
  const groupId=b('opaque-product-group');
  const fresh=new native.NativeProductClient();
  const founder=restore(fresh.stageCreate(groupId,credential('founder evidence'),profile));
  const recipientFresh=new native.NativeProductClient();
  const kp=recipientFresh.stageKeyPackage(credential('recipient evidence'),profile);
  const recipient=restore(kp);
  const add=founder.stageCommit(groupId,request({ additions:[kp.keyPackage] }),b('product aad'));
  return {groupId,founder:restore(add),recipient:restore(recipient.stageJoin(add.welcome,limits)),add};
}

test('product facade stages authenticated generic profile, commit, join, and application custody', () => {
  const {groupId,founder,recipient,add}=pair();
  assert.equal(add.projection.epoch,'1');assert.equal(add.projection.members.length,2);
  equal(founder.inspect(groupId).context,recipient.inspect(groupId).context);
  equal(founder.inspect(groupId).members[0].credential,credential('founder evidence'));
  equal(founder.inspect(groupId).members[0].signingKey,founder.ownSigner());
  equal(native.NativeProductClient.fromParts(founder.exportProviderState(),founder.exportSigningState()).exportCustody(),founder.exportCustody());
  const before=founder.exportCustody();
  const update=founder.stageCommit(groupId,request({componentUpdates:[{id:42,value:b('opaque dictionary semantics')}]}),b('commit aad'));
  equal(founder.exportCustody(),before);
  const own=founder.stageProcess(groupId,update.commit,'ownCommit');
  assert.equal(own.selfRemoved,false);
  assert(own.proposals.length>0);
  for(const proposal of own.proposals){assert.equal(proposal.origin,'inline');assert.equal(proposal.reference,undefined);}
  equal(own.resultingContext,update.projection.context);
  assert.equal(own.projection.epoch,'1');
  const pending=native.NativeProductClient.fromCustody(update.pendingCustody);
  equal(pending.stageMergePending(groupId).projection.context,update.projection.context);
  const recipientBefore=recipient.exportCustody();
  assert.throws(()=>recipient.stageProcess(groupId,update.commit,'application'));
  const applied=recipient.stageProcess(groupId,update.commit,'member');
  assert.equal(applied.kind,'commit');assert.equal(applied.messageEpoch,'1');assert.equal(applied.projection.epoch,'2');
  equal(applied.aad,b('commit aad'));equal(applied.componentUpdates,[{id:42,value:b('opaque dictionary semantics')}]);
  equal(applied.projection.context,update.projection.context);equal(recipient.exportCustody(),recipientBefore);
  const sender=restore(update),receiver=restore(applied);
  const sealed=sender.stageSeal(groupId,b('opaque application'),b('application aad'));
  const opened=receiver.stageProcess(groupId,sealed.frame,'application');
  assert.equal(opened.kind,'application');equal(opened.plaintext,b('opaque application'));equal(opened.aad,b('application aad'));
  equal(opened.credential,credential('founder evidence'));
  equal(sender.exportSecret(groupId,'product exporter',b('context'),32),receiver.exportSecret(groupId,'product exporter',b('context'),32));
  const proof=sender.signProof(b('product proof domain transcript'));
  const key=createPublicKey({key:Buffer.concat([Buffer.from('302a300506032b6570032100','hex'),proof.signingKey]),format:'der',type:'spki'});
  assert(verify(null,b('product proof domain transcript'),key,proof.signature));
});

test('ownCommit removal facts use the parent local leaf for additions and terminal dictionary updates', () => {
  const {groupId,founder,recipient}=pair();
  const before=founder.exportCustody(),recipientBefore=recipient.exportCustody();
  const third=new native.NativeProductClient().stageKeyPackage(credential('third evidence'),profile);
  const add=founder.stageCommit(groupId,request({additions:[third.keyPackage]}),empty());
  assert.equal(founder.stageProcess(groupId,add.commit,'ownCommit').selfRemoved,false);
  const removal=founder.stageCommit(groupId,request({
    removals:[recipient.inspect(groupId).ownLeaf],
    componentUpdates:[{id:42,value:b('opaque terminal dictionary state')}],
  }),empty());
  const own=founder.stageProcess(groupId,removal.commit,'ownCommit');
  assert.equal(own.selfRemoved,false);equal(own.resultingContext,removal.projection.context);
  assert.equal(own.projection.active,true);assert.equal(own.projection.epoch,'1');
  assert.equal(recipient.stageProcess(groupId,removal.commit,'ownCommit').selfRemoved,true);
  assert.equal(recipient.stageProcess(groupId,removal.commit,'member').selfRemoved,true);
  const tampered=removal.commit.slice();tampered[tampered.length-1]^=1;
  assert.throws(()=>founder.stageProcess(groupId,tampered,'ownCommit'));
  equal(founder.exportCustody(),before);equal(recipient.exportCustody(),recipientBefore);
});

test('product facade authenticates queued proposals and selects exact references', () => {
  const {groupId,founder,recipient}=pair();
  const leave=recipient.stageSelfRemove(groupId,b('leave aad'));
  const received=founder.stageProcess(groupId,leave.frame,'member');
  assert.equal(received.kind,'proposal');assert.equal(received.proposals.length,1);
  assert.equal(received.proposals[0].origin,'reference');
  equal(received.aad,b('leave aad'));assert.equal(received.projection.pendingProposals.length,1);
  assert.equal(received.projection.pendingProposals[0].origin,'reference');
  equal(received.projection.pendingProposals[0].reference,received.proposals[0].reference);
  const queued=restore(received);
  assert.throws(()=>queued.stageCommit(groupId,request({proposalReferences:[u(1)]}),empty()));
  assert.throws(()=>queued.stageCommit(groupId,request({proposalReferences:[received.proposals[0].reference,received.proposals[0].reference]}),empty()));
  const omitted=queued.stageCommit(groupId,request({proposalReferences:[]}),empty());
  assert.equal(omitted.projection.members.length,2);
  const selected=queued.stageCommit(groupId,request({proposalReferences:[received.proposals[0].reference]}),empty());
  assert.equal(selected.projection.members.length,1);
  assert.equal(queued.stageProcess(groupId,selected.commit,'ownCommit').selfRemoved,false);
  const recipientQueued=restore(recipient.stageProcess(groupId,leave.frame,'member'));
  assert.equal(recipientQueued.stageProcess(groupId,selected.commit,'ownCommit').selfRemoved,true);
  const removed=recipientQueued.stageProcess(groupId,selected.commit,'member');
  assert.equal(removed.selfRemoved,true);assert.equal(removed.projection.active,false);
  assert.equal(removed.proposals[0].origin,'reference');
  equal(removed.proposals[0].reference,received.proposals[0].reference);
  const inactive=restore(removed);
  assert.equal(inactive.hasGroup(groupId),true);
  assert.equal(restore({custody:inactive.stageDelete(groupId)}).hasGroup(groupId),false);
  assert.equal(founder.inspect(groupId).pendingProposals.length,0);
});

test('product custody rejects malformed input and leaves source unchanged after failures', () => {
  const {groupId,founder,recipient}=pair();const before=founder.exportCustody();
  for(const invalid of [u(),u(...before,0),before.slice(0,-1),b('ZGN01')])assert.throws(()=>native.NativeProductClient.fromCustody(invalid));
  assert.throws(()=>founder.stageCreate(groupId,credential('duplicate'),profile));
  assert.throws(()=>founder.inspect(b('absent')));
  assert.throws(()=>founder.stageKeyPackage(credential('bad'),{...profile,capabilities:u(...profile.capabilities,0)}));
  assert.throws(()=>founder.stageJoin(u(0),limits));
  assert.throws(()=>founder.stageCommit(groupId,request({componentUpdates:[{id:42,value:u(1)},{id:42,value:u(2)}]}),empty()));
  assert.throws(()=>founder.stageCommit(groupId,request({additions:Array(1025).fill(u(0))}),empty()));
  assert.throws(()=>founder.stageCommit(groupId,request({additions:Array(2**32-1)}),empty()));
  assert.throws(()=>founder.stageCommit(groupId,request({removals:[-1]}),empty()));
  const commit=founder.stageCommit(groupId,request(),empty()).commit;commit[commit.length-1]^=1;
  assert.throws(()=>recipient.stageProcess(groupId,commit,'member'));
  assert.throws(()=>founder.stageProcess(groupId,u(1),'unknown'));
  assert.throws(()=>native.NativeProductClient.fromParts(founder.exportProviderState(),recipient.exportSigningState()).inspect(groupId));
  const wrongSigner=native.NativeProductClient.fromParts(founder.exportProviderState(),recipient.exportSigningState());
  assert.throws(()=>wrongSigner.hasGroup(groupId));assert.throws(()=>wrongSigner.stageDelete(groupId));
  for(const invalid of [empty(),new Uint8Array(256)]){
    assert.throws(()=>founder.hasGroup(invalid));assert.throws(()=>founder.stageDelete(invalid));
  }
  assert.equal(founder.hasGroup(b('absent')),false);assert.throws(()=>founder.stageDelete(b('absent')));
  equal(founder.exportCustody(),before);
});

test('terminal checkpoint deletes exactly its installed group and named sidecars while preserving live custody', () => {
  const {groupId,founder}=pair();
  const otherId=b('unrelated terminal test group');
  const owned=b('group-foundation.sidecar.terminal.owned'),foreign=b('group-foundation.sidecar.terminal.foreign');
  const both=restore(founder.stageCreate(otherId,credential('unrelated group'),profile));
  const anchor=native.NativeProductClient.fromCustody(both.stageRecords([{key:owned,value:b('terminal sidecar')},{key:foreign,value:b('unrelated sidecar')}]));
  const liveOther=anchor.stageSeal(otherId,b('unrelated live send'),empty());
  const current=native.NativeProductClient.fromCustody(restore(liveOther).stageRecords([{key:foreign,value:b('unrelated live record')}]));
  const anchorBefore=anchor.exportCustody(),currentBefore=current.exportCustody();
  const deleted=native.NativeProductClient.fromCustody(anchor.stageDelete(groupId));
  assert.equal(deleted.hasGroup(groupId),false);assert.equal(deleted.hasGroup(otherId),true);
  equal(deleted.inspect(otherId),anchor.inspect(otherId));
  equal(deleted.ownSigner(),anchor.ownSigner());equal(deleted.exportSigningState(),anchor.exportSigningState());
  equal(deleted.readRecord(owned),b('terminal sidecar'));equal(deleted.readRecord(foreign),b('unrelated sidecar'));
  equal(anchor.exportCustody(),anchorBefore);assert.equal(anchor.hasGroup(groupId),true);
  const selected=deleted.stageRecords([{key:owned,value:null}]);
  const installed=native.NativeProductClient.fromCustody(current.stageCheckpoint(anchorBefore,selected,groupId,[owned]));
  assert.equal(installed.hasGroup(groupId),false);assert.throws(()=>installed.inspect(groupId));
  assert.equal(installed.readRecord(owned),undefined);equal(installed.readRecord(foreign),b('unrelated live record'));
  // Retain the exact live ratchet state and all unrelated native/package/signing records.
  const expected=native.NativeProductClient.fromCustody(native.NativeProductClient.fromCustody(current.stageDelete(groupId)).stageRecords([{key:owned,value:null}]));
  equal(installed.exportCustody(),expected.exportCustody());
  assert.throws(()=>current.stageCheckpoint(anchorBefore,selected,groupId,[]));
  assert.throws(()=>current.stageCheckpoint(anchorBefore,deleted.stageDelete(otherId),groupId,[owned]));
  assert.throws(()=>current.stageCheckpoint(anchorBefore,deleted.stageRecords([{key:foreign,value:null}]),groupId,[owned]));
  assert.throws(()=>current.stageCheckpoint(anchorBefore,selected,otherId,[owned]));
  assert.throws(()=>current.stageCheckpoint(anchorBefore,anchorBefore,b('unknown terminal group'),[]));
  assert.throws(()=>current.stageCheckpoint(deleted.exportCustody(),deleted.exportCustody(),groupId,[]));
  assert.throws(()=>deleted.stageDelete(groupId));
  equal(current.exportCustody(),currentBefore);equal(anchor.exportCustody(),anchorBefore);
});

test('group existence and terminal checkpoint reject partially erased native state', () => {
  const {groupId,founder}=pair();
  const state=Buffer.from(founder.exportProviderState()),rows=[];
  const count=Number(state.readBigUInt64BE(5));let at=13;
  for(let i=0;i<count;i++){
    const start=at,keyLength=Number(state.readBigUInt64BE(at)),valueLength=Number(state.readBigUInt64BE(at+8));
    const key=state.subarray(at+16,at+16+keyLength);at+=16+keyLength+valueLength;
    if(!key.subarray(0,10).equals(Buffer.from('GroupState')))rows.push(state.subarray(start,at));
  }
  assert.equal(rows.length,count-1);
  const header=Buffer.from(state.subarray(0,13));header.writeBigUInt64BE(BigInt(rows.length),5);
  const partial=native.NativeProductClient.fromParts(Buffer.concat([header,...rows]),founder.exportSigningState());
  assert.throws(()=>partial.hasGroup(groupId));
  assert.throws(()=>partial.stageDelete(groupId));
  assert.throws(()=>founder.stageCheckpoint(founder.exportCustody(),partial.exportCustody(),groupId,[]));
  assert.equal(founder.hasGroup(groupId),true);
});

test('product checkpoint installs only named sidecars and exact group namespaces', () => {
  const {groupId,founder}=pair();
  const owned=b('group-foundation.sidecar.product.owned'),foreign=b('group-foundation.sidecar.product.foreign');
  const anchor=native.NativeProductClient.fromCustody(founder.stageRecords([{key:owned,value:b('old')},{key:foreign,value:b('preserved')}]));
  const current=native.NativeProductClient.fromCustody(anchor.stageRecords([{key:foreign,value:b('live unrelated update')}]));
  const transition=anchor.stageCommit(groupId,request({componentUpdates:[{id:7,value:b('candidate')}]}),empty());
  const selected=native.NativeProductClient.fromCustody(transition.custody);
  const withSidecar=selected.stageRecords([{key:owned,value:b('new')}]);
  const before=current.exportCustody();
  const installed=native.NativeProductClient.fromCustody(current.stageCheckpoint(anchor.exportCustody(),withSidecar,groupId,[owned]));
  equal(installed.readRecord(owned),b('new'));equal(installed.readRecord(foreign),b('live unrelated update'));
  assert.equal(installed.inspect(groupId).epoch,'2');equal(current.exportCustody(),before);
  assert.throws(()=>current.stageCheckpoint(anchor.exportCustody(),withSidecar,groupId,[]));
  const foreignChange=selected.stageRecords([{key:foreign,value:b('attack')}]);
  assert.throws(()=>current.stageCheckpoint(anchor.exportCustody(),foreignChange,groupId,[owned]));
  const otherId=b('other product group');
  const otherGroup=selected.stageCreate(otherId,credential('other group'),profile);
  assert.throws(()=>current.stageCheckpoint(anchor.exportCustody(),otherGroup.custody,groupId,[owned]));
  assert.throws(()=>current.stageCheckpoint(anchor.exportCustody(),new native.NativeProductClient().exportCustody(),groupId,[owned]));
  assert.throws(()=>current.stageRecords([{key:b('GroupContext'),value:u(1)}]));
  assert.throws(()=>current.stageRecords([{key:owned,value:u(1)},{key:owned,value:u(2)}]));
  const removed=native.NativeProductClient.fromCustody(anchor.stageRecords([{key:owned,value:null}]));
  assert.equal(removed.readRecord(owned),undefined);equal(current.exportCustody(),before);
});
