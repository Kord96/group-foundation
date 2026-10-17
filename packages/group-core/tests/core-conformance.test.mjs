import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash, createPublicKey, verify } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { GROUP_MEMBER_ID_DOMAIN, GROUP_SIDECAR_PREFIX, GroupError, assertNativeGroupState, assertStagedNativeGroupTransition } from '@group-foundation/group-core';
import { canonicalJson, bytesToBase64url, base64urlToBytes } from '@group-foundation/group-core/encoding';
import { InMemoryNativeGroupStorage } from '@group-foundation/group-core/testing';
import * as native from '@group-foundation/group-core/native';
await native.default({ module_or_path: await readFile(new URL(import.meta.resolve('@group-foundation/group-core/native-wasm'))) });
const b = value => new TextEncoder().encode(value);
const authority = () => new native.NativeAuthorityFacts(7n, 10000n, 9n, 10000n);
const keyObject = signingKey => createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), signingKey]), format: 'der', type: 'spki' });

test('Foundation member fingerprint vector and canonical primitives have one current encoding', async () => {
  const vector = JSON.parse(await readFile(new URL('../spec/vectors/member-fingerprint-v1.json', import.meta.url), 'utf8'));
  const signingKey = new Uint8Array(Buffer.from(vector.signingKeyHex, 'hex'));
  assert.equal(vector.domain, GROUP_MEMBER_ID_DOMAIN);
  const expected = createHash('sha256').update(b(GROUP_MEMBER_ID_DOMAIN)).update(signingKey).digest();
  assert.equal(bytesToBase64url(native.member_fingerprint(signingKey)), vector.fingerprintBase64url);
  assert.equal(Buffer.from(native.member_fingerprint(signingKey)).toString('hex'), vector.fingerprintHex);
  assert.deepEqual(native.member_fingerprint(signingKey), new Uint8Array(expected));
  assert.equal(canonicalJson({ z: [2, true], a: 'first' }), '{"a":"first","z":[2,true]}');
  assert.deepEqual(base64urlToBytes('AAECAw', 4, 'vector'), Uint8Array.of(0, 1, 2, 3));
  for (const value of ['AAECAw=', 'AAECAx', '+A', '']) assert.throws(() => base64urlToBytes(value, 4, 'vector'), GroupError);
  assert.throws(() => canonicalJson({ bad: 1.5 }), GroupError);
});

test('generic Remove stages exact detached custody and surviving peers authenticate its commit', () => {
  const groupId = b('foundation-remove-group'), profile = b('generic.v1'), facts = authority();
  let founder = new native.NativeClient(b('founder evidence'));
  founder = native.NativeClient.fromSnapshot(founder.createGroup(groupId, profile, facts, 100n).snapshot);
  const join = (source, evidence) => {
    let recipient = new native.NativeClient(b(evidence));
    const kp = recipient.createKeyPackage(profile);
    recipient = native.NativeClient.fromSnapshot(kp.snapshot);
    const add = source.stageAdd(groupId, profile, kp.keyPackage, facts, 100n);
    const joined = recipient.stageJoin(groupId, profile, add.welcome, add.ratchetTree, facts, 100n);
    return { source: native.NativeClient.fromSnapshot(add.snapshot), recipient: native.NativeClient.fromSnapshot(joined.snapshot), add };
  };
  const first = join(founder, 'recipient evidence');
  const second = join(first.source, 'surviving peer evidence');
  founder = second.source;
  const recipient = native.NativeClient.fromSnapshot(first.recipient.stageApplyCommit(groupId, profile, second.add.commit, facts, 100n).snapshot);
  const before = founder.exportSnapshot();
  const removal = founder.stageRemove(groupId, profile, recipient.memberId(), facts, 101n);
  assert.equal(removal.priorEpoch, '2'); assert.equal(removal.epoch, '3');
  assert.deepEqual(founder.exportSnapshot(), before);
  const peerBefore = second.recipient.exportSnapshot();
  const applied = second.recipient.stageApplyCommit(groupId, profile, removal.commit, facts, 101n);
  assert.equal(applied.epoch, '3'); assert.deepEqual(applied.ratchetTree, removal.ratchetTree);
  assert.deepEqual(second.recipient.exportSnapshot(), peerBefore);
  for (const target of [founder.memberId(), new Uint8Array(31), new Uint8Array(32)]) assert.throws(() => founder.stageRemove(groupId, profile, target, facts, 101n));
  const expired = new native.NativeAuthorityFacts(7n, 100n, 9n, 100n);
  assert.throws(() => founder.stageRemove(groupId, profile, recipient.memberId(), expired, 101n));
  const tampered = removal.commit.slice(); tampered[tampered.length - 1] ^= 1;
  assert.throws(() => second.recipient.stageApplyCommit(groupId, profile, tampered, facts, 101n));
  assert.deepEqual(founder.exportSnapshot(), before);
  const sender = native.NativeClient.fromSnapshot(removal.snapshot), receiver = native.NativeClient.fromSnapshot(applied.snapshot);
  const sealed = sender.stageSealApplication(groupId, profile, b('after removal'), facts, 102n);
  assert.deepEqual(receiver.stageOpenApplication(groupId, profile, sealed.message).plaintext, b('after removal'));
});

test('Foundation custody rejects predecessor headers, foreign facade custody, and predecessor proof domains', () => {
  const generic = new native.NativeClient(b('generic evidence')), product = new native.NativeProductClient();
  const withMagic = (bytes, magic, offset = 0) => { const result = bytes.slice(); result.set(b(magic), offset); return result; };
  const genericSnapshot = generic.exportSnapshot(), custody = product.exportCustody();
  assert.equal(new TextDecoder().decode(genericSnapshot.slice(0, 5)), 'GFN01');
  assert.equal(new TextDecoder().decode(custody.slice(0, 5)), 'GFC01');
  assert.equal(new TextDecoder().decode(product.exportProviderState().slice(0, 5)), 'GFS01');
  assert.equal(new TextDecoder().decode(product.exportSigningState().slice(0, 5)), 'GFI01');
  assert.throws(() => native.NativeClient.fromSnapshot(withMagic(genericSnapshot, 'ZGN01')));
  assert.throws(() => native.NativeProductClient.fromCustody(withMagic(custody, 'ZGP01')));
  assert.throws(() => native.NativeProductClient.fromParts(withMagic(product.exportProviderState(), 'ZGG01'), product.exportSigningState()));
  assert.throws(() => native.NativeProductClient.fromParts(product.exportProviderState(), withMagic(product.exportSigningState(), 'ZGIK\x03')));
  assert.throws(() => native.NativeClient.fromSnapshot(custody));
  assert.throws(() => native.NativeProductClient.fromCustody(genericSnapshot));
  for (const domain of ['group-foundation.group.proof.v1', 'group-foundation.admission.candidate-proof.v1', 'group-foundation.admission.actor.v1', 'group-foundation.admission.installation-proof.v1']) {
    const transcript = b(canonicalJson({ domain, payload: 'exact operation' }));
    const proof = generic.signMemberProof(transcript);
    assert(verify(null, transcript, keyObject(proof.signingKey), proof.signature));
  }
  for (const transcript of [b('{"domain":"zagel.group.actor.v1"}'), b('{"domain":"zagel.group.actor.v1","payload":"group-foundation.group.proof.v1"}'), b('not json')]) assert.throws(() => generic.signMemberProof(transcript));
  assert.throws(() => product.stageRecords([{ key: b('zagel.predecessor.sidecar'), value: b('value') }]));
  assert.throws(() => product.stageRecords([{ key: b(GROUP_SIDECAR_PREFIX), value: b('value') }]));
  const key = new Uint8Array([...b(GROUP_SIDECAR_PREFIX), 0, 255, 1]);
  const staged = native.NativeProductClient.fromCustody(product.stageRecords([{ key, value: b('opaque suffix') }]));
  assert.deepEqual(staged.readRecord(key), b('opaque suffix'));
});

const state = () => ({ schema: 'group-foundation.group.native-state.v1', groupId: 'group-one', profile: 'generic.v1', member: { signingKeyFingerprint: 'independent-member' }, revision: 0, epoch: '0', snapshot: b('authenticated private custody') });
const transition = () => ({ schema: 'group-foundation.group.native-transition.v1', transitionId: 'create-one', kind: 'create', expectedRevision: null, next: state(), outbox: [{ id: 'initial-outbox', kind: 'commit', bytes: b('exact public bytes'), digest: 'validated-digest' }] });
test('reference transition writer atomically fences revisions, exact retries, and outbox identities', async () => {
  const storage = new InMemoryNativeGroupStorage(), initial = transition();
  assert.equal((await storage.commit(initial)).replayed, false);
  initial.next.snapshot.fill(0);
  assert.equal((await storage.commit(transition())).replayed, true);
  assert.deepEqual((await storage.read('group-one', state().member)).snapshot, state().snapshot);
  await assert.rejects(storage.commit({ ...transition(), outbox: [] }), error => error.code === 'conflict');
  const next = { ...transition(), transitionId: 'remove-one', kind: 'remove', expectedRevision: 0, next: { ...state(), revision: 1, epoch: '1' }, outbox: [{ id: 'remove-commit', kind: 'commit', bytes: b('remove wire'), digest: 'remove-digest' }] };
  assert.equal((await storage.commit(next)).state.revision, 1);
  await assert.rejects(storage.commit({ ...next, transitionId: 'stale-attempt', outbox: [] }), error => error.code === 'conflict');
  await assert.rejects(storage.commit({ ...next, transitionId: 'duplicate-outbox', expectedRevision: 1, next: { ...next.next, revision: 2 }, outbox: transition().outbox }), error => error.code === 'conflict');
  assert.equal((await storage.read('group-one', state().member)).revision, 1);
  assert.equal(storage.readOutbox().length, 2);
  assert.throws(() => assertNativeGroupState({ ...state(), schema: 'zagel.group.native-state.v1' }), GroupError);
  assert.throws(() => assertStagedNativeGroupTransition({ ...transition(), schema: 'zagel.group.native-transition.v1' }), GroupError);
  assert.throws(() => assertStagedNativeGroupTransition({ ...transition(), admission: {} }), GroupError);
});
