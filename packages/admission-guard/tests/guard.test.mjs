import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import test from 'node:test';
import { AdmissionGuardError, AdmissionWireError, ClaimPolicyError } from '@group-foundation/admission-guard/contracts';
import { parseAdmissionEvidenceRequestV1, parseAdmissionEvidenceEvaluationV1, parseEvidenceRequestBindingV1, parseClaimEvidenceV1 } from '@group-foundation/admission-guard/wire';
import { defineClaimPolicyV1, parseClaimPolicyV1, createClaimPolicyPinV1, assertClaimReleaseConsentV1, evaluateClaimEvidenceV1 } from '@group-foundation/admission-guard/policy';
import { createAdmissionEvidenceRequestV1, assertAdmissionEvidenceRequestV1, verifyAdmissionEvidenceRequestIntegrityV1, evaluateAdmissionEvidenceV1, assertAdmissionEvidenceEvaluationV1, verifyAdmissionSignedEvidenceV1 } from '@group-foundation/admission-guard/guard';
import * as root from '@group-foundation/admission-guard';

const sha256 = { sha256: async bytes => new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes)) };
const digestA = 'A'.repeat(43), digestB = 'B'.repeat(42) + 'A';
const disclosure = (rawValue = false, scopedIdentifier = false) => ({ assertion: true, rawValue, scopedIdentifier });
const claim = (claimId = 'qualification', options = {}) => ({ claimId, predicate: { kind: 'issuer-claim', issuer: 'issuer:credentials', claim: 'qualified' }, required: true,
  verification: { maximumAgeSeconds: 60, methods: ['signed-credential'] }, disclosure: disclosure(), ...options });
const definition = (claims = [claim()], revision = 1) => ({ schema: 'group-foundation.claim-policy.v1', policyId: 'policy:join', revision, claims });
const bindingFor = policy => ({ scopeId: 'scope:workspace', policyId: policy.policyId, policyRevision: policy.revision, policyDigest: policy.digest,
  target: 'target:room', recipient: 'recipient:service', audience: 'audience:room', purpose: 'purpose:join', subjectCommitment: digestA, nonce: digestB });
const requestDefinition = (binding, claims = [{ claimId: 'qualification', disclosure: disclosure() }]) => ({ schema: 'group-foundation.admission-evidence-request.v1', binding, issuedAt: 100, expiresAt: 200, claims });
const evidence = (overrides = {}) => ({ claimId: 'qualification', assertion: true, verifiedAt: 90, verificationExpiresAt: 300,
  verificationMethod: 'signed-credential', verificationIssuer: 'issuer:credentials', issuedAt: 100, expiresAt: 200, ...overrides });
async function fixture(policyDefinition = definition(), claims) {
  const policy = await defineClaimPolicyV1(policyDefinition, sha256), binding = bindingFor(policy);
  const request = await createAdmissionEvidenceRequestV1(requestDefinition(binding, claims), policy, sha256);
  return { policy, binding, request, evidence: [evidence()], now: 110 };
}
const guardRejects = promise => assert.rejects(promise, error => error instanceof AdmissionGuardError && error.message === 'admission-evidence-invalid');
const policyRejects = promise => assert.rejects(promise, ClaimPolicyError);

test('all public subpaths are standalone and the SHA-256 port accepts Web Crypto', async () => {
  assert.equal(root.AdmissionGuardError, AdmissionGuardError);
  const input = await fixture();
  assert.equal(input.policy.digest, '69iY5s_05z-v5Sdj_yH0RJR69ujbHNyT_-BKEIZFCUk');
  assert.equal(input.request.requestId, 'y6mIjG6Ol2sqOgwISyTDYcGe_DKK-Be9DxRTAzfP2GI');
  const result = await evaluateAdmissionEvidenceV1(input, sha256);
  assert.deepEqual(result.disclosures, [{ claimId: 'qualification', assertion: true }]);
  assert.equal(result.evidenceFreshUntil, 150);
  assert.ok(Object.isFrozen(result));
  assert.ok(Object.isFrozen(result.binding));
  assert.ok(Object.isFrozen(result.disclosures[0]));
  assert.deepEqual(await assertAdmissionEvidenceEvaluationV1({ ...input, evaluation: result }, sha256), result);
  assert.deepEqual(await parseClaimPolicyV1(input.policy, sha256), input.policy);
});

test('canonical policy/request digests ignore input field/claim/method order and use code-unit ordering', async () => {
  const claims = [claim('ä', { verification: { maximumAgeSeconds: 60, methods: ['z', 'a'] } }), claim('z')];
  const first = await defineClaimPolicyV1(definition(claims), sha256);
  const second = await defineClaimPolicyV1({ claims: [{ ...claims[1] }, { ...claims[0], verification: { maximumAgeSeconds: 60, methods: ['a', 'z'] } }], revision: 1, policyId: 'policy:join', schema: 'group-foundation.claim-policy.v1' }, sha256);
  assert.equal(first.digest, second.digest);
  assert.deepEqual(first.claims.map(item => item.claimId), ['z', 'ä']);
  const requests = claims.map(item => ({ claimId: item.claimId, disclosure: disclosure() }));
  const binding = bindingFor(first);
  const a = await createAdmissionEvidenceRequestV1(requestDefinition(binding, requests), first, sha256);
  const b = await createAdmissionEvidenceRequestV1(requestDefinition({ ...binding }, [...requests].reverse()), second, sha256);
  assert.equal(a.requestId, b.requestId);
  assert.deepEqual(a.claims.map(item => item.claimId), ['z', 'ä']);
  assert.deepEqual(await verifyAdmissionEvidenceRequestIntegrityV1(a, sha256), a);
  assert.equal(a.requestId.length, 43);
});

test('every scope, audience, nonce, subject and policy field is digest-bound and independently expected', async () => {
  const input = await fixture();
  const substitutes = { scopeId: 'scope:other', target: 'target:other', recipient: 'recipient:other', audience: 'audience:other', purpose: 'purpose:other', subjectCommitment: digestB, nonce: digestA };
  for (const [key, value] of Object.entries(substitutes)) {
    const changed = { ...input.binding, [key]: value };
    await guardRejects(assertAdmissionEvidenceRequestV1({ ...input.request, binding: changed }, input.policy, input.binding, 110, sha256));
    const rehashed = await createAdmissionEvidenceRequestV1(requestDefinition(changed), input.policy, sha256);
    assert.notEqual(rehashed.requestId, input.request.requestId);
    await guardRejects(evaluateAdmissionEvidenceV1({ ...input, request: rehashed }, sha256));
    await guardRejects(evaluateAdmissionEvidenceV1({ ...input, binding: changed }, sha256));
  }
  for (const change of [{ policyId: 'policy:other' }, { policyRevision: 2 }, { policyDigest: digestA }]) {
    await guardRejects(createAdmissionEvidenceRequestV1(requestDefinition({ ...input.binding, ...change }), input.policy, sha256));
  }
  const newer = await defineClaimPolicyV1(definition([claim()], 2), sha256);
  await guardRejects(evaluateAdmissionEvidenceV1({ ...input, policy: newer }, sha256));
  await policyRejects(parseClaimPolicyV1({ ...input.policy, revision: 2 }, sha256));
});

test('request times, disclosure and complete claim set are part of the canonical request ID', async () => {
  const input = await fixture(definition([claim('qualification', { disclosure: disclosure(true) })]));
  for (const change of [{ issuedAt: 99 }, { expiresAt: 201 }, { claims: [{ claimId: 'qualification', disclosure: disclosure(true) }] }]) {
    await guardRejects(verifyAdmissionEvidenceRequestIntegrityV1({ ...input.request, ...change }, sha256));
    const changed = await createAdmissionEvidenceRequestV1({ ...requestDefinition(input.binding), ...change }, input.policy, sha256);
    assert.notEqual(changed.requestId, input.request.requestId);
  }
});

test('expiry is exclusive for requests, evidence, verification, presentation and retained evaluations', async () => {
  const input = await fixture();
  await guardRejects(evaluateAdmissionEvidenceV1({ ...input, now: 99 }, sha256));
  await guardRejects(evaluateAdmissionEvidenceV1({ ...input, now: 200 }, sha256));
  await guardRejects(evaluateAdmissionEvidenceV1({ ...input, now: 150 }, sha256));
  for (const change of [{ expiresAt: 110 }, { issuedAt: 111 }, { verifiedAt: 101 }, { verificationExpiresAt: 90 }, { verificationExpiresAt: 199 }, { verifiedAt: 49 }]) {
    await guardRejects(evaluateAdmissionEvidenceV1({ ...input, evidence: [evidence(change)] }, sha256));
  }
  const result = await evaluateAdmissionEvidenceV1(input, sha256);
  await guardRejects(assertAdmissionEvidenceEvaluationV1({ ...input, evaluation: result, now: 150 }, sha256));
  await guardRejects(assertAdmissionEvidenceEvaluationV1({ ...input, evaluation: result, now: 109 }, sha256));
  assert.deepEqual((await assertAdmissionEvidenceEvaluationV1({ ...input, evaluation: result, now: 149 }, sha256)).disclosures, result.disclosures);
  const evidenceDeadline = await evaluateAdmissionEvidenceV1({ ...input, evidence: [evidence({ expiresAt: 130 })] }, sha256);
  assert.equal(evidenceDeadline.evidenceFreshUntil, 130);
  const shortRequest = await createAdmissionEvidenceRequestV1({ ...requestDefinition(input.binding), expiresAt: 120 }, input.policy, sha256);
  assert.equal((await evaluateAdmissionEvidenceV1({ ...input, request: shortRequest }, sha256)).evidenceFreshUntil, 120);
  for (const change of [{ issuedAt: 100, expiresAt: 100 }, { issuedAt: 100, expiresAt: 1001 }, { issuedAt: -1 }, { expiresAt: Infinity }]) {
    await guardRejects(createAdmissionEvidenceRequestV1({ ...requestDefinition(input.binding), ...change }, input.policy, sha256));
  }
});

test('only the exact requested and policy-authorized disclosure is accepted', async () => {
  const input = await fixture(definition([claim('qualification', { disclosure: disclosure(true, true) })]));
  await guardRejects(evaluateAdmissionEvidenceV1({ ...input, evidence: [evidence({ value: 'not-requested' })] }, sha256));
  await guardRejects(evaluateAdmissionEvidenceV1({ ...input, evidence: [evidence({ privateIdentifier: `v1.room.${digestA}` })] }, sha256));
  const all = await fixture(definition([claim('qualification', { disclosure: disclosure(true, true) })]), [{ claimId: 'qualification', disclosure: disclosure(true, true) }]);
  await guardRejects(evaluateAdmissionEvidenceV1(all, sha256));
  const result = await evaluateAdmissionEvidenceV1({ ...all, evidence: [evidence({ value: 'qualified', privateIdentifier: `v1.room.${digestA}` })] }, sha256);
  assert.deepEqual(result.disclosures, [{ claimId: 'qualification', assertion: true, value: 'qualified', privateIdentifier: `v1.room.${digestA}` }]);
  const restrictive = await fixture();
  await guardRejects(createAdmissionEvidenceRequestV1(requestDefinition(restrictive.binding, [{ claimId: 'qualification', disclosure: disclosure(true) }]), restrictive.policy, sha256));
  await guardRejects(evaluateAdmissionEvidenceV1({ ...restrictive, evidence: [evidence({ assertion: false })] }, sha256));
  const { assertion: _assertion, ...withoutAssertion } = evidence();
  await guardRejects(evaluateAdmissionEvidenceV1({ ...restrictive, evidence: [withoutAssertion] }, sha256));
});

test('missing, duplicate, unknown, unverified and wrong-issuer evidence fail closed', async () => {
  const input = await fixture();
  for (const items of [[], [evidence(), evidence()], [evidence({ claimId: 'unknown' })], [evidence({ verificationMethod: 'untrusted' })], [evidence({ verificationIssuer: 'issuer:other' })]]) {
    await guardRejects(evaluateAdmissionEvidenceV1({ ...input, evidence: items }, sha256));
  }
  await guardRejects(createAdmissionEvidenceRequestV1(requestDefinition(input.binding, []), input.policy, sha256));
  await guardRejects(createAdmissionEvidenceRequestV1(requestDefinition(input.binding, [{ claimId: 'unknown', disclosure: disclosure() }]), input.policy, sha256));
  await policyRejects(evaluateClaimEvidenceV1(input.policy, input.binding, [], 110, sha256));
});

test('release consent is bound to every scope field and allowed disclosure', async () => {
  const input = await fixture();
  const consent = { scope: input.binding, claimId: 'qualification', disclosure: disclosure() };
  await assertClaimReleaseConsentV1(input.policy, input.binding, 'qualification', consent, sha256);
  for (const scope of [{ ...input.binding, nonce: digestA }, { ...input.binding, audience: 'other' }, { ...input.binding, scopeId: 'other' }]) {
    await policyRejects(assertClaimReleaseConsentV1(input.policy, input.binding, 'qualification', { ...consent, scope }, sha256));
  }
  for (const change of [{ claimId: 'other' }, { disclosure: disclosure(true) }, { extra: true }]) {
    await policyRejects(assertClaimReleaseConsentV1(input.policy, input.binding, 'qualification', { ...consent, ...change }, sha256));
  }
});

test('current policy pins reject rollback and same-revision forks', async () => {
  const first = await defineClaimPolicyV1(definition(), sha256);
  const newer = await defineClaimPolicyV1(definition([claim()], 2), sha256);
  const fork = await defineClaimPolicyV1(definition([claim('qualification', { required: false })], 2), sha256);
  const pin = createClaimPolicyPinV1(sha256);
  await pin(first); await pin(newer); await pin(newer);
  await policyRejects(pin(first)); await policyRejects(pin(fork));
});

test('signed verification passes exact immutable bindings and supports asynchronous evidence adapters', async () => {
  const input = await fixture(), calls = [];
  const verifier = {
    async verifyPresentation(value, binding) {
      calls.push('presentation'); assert.equal(value, 'signed-subject'); assert.deepEqual(binding, input.binding);
      assert.ok(Object.isFrozen(binding));
      return { issuedAt: 100, expiresAt: 200, value: { subject: 'opaque' } };
    },
    async verifyEvidence(value, context) {
      calls.push('evidence'); assert.equal(value, 'signed-claim'); assert.deepEqual(context.request, input.request);
      assert.ok(Object.isFrozen(context.request.claims[0].disclosure)); assert.ok(Object.isFrozen(context.policy));
      assert.equal(context.now, 110);
      return { evidence: evidence(), value: { signed: 'opaque' } };
    },
  };
  const result = await verifyAdmissionSignedEvidenceV1({ ...input, claims: input.request.claims, presentation: 'signed-subject', evidence: ['signed-claim'], verifier }, sha256);
  assert.deepEqual(calls, ['presentation', 'evidence']);
  assert.deepEqual(result.presentation, { subject: 'opaque' });
  assert.deepEqual(result.evidence, [{ signed: 'opaque' }]);
  assert.equal(result.evaluation.requestId, input.request.requestId);
});

test('presentation failures and stale lifetimes stop before evidence cryptography', async () => {
  const input = await fixture();
  for (const presentation of [null, {}, { issuedAt: 111, expiresAt: 200, value: true }, { issuedAt: 100, expiresAt: 110, value: true }, { issuedAt: 0, expiresAt: 2000, value: true }]) {
    let evidenceCalls = 0;
    await guardRejects(verifyAdmissionSignedEvidenceV1({ ...input, now: presentation?.issuedAt === 0 ? 1000 : 110, claims: input.request.claims, presentation: 'signed', evidence: ['claim'], verifier: {
      async verifyPresentation() { return presentation; },
      async verifyEvidence() { evidenceCalls++; return { evidence: evidence(), value: true }; },
    } }, sha256));
    assert.equal(evidenceCalls, 0);
  }
  for (const stage of ['presentation', 'evidence']) {
    await guardRejects(verifyAdmissionSignedEvidenceV1({ ...input, claims: input.request.claims, presentation: 'signed', evidence: ['claim'], verifier: {
      async verifyPresentation() { if (stage === 'presentation') throw new Error('secret verifier details'); return { issuedAt: 100, expiresAt: 200, value: true }; },
      async verifyEvidence() { throw new Error('secret verifier details'); },
    } }, sha256));
  }
});

test('evaluations cannot be substituted, extended, overdisclosed, duplicated or future-dated', async () => {
  const input = await fixture(), evaluation = await evaluateAdmissionEvidenceV1(input, sha256);
  for (const change of [{ requestId: digestA }, { binding: { ...input.binding, nonce: digestA } }, { requestIssuedAt: 99 }, { requestExpiresAt: 201 }, { evaluatedAt: 111 }, { evidenceFreshUntil: 201 }, { disclosures: [] }, { disclosures: [{ claimId: 'qualification', assertion: true, value: 'extra' }] }, { disclosures: [evaluation.disclosures[0], evaluation.disclosures[0]] }]) {
    await guardRejects(assertAdmissionEvidenceEvaluationV1({ ...input, evaluation: { ...evaluation, ...change } }, sha256));
  }
});

test('wire and guard reject unknown fields at every nesting level', async () => {
  const input = await fixture(), { request, policy } = input;
  for (const bad of [{ ...request, extra: true }, { ...request, binding: { ...request.binding, extra: true } }, { ...request, claims: [{ ...request.claims[0], extra: true }] }, { ...request, claims: [{ claimId: 'qualification', disclosure: { ...disclosure(), extra: true } }] }]) {
    assert.throws(() => parseAdmissionEvidenceRequestV1(bad), AdmissionWireError);
    await guardRejects(verifyAdmissionEvidenceRequestIntegrityV1(bad, sha256));
  }
  const policyClaim = policy.claims[0];
  for (const bad of [{ ...policy, extra: true }, { ...policy, claims: [{ ...policyClaim, extra: true }] }, { ...policy, claims: [{ ...policyClaim, predicate: { ...policyClaim.predicate, extra: true } }] }, { ...policy, claims: [{ ...policyClaim, verification: { ...policyClaim.verification, extra: true } }] }, { ...policy, claims: [{ ...policyClaim, disclosure: { ...policyClaim.disclosure, extra: true } }] }]) {
    await policyRejects(parseClaimPolicyV1(bad, sha256));
  }
  await guardRejects(evaluateAdmissionEvidenceV1({ ...input, evidence: [evidence({ extra: true })] }, sha256));
  const evaluation = await evaluateAdmissionEvidenceV1(input, sha256);
  assert.throws(() => parseAdmissionEvidenceEvaluationV1({ ...evaluation, extra: true }), AdmissionWireError);
});

test('malformed JSON vocabulary, digests, sparse arrays and explicit undefined are refused', async () => {
  const input = await fixture();
  for (const bad of [null, [], true, 'request', {}, new Date(), { ...input.binding, nonce: 'A'.repeat(42) + 'B' }, { ...input.binding, subjectCommitment: 'short' }, { ...input.binding, scopeId: 'bad\nvalue' }, { ...input.binding, policyRevision: NaN }, { ...input.binding, [Symbol('hidden')]: true }]) {
    assert.throws(() => parseEvidenceRequestBindingV1(bad), AdmissionWireError);
  }
  for (const change of [{ assertion: undefined }, { value: undefined }, { privateIdentifier: undefined }, { verificationIssuer: undefined }, { issuedAt: 1.5 }, { expiresAt: Number.MAX_SAFE_INTEGER + 1 }, { privateIdentifier: `v1.room.${'A'.repeat(42)}B` }]) {
    assert.throws(() => parseClaimEvidenceV1(evidence(change)), AdmissionWireError);
  }
  const accessor = { ...input.binding };
  Object.defineProperty(accessor, 'nonce', { enumerable: true, get() { throw new Error('must not execute'); } });
  assert.throws(() => parseEvidenceRequestBindingV1(accessor), AdmissionWireError);
  const sparse = Array(1), extra = [...input.request.claims]; extra.extra = true;
  class CustomArray extends Array {}
  for (const claims of [new CustomArray(input.request.claims[0]), sparse, extra, Array(33).fill(input.request.claims[0]), [input.request.claims[0], input.request.claims[0]]]) {
    await guardRejects(createAdmissionEvidenceRequestV1({ ...requestDefinition(input.binding), claims }, input.policy, sha256));
  }
  for (const claims of [[claim(), claim()], [claim('qualification', { required: 'yes' })], [claim('qualification', { verification: { maximumAgeSeconds: 0, methods: ['signed-credential'] } })], [claim('qualification', { verification: { maximumAgeSeconds: 60, methods: ['same', 'same'] } })], [claim('qualification', { predicate: { kind: 'unknown' } })]]) {
    await policyRejects(defineClaimPolicyV1(definition(claims), sha256));
  }
});

test('hash port failure and malformed digest output fail closed', async () => {
  const input = await fixture();
  for (const bad of [{ sha256() { throw new Error('secret hash failure'); } }, { sha256: async () => new Uint8Array(31) }, { sha256: () => 'A'.repeat(43) }]) {
    await policyRejects(defineClaimPolicyV1(definition(), bad));
    await guardRejects(verifyAdmissionEvidenceRequestIntegrityV1(input.request, bad));
  }
});

test('untrusted request/evidence/policy inputs are snapshotted before awaiting host hashing', async () => {
  const input = await fixture();
  const mutable = structuredClone(input);
  let calls = 0;
  const hash = { async sha256(bytes) {
    if (calls++ === 0) { mutable.request.binding.audience = 'changed'; mutable.evidence[0].expiresAt = 0; mutable.policy.claims[0].verification.maximumAgeSeconds = 1; }
    return sha256.sha256(bytes);
  } };
  const result = await evaluateAdmissionEvidenceV1(mutable, hash);
  assert.equal(result.binding.audience, input.binding.audience);
  assert.equal(result.evidenceFreshUntil, 150);
});

test('production sources contain no product imports, Node crypto, Buffer, or locale-dependent ordering', async () => {
  const directory = new URL('../src/', import.meta.url);
  for (const name of await readdir(directory)) {
    const source = await readFile(new URL(name, directory), 'utf8');
    assert.doesNotMatch(source, /(?:node:|\bBuffer\b|localeCompare|@kord96|hafez)/u, name);
  }
});
