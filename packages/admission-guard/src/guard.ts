import { AdmissionGuardError } from './contracts.js';
import type {
  AdmissionClaimDisclosureV1, AdmissionClaimRequestV1, AdmissionEvidenceEvaluationV1,
  AdmissionEvidenceInputV1, AdmissionEvidenceRequestDefinitionV1, AdmissionEvidenceRequestV1,
  AdmissionSignedEvidenceEvaluationV1, AdmissionSignedEvidenceVerifierV1,
  ClaimEvidenceV1, ClaimPolicyV1, EvidenceRequestBindingV1, Sha256Port,
} from './contracts.js';
import { digest } from './digest.js';
import { assertEvidenceRequestBindingV1, equalEvidenceRequestBindingV1, evaluateClaimEvidenceV1, parseClaimPolicyV1 } from './policy.js';
import {
  parseAdmissionEvidenceEvaluationV1, parseAdmissionEvidenceRequestDefinitionV1,
  parseAdmissionEvidenceRequestV1, parseClaimEvidenceV1, parseEvidenceRequestBindingV1,
  wireArray, wireInteger,
} from './wire.js';

const fail = (): never => { throw new AdmissionGuardError(); };
const guarded = async <T>(operation: () => T | Promise<T>): Promise<T> => { try { return await operation(); } catch { return fail(); } };

function requestId(value: AdmissionEvidenceRequestDefinitionV1, sha256: Sha256Port): Promise<string> {
  const binding = value.binding;
  return digest('group-foundation.admission-evidence-request.v1\0' + JSON.stringify([
    value.schema, binding.scopeId, binding.policyId, binding.policyRevision, binding.policyDigest,
    binding.target, binding.recipient, binding.audience, binding.purpose, binding.subjectCommitment, binding.nonce,
    value.issuedAt, value.expiresAt,
    value.claims.map(claim => [claim.claimId, claim.disclosure.assertion, claim.disclosure.rawValue, claim.disclosure.scopedIdentifier]),
  ]), sha256);
}

function assertRequestedClaims(request: AdmissionEvidenceRequestV1 | AdmissionEvidenceRequestDefinitionV1, policy: ClaimPolicyV1): void {
  const requested = new Set(request.claims.map(claim => claim.claimId));
  if (policy.claims.some(claim => claim.required && !requested.has(claim.claimId)) || request.claims.some(claim => {
    const rule = policy.claims.find(item => item.claimId === claim.claimId);
    return !rule || (['assertion', 'rawValue', 'scopedIdentifier'] as const).some(key => claim.disclosure[key] && !rule.disclosure[key]);
  })) return fail();
}

/** Construct a canonical policy-pinned request, valid for at most 900 seconds. */
export async function createAdmissionEvidenceRequestV1(value: AdmissionEvidenceRequestDefinitionV1, policy: ClaimPolicyV1, sha256: Sha256Port): Promise<Readonly<AdmissionEvidenceRequestV1>> {
  return guarded(async () => {
    const request = parseAdmissionEvidenceRequestDefinitionV1(value);
    const current = await assertEvidenceRequestBindingV1(policy, request.binding, sha256);
    assertRequestedClaims(request, current);
    return Object.freeze({ ...request, requestId: await requestId(request, sha256) });
  });
}

/** Verify only the canonical digest; this does not establish the host's expected scope. */
export async function verifyAdmissionEvidenceRequestIntegrityV1(value: unknown, sha256: Sha256Port): Promise<Readonly<AdmissionEvidenceRequestV1>> {
  return guarded(async () => {
    const request = parseAdmissionEvidenceRequestV1(value);
    if (request.requestId !== await requestId(request, sha256)) return fail();
    return request;
  });
}

/** Require an exact independent host binding, current policy pin, authorized claims and freshness. */
export async function assertAdmissionEvidenceRequestV1(value: unknown, policy: ClaimPolicyV1, binding: EvidenceRequestBindingV1, now: number, sha256: Sha256Port): Promise<Readonly<AdmissionEvidenceRequestV1>> {
  return guarded(async () => {
    const expected = parseEvidenceRequestBindingV1(binding);
    const request = await verifyAdmissionEvidenceRequestIntegrityV1(value, sha256);
    const current = await assertEvidenceRequestBindingV1(policy, request.binding, sha256);
    if (!equalEvidenceRequestBindingV1(expected, request.binding) || !wireInteger(now) || now < request.issuedAt || now >= request.expiresAt) return fail();
    assertRequestedClaims(request, current);
    return request;
  });
}

function outputDisclosure(request: AdmissionClaimRequestV1, evidence: ClaimEvidenceV1): Readonly<AdmissionClaimDisclosureV1> {
  // Refuse overdisclosure instead of silently dropping signed fields.
  if (Object.hasOwn(evidence, 'assertion') !== request.disclosure.assertion
    || Object.hasOwn(evidence, 'value') !== request.disclosure.rawValue
    || Object.hasOwn(evidence, 'privateIdentifier') !== request.disclosure.scopedIdentifier) return fail();
  return Object.freeze({ claimId: request.claimId,
    ...(evidence.assertion === true ? { assertion: true as const } : {}),
    ...(evidence.value === undefined ? {} : { value: evidence.value }),
    ...(evidence.privateIdentifier === undefined ? {} : { privateIdentifier: evidence.privateIdentifier }),
  });
}

/**
 * Stateless evaluation of evidence already cryptographically authenticated and
 * bound to this request. The host must atomically consume requestId with its
 * durable effect; this package owns no replay ledger or admission authority.
 */
export async function evaluateAdmissionEvidenceV1(input: Readonly<{
  request: unknown; policy: ClaimPolicyV1; binding: EvidenceRequestBindingV1;
  evidence: readonly AdmissionEvidenceInputV1[]; now: number;
}>, sha256: Sha256Port): Promise<Readonly<AdmissionEvidenceEvaluationV1>> {
  return guarded(async () => {
    // Copy all untrusted data before calling an async host port.
    const evidence = wireArray(input.evidence).map(parseClaimEvidenceV1);
    const { now } = input;
    const rawRequest = parseAdmissionEvidenceRequestV1(input.request);
    const binding = parseEvidenceRequestBindingV1(input.binding);
    const policy = await parseClaimPolicyV1(input.policy, sha256);
    const request = await assertAdmissionEvidenceRequestV1(rawRequest, policy, binding, now, sha256);
    if (evidence.length !== request.claims.length) return fail();
    const byId = new Map<string, ClaimEvidenceV1>();
    for (const item of evidence) {
      if (byId.has(item.claimId)) return fail();
      byId.set(item.claimId, item);
    }
    if (request.claims.some(claim => !byId.has(claim.claimId))) return fail();
    await evaluateClaimEvidenceV1(policy, request.binding, evidence, now, sha256);
    const disclosures = request.claims.map(claim => outputDisclosure(claim, byId.get(claim.claimId)!));
    const evidenceFreshUntil = Math.min(request.expiresAt, ...evidence.map(item => {
      const rule = policy.claims.find(claim => claim.claimId === item.claimId)!;
      // Expiration includes verification age, so retained evaluations cannot outlive policy freshness.
      return Math.min(item.expiresAt, item.verificationExpiresAt, item.verifiedAt + rule.verification.maximumAgeSeconds);
    }));
    if (!wireInteger(evidenceFreshUntil) || evidenceFreshUntil <= now) return fail();
    return Object.freeze({ schema: 'group-foundation.admission-evidence-evaluation.v1' as const,
      requestId: request.requestId, binding: request.binding, requestIssuedAt: request.issuedAt,
      requestExpiresAt: request.expiresAt, evaluatedAt: now, evidenceFreshUntil, disclosures: Object.freeze(disclosures) });
  });
}

/** Verify the subject first, then each signed claim against the exact canonical request. */
export async function verifyAdmissionSignedEvidenceV1<TPresentation, TEvidence>(input: Readonly<{
  policy: ClaimPolicyV1; binding: EvidenceRequestBindingV1; claims: readonly AdmissionClaimRequestV1[];
  presentation: unknown; evidence: readonly unknown[]; now: number;
  verifier: AdmissionSignedEvidenceVerifierV1<TPresentation, TEvidence>;
}>, sha256: Sha256Port): Promise<Readonly<AdmissionSignedEvidenceEvaluationV1<TPresentation, TEvidence>>> {
  return guarded(async () => {
    const { now, presentation: rawPresentation, verifier } = input;
    const binding = parseEvidenceRequestBindingV1(input.binding);
    const evidence = [...wireArray(input.evidence)];
    // Use the request decoder to snapshot claim data before awaiting a host port.
    const claims = parseAdmissionEvidenceRequestDefinitionV1({ schema: 'group-foundation.admission-evidence-request.v1', binding, issuedAt: 0, expiresAt: 1, claims: input.claims }).claims;
    if (!wireInteger(now) || typeof verifier?.verifyPresentation !== 'function' || typeof verifier?.verifyEvidence !== 'function') return fail();
    const policy = await assertEvidenceRequestBindingV1(input.policy, binding, sha256);
    const presentation = await verifier.verifyPresentation(rawPresentation, binding);
    if (!presentation || typeof presentation !== 'object' || !Object.hasOwn(presentation, 'value')
      || !wireInteger(presentation.issuedAt) || !wireInteger(presentation.expiresAt)
      || presentation.issuedAt > now || presentation.expiresAt <= now) return fail();
    const request = await createAdmissionEvidenceRequestV1({ schema: 'group-foundation.admission-evidence-request.v1',
      binding, issuedAt: presentation.issuedAt, expiresAt: Math.min(presentation.expiresAt, presentation.issuedAt + 900), claims }, policy, sha256);
    // Refuse stale/overlong presentations before asking for signed evidence.
    await assertAdmissionEvidenceRequestV1(request, policy, binding, now, sha256);
    const verified: { evidence: ClaimEvidenceV1; value: TEvidence }[] = [];
    for (const value of evidence) {
      const result = await verifier.verifyEvidence(value, { request, policy, now });
      if (!result || typeof result !== 'object' || !Object.hasOwn(result, 'evidence') || !Object.hasOwn(result, 'value')) return fail();
      verified.push({ evidence: parseClaimEvidenceV1(result.evidence), value: result.value });
    }
    const evaluation = await evaluateAdmissionEvidenceV1({ request, policy, binding, evidence: verified.map(item => item.evidence), now }, sha256);
    return Object.freeze({ request, evaluation, presentation: presentation.value, evidence: Object.freeze(verified.map(item => item.value)) });
  });
}

/** Validate trusted evaluation data against this exact request before replay consumption. */
export async function assertAdmissionEvidenceEvaluationV1(input: Readonly<{
  request: unknown; policy: ClaimPolicyV1; binding: EvidenceRequestBindingV1; evaluation: unknown; now: number;
}>, sha256: Sha256Port): Promise<Readonly<AdmissionEvidenceEvaluationV1>> {
  return guarded(async () => {
    const evaluation = parseAdmissionEvidenceEvaluationV1(input.evaluation);
    const { now } = input;
    const rawRequest = parseAdmissionEvidenceRequestV1(input.request);
    const binding = parseEvidenceRequestBindingV1(input.binding);
    const policy = await parseClaimPolicyV1(input.policy, sha256);
    const request = await assertAdmissionEvidenceRequestV1(rawRequest, policy, binding, now, sha256);
    if (evaluation.requestId !== request.requestId || !equalEvidenceRequestBindingV1(evaluation.binding, request.binding)
      || evaluation.requestIssuedAt !== request.issuedAt || evaluation.requestExpiresAt !== request.expiresAt
      || evaluation.evaluatedAt > now || now >= evaluation.evidenceFreshUntil || evaluation.disclosures.length !== request.claims.length) return fail();
    const requested = new Map(request.claims.map(claim => [claim.claimId, claim]));
    for (const output of evaluation.disclosures) {
      const expected = requested.get(output.claimId);
      if (!expected || Object.hasOwn(output, 'assertion') !== expected.disclosure.assertion
        || Object.hasOwn(output, 'value') !== expected.disclosure.rawValue
        || Object.hasOwn(output, 'privateIdentifier') !== expected.disclosure.scopedIdentifier) return fail();
    }
    return evaluation;
  });
}
