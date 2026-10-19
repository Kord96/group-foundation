import { ClaimPolicyError } from './contracts.js';
import type { ClaimEvidenceV1, ClaimPolicyDefinitionV1, ClaimPolicyV1, ClaimRequirementV1, EvidenceRequestBindingV1, Sha256Port } from './contracts.js';
import { digest } from './digest.js';
import { compareText, parseClaimDisclosureV1, parseClaimEvidenceV1, parseEvidenceRequestBindingV1, wireArray, wireInteger, wireRecord, wireText } from './wire.js';

const fail = (): never => { throw new ClaimPolicyError(); };
const guarded = async <T>(operation: () => T | Promise<T>): Promise<T> => { try { return await operation(); } catch { return fail(); } };

function definition(value: unknown): Readonly<ClaimPolicyDefinitionV1> {
  const record = wireRecord(value, ['schema', 'policyId', 'revision', 'claims']);
  if (record.schema !== 'group-foundation.claim-policy.v1' || !wireInteger(record.revision) || !wireText(record.policyId)) return fail();
  const claims = wireArray(record.claims).map((raw): ClaimRequirementV1 => {
    const claim = wireRecord(raw, ['claimId', 'predicate', 'required', 'verification', 'disclosure']);
    // Inspect kind only after refusing accessors and unknown predicate fields.
    const predicate = wireRecord(claim.predicate, ['kind'], ['channel', 'issuer', 'claim']);
    const verification = wireRecord(claim.verification, ['maximumAgeSeconds', 'methods']);
    const disclosure = parseClaimDisclosureV1(claim.disclosure);
    const methods = wireArray(verification.methods, 16);
    if (!wireText(claim.claimId) || typeof claim.required !== 'boolean' || !wireInteger(verification.maximumAgeSeconds)
      || verification.maximumAgeSeconds < 1 || verification.maximumAgeSeconds > 31536000
      || !methods.length || !methods.every(wireText) || new Set(methods).size !== methods.length) return fail();
    let normalizedPredicate: ClaimRequirementV1['predicate'];
    if (predicate.kind === 'contact-possession') {
      wireRecord(predicate, ['kind', 'channel']);
      if (predicate.channel !== 'email' && predicate.channel !== 'phone') return fail();
      normalizedPredicate = Object.freeze({ kind: predicate.kind, channel: predicate.channel });
    } else {
      wireRecord(predicate, ['kind', 'issuer', 'claim']);
      if (predicate.kind !== 'issuer-claim' || !wireText(predicate.issuer) || !wireText(predicate.claim)) return fail();
      normalizedPredicate = Object.freeze({ kind: predicate.kind, issuer: predicate.issuer, claim: predicate.claim });
    }
    return Object.freeze({ claimId: claim.claimId, predicate: normalizedPredicate, required: claim.required,
      verification: Object.freeze({ maximumAgeSeconds: verification.maximumAgeSeconds, methods: Object.freeze([...methods].sort(compareText)) }), disclosure });
  }).sort((left, right) => compareText(left.claimId, right.claimId));
  if (new Set(claims.map(claim => claim.claimId)).size !== claims.length) return fail();
  return Object.freeze({ schema: record.schema, policyId: record.policyId, revision: record.revision, claims: Object.freeze(claims) });
}

/** Canonical policy pin. Ordering uses code units, independent of host locale. */
export async function defineClaimPolicyV1(value: ClaimPolicyDefinitionV1, sha256: Sha256Port): Promise<Readonly<ClaimPolicyV1>> {
  return guarded(async () => {
    const policy = definition(value);
    const claims = policy.claims.map(claim => [claim.claimId, claim.predicate.kind,
      claim.predicate.kind === 'contact-possession' ? claim.predicate.channel : [claim.predicate.issuer, claim.predicate.claim],
      claim.required, claim.verification.maximumAgeSeconds, claim.verification.methods,
      claim.disclosure.assertion, claim.disclosure.rawValue, claim.disclosure.scopedIdentifier]);
    const hash = await digest('group-foundation.claim-policy.v1\0' + JSON.stringify([policy.schema, policy.policyId, policy.revision, claims]), sha256);
    return Object.freeze({ ...policy, digest: hash });
  });
}

export async function parseClaimPolicyV1(value: unknown, sha256: Sha256Port): Promise<Readonly<ClaimPolicyV1>> {
  return guarded(async () => {
    const record = wireRecord(value, ['schema', 'policyId', 'revision', 'digest', 'claims']);
    const { digest: hash, ...rest } = record;
    const policy = await defineClaimPolicyV1(rest as unknown as ClaimPolicyDefinitionV1, sha256);
    if (hash !== policy.digest) return fail();
    return policy;
  });
}

export async function assertEvidenceRequestBindingV1(policy: ClaimPolicyV1, binding: EvidenceRequestBindingV1, sha256: Sha256Port): Promise<Readonly<ClaimPolicyV1>> {
  return guarded(async () => {
    // Snapshot the binding before awaiting the host hash implementation.
    const request = parseEvidenceRequestBindingV1(binding);
    const current = await parseClaimPolicyV1(policy, sha256);
    if (current.policyId !== request.policyId || current.revision !== request.policyRevision || current.digest !== request.policyDigest) return fail();
    return current;
  });
}

/** In-process rollback/fork refusal. Persist current pins in the host for restart safety. */
export function createClaimPolicyPinV1(sha256: Sha256Port): (value: ClaimPolicyV1) => Promise<Readonly<ClaimPolicyV1>> {
  const pins = new Map<string, { revision: number; digest: string }>();
  return async value => {
    const policy = await parseClaimPolicyV1(value, sha256), last = pins.get(policy.policyId);
    if (last && (policy.revision < last.revision || policy.revision === last.revision && policy.digest !== last.digest)) return fail();
    pins.set(policy.policyId, { revision: policy.revision, digest: policy.digest });
    return policy;
  };
}

export function equalEvidenceRequestBindingV1(left: EvidenceRequestBindingV1, right: EvidenceRequestBindingV1): boolean {
  return Object.entries(left).every(([key, value]) => right[key as keyof EvidenceRequestBindingV1] === value);
}

export async function assertClaimReleaseConsentV1(policy: ClaimPolicyV1, binding: EvidenceRequestBindingV1, claimId: string, value: unknown, sha256: Sha256Port): Promise<void> {
  return guarded(async () => {
    const expected = parseEvidenceRequestBindingV1(binding);
    const consent = wireRecord(value, ['scope', 'claimId', 'disclosure']);
    const scope = parseEvidenceRequestBindingV1(consent.scope), disclosure = parseClaimDisclosureV1(consent.disclosure);
    const current = await assertEvidenceRequestBindingV1(policy, expected, sha256);
    const rule = current.claims.find(claim => claim.claimId === claimId);
    if (!rule || consent.claimId !== claimId || !equalEvidenceRequestBindingV1(expected, scope)
      || (['assertion', 'rawValue', 'scopedIdentifier'] as const).some(key => disclosure[key] && !rule.disclosure[key])) return fail();
  });
}

function assertEvidence(current: ClaimPolicyV1, evidence: readonly ClaimEvidenceV1[], now: number, complete: boolean): void {
  if (!wireInteger(now)) return fail();
  const seen = new Set<string>();
  for (const item of evidence) {
    const rule = current.claims.find(claim => claim.claimId === item.claimId);
    if (!rule || seen.has(item.claimId)) return fail();
    seen.add(item.claimId);
    if (item.verificationExpiresAt <= item.verifiedAt || item.expiresAt > item.verificationExpiresAt
      || item.verifiedAt > item.issuedAt || item.issuedAt > now || item.expiresAt <= now || item.expiresAt <= item.issuedAt
      || now - item.verifiedAt >= rule.verification.maximumAgeSeconds || !rule.verification.methods.includes(item.verificationMethod)
      || rule.predicate.kind === 'issuer-claim' && item.verificationIssuer !== rule.predicate.issuer) return fail();
    if (Object.hasOwn(item, 'assertion') && !rule.disclosure.assertion
      || Object.hasOwn(item, 'value') && !rule.disclosure.rawValue
      || Object.hasOwn(item, 'privateIdentifier') && !rule.disclosure.scopedIdentifier) return fail();
  }
  if (complete && current.claims.some(claim => claim.required && !seen.has(claim.claimId))) return fail();
}

/** Evidence must already be authenticated and bound to this exact request by the host. */
export async function evaluateClaimEvidenceV1(policy: ClaimPolicyV1, binding: EvidenceRequestBindingV1, evidence: readonly ClaimEvidenceV1[], now: number, sha256: Sha256Port): Promise<void> {
  return guarded(async () => {
    const items = wireArray(evidence).map(parseClaimEvidenceV1);
    const current = await assertEvidenceRequestBindingV1(policy, binding, sha256);
    assertEvidence(current, items, now, true);
  });
}

export async function assertClaimEvidenceItemV1(policy: ClaimPolicyV1, binding: EvidenceRequestBindingV1, evidence: ClaimEvidenceV1, now: number, sha256: Sha256Port): Promise<void> {
  return guarded(async () => {
    const item = parseClaimEvidenceV1(evidence);
    const current = await assertEvidenceRequestBindingV1(policy, binding, sha256);
    assertEvidence(current, [item], now, false);
  });
}
