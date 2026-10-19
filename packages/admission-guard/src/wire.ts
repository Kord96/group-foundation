import { AdmissionWireError } from './contracts.js';
import type {
  AdmissionClaimDisclosureV1, AdmissionClaimRequestV1, AdmissionEvidenceEvaluationV1,
  AdmissionEvidenceRequestDefinitionV1, AdmissionEvidenceRequestV1, ClaimDisclosureV1,
  ClaimEvidenceV1, EvidenceRequestBindingV1,
} from './contracts.js';

export const wireInvalid = (): never => { throw new AdmissionWireError(); };
export const wireText = (value: unknown): value is string => typeof value === 'string'
  && value.length > 0 && value.length <= 512 && !/[\p{Cc}\p{Cf}]/u.test(value);
export const wireInteger = (value: unknown): value is number => Number.isSafeInteger(value) && Number(value) >= 0;
/** Canonical unpadded base64url of 32 bytes, including zero padding bits. */
export const wireDigest = (value: unknown): value is string => typeof value === 'string'
  && /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u.test(value);
export const wirePrivateIdentifier = (value: unknown): value is string => typeof value === 'string'
  && /^v1\.[A-Za-z0-9_-]{1,32}\.[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/u.test(value);
export const compareText = (left: string, right: string): number => left < right ? -1 : left > right ? 1 : 0;

/** Accept plain data records only; refuse accessors and every unknown own field. */
export function wireRecord(value: unknown, required: readonly string[], optional: readonly string[] = []): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || ![Object.prototype, null].includes(Object.getPrototypeOf(value))) return wireInvalid();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (required.some(key => !Object.hasOwn(descriptors, key)) || Reflect.ownKeys(value).some(key =>
    typeof key !== 'string' || (!required.includes(key) && !optional.includes(key))
    || !Object.hasOwn(descriptors[key]!, 'value') || !descriptors[key]!.enumerable)) return wireInvalid();
  return value as Record<string, unknown>;
}

/** A JSON array has no holes, accessors, symbols, or extra fields. */
export function wireArray(value: unknown, maximum = 32): readonly unknown[] {
  if (!Array.isArray(value) || Object.getPrototypeOf(value) !== Array.prototype || value.length > maximum || Reflect.ownKeys(value).length !== value.length + 1) return wireInvalid();
  for (let index = 0; index < value.length; index++) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (!descriptor || !Object.hasOwn(descriptor, 'value') || !descriptor.enumerable) return wireInvalid();
  }
  return value;
}

export function parseClaimDisclosureV1(value: unknown): Readonly<ClaimDisclosureV1> {
  const record = wireRecord(value, ['assertion', 'rawValue', 'scopedIdentifier']);
  if (typeof record.assertion !== 'boolean' || typeof record.rawValue !== 'boolean' || typeof record.scopedIdentifier !== 'boolean') return wireInvalid();
  return Object.freeze({ assertion: record.assertion, rawValue: record.rawValue, scopedIdentifier: record.scopedIdentifier });
}

export function parseEvidenceRequestBindingV1(value: unknown): Readonly<EvidenceRequestBindingV1> {
  const record = wireRecord(value, ['scopeId', 'policyId', 'policyRevision', 'policyDigest', 'target', 'recipient', 'audience', 'purpose', 'subjectCommitment', 'nonce']);
  if (![record.scopeId, record.policyId, record.target, record.recipient, record.audience, record.purpose].every(wireText)
    || ![record.policyDigest, record.subjectCommitment, record.nonce].every(wireDigest) || !wireInteger(record.policyRevision)) return wireInvalid();
  return Object.freeze({ ...record }) as unknown as EvidenceRequestBindingV1;
}

function requestClaims(value: unknown): readonly AdmissionClaimRequestV1[] {
  const claims = wireArray(value).map(item => {
    const record = wireRecord(item, ['claimId', 'disclosure']);
    if (!wireText(record.claimId)) return wireInvalid();
    return Object.freeze({ claimId: record.claimId, disclosure: parseClaimDisclosureV1(record.disclosure) });
  }).sort((left, right) => compareText(left.claimId, right.claimId));
  if (new Set(claims.map(item => item.claimId)).size !== claims.length) return wireInvalid();
  return Object.freeze(claims);
}

export function parseAdmissionEvidenceRequestDefinitionV1(value: unknown): Readonly<AdmissionEvidenceRequestDefinitionV1> {
  const record = wireRecord(value, ['schema', 'binding', 'issuedAt', 'expiresAt', 'claims']);
  if (record.schema !== 'group-foundation.admission-evidence-request.v1' || !wireInteger(record.issuedAt)
    || !wireInteger(record.expiresAt) || record.expiresAt <= record.issuedAt || record.expiresAt - record.issuedAt > 900) return wireInvalid();
  return Object.freeze({ schema: record.schema, binding: parseEvidenceRequestBindingV1(record.binding), issuedAt: record.issuedAt, expiresAt: record.expiresAt, claims: requestClaims(record.claims) });
}

/** Structural decoding only: this does not verify the claimed digest or policy. */
export function parseAdmissionEvidenceRequestV1(value: unknown): Readonly<AdmissionEvidenceRequestV1> {
  const record = wireRecord(value, ['schema', 'binding', 'issuedAt', 'expiresAt', 'claims', 'requestId']);
  const request = parseAdmissionEvidenceRequestDefinitionV1({ schema: record.schema, binding: record.binding, issuedAt: record.issuedAt, expiresAt: record.expiresAt, claims: record.claims });
  if (!wireDigest(record.requestId)) return wireInvalid();
  return Object.freeze({ ...request, requestId: record.requestId });
}

function parseOutputDisclosure(value: unknown): Readonly<AdmissionClaimDisclosureV1> {
  const record = wireRecord(value, ['claimId'], ['assertion', 'value', 'privateIdentifier']);
  if (!wireText(record.claimId) || Object.hasOwn(record, 'assertion') && record.assertion !== true
    || Object.hasOwn(record, 'value') && !wireText(record.value)
    || Object.hasOwn(record, 'privateIdentifier') && !wirePrivateIdentifier(record.privateIdentifier)) return wireInvalid();
  return Object.freeze({ ...record }) as unknown as AdmissionClaimDisclosureV1;
}

export function parseClaimEvidenceV1(value: unknown): Readonly<ClaimEvidenceV1> {
  const record = wireRecord(value, ['claimId', 'verifiedAt', 'verificationExpiresAt', 'verificationMethod', 'issuedAt', 'expiresAt'], ['assertion', 'value', 'privateIdentifier', 'verificationIssuer']);
  const disclosure = parseOutputDisclosure({ claimId: record.claimId,
    ...(Object.hasOwn(record, 'assertion') ? { assertion: record.assertion } : {}),
    ...(Object.hasOwn(record, 'value') ? { value: record.value } : {}),
    ...(Object.hasOwn(record, 'privateIdentifier') ? { privateIdentifier: record.privateIdentifier } : {}) });
  if (![record.verifiedAt, record.verificationExpiresAt, record.issuedAt, record.expiresAt].every(wireInteger)
    || !wireText(record.verificationMethod) || Object.hasOwn(record, 'verificationIssuer') && !wireText(record.verificationIssuer)) return wireInvalid();
  return Object.freeze({ ...record, ...disclosure }) as unknown as ClaimEvidenceV1;
}

/** A decoded evaluation is data, not proof of cryptographic verification or durable admission. */
export function parseAdmissionEvidenceEvaluationV1(value: unknown): Readonly<AdmissionEvidenceEvaluationV1> {
  const record = wireRecord(value, ['schema', 'requestId', 'binding', 'requestIssuedAt', 'requestExpiresAt', 'evaluatedAt', 'evidenceFreshUntil', 'disclosures']);
  const { requestIssuedAt, requestExpiresAt, evaluatedAt, evidenceFreshUntil } = record;
  if (record.schema !== 'group-foundation.admission-evidence-evaluation.v1' || !wireDigest(record.requestId)
    || !wireInteger(requestIssuedAt) || !wireInteger(requestExpiresAt) || !wireInteger(evaluatedAt) || !wireInteger(evidenceFreshUntil)
    || requestExpiresAt <= requestIssuedAt || requestExpiresAt - requestIssuedAt > 900
    || evaluatedAt < requestIssuedAt || evaluatedAt >= requestExpiresAt || evidenceFreshUntil <= evaluatedAt || evidenceFreshUntil > requestExpiresAt) return wireInvalid();
  const disclosures = wireArray(record.disclosures).map(parseOutputDisclosure).sort((left, right) => compareText(left.claimId, right.claimId));
  if (new Set(disclosures.map(item => item.claimId)).size !== disclosures.length) return wireInvalid();
  return Object.freeze({ schema: record.schema, requestId: record.requestId, binding: parseEvidenceRequestBindingV1(record.binding), requestIssuedAt, requestExpiresAt, evaluatedAt, evidenceFreshUntil, disclosures: Object.freeze(disclosures) });
}
