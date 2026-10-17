import { canonicalJson, bytesToBase64url, base64urlToBytes } from "@group-foundation/group-core/encoding";
import { ADMISSION_SCHEMA, REMOVAL_SCHEMA, OUTBOX_SCHEMA, INSTALLATION_SCHEMA, LIMITS, AdmissionError, type AdmissionRequest, type RemovalRequest, type GroupCursor, type MemberIdentity, type InvitationDefinition, type PublicSelection, type InstallationReceipt } from "./contracts.js";
export { canonicalJson, bytesToBase64url, base64urlToBytes };
export type Json = null | boolean | number | string | readonly Json[] | { readonly [key: string]: Json };
const encoder = new TextEncoder(), decoder = new TextDecoder("utf-8", { fatal: true });
export function fail(code: string, message: string): never { throw new AdmissionError(code, message); }
export function identifier(value: unknown, field = "identifier"): string {
  if (typeof value !== "string" || !value.length || value.length > LIMITS.identifierChars || /[\u0000-\u001f\u007f]/u.test(value)) fail("invalid-input", `${field} is invalid`);
  return value;
}
export function instant(value: unknown): number { if (!Number.isSafeInteger(value) || (value as number) < 0) fail("invalid-input", "time must be a nonnegative safe integer in the host clock domain"); return value as number; }
function exact(value: unknown, fields: string[], optional: string[] = []): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || !fields.every(key => Object.hasOwn(value, key)) || Object.keys(value).some(key => !fields.includes(key) && !optional.includes(key))) fail("invalid-wire", "unexpected wire fields");
  return value as Record<string, unknown>;
}
export function validateMember(value: unknown): MemberIdentity { const row = exact(value, ["signingKeyFingerprint"]); return { signingKeyFingerprint: identifier(row.signingKeyFingerprint, "member") }; }
export function validateCursor(value: unknown): GroupCursor {
  const row = exact(value, ["scope", "revision", "epoch", "predecessor"]);
  if (!Number.isSafeInteger(row.revision) || (row.revision as number) < 0 || typeof row.epoch !== "string" || !/^(0|[1-9][0-9]{0,39})$/u.test(row.epoch)) fail("invalid-input", "invalid revision or epoch");
  return { scope: identifier(row.scope, "scope"), revision: row.revision as number, epoch: row.epoch, predecessor: identifier(row.predecessor, "predecessor") };
}
export function sameCursor(a: GroupCursor, b: GroupCursor): boolean { return a.scope === b.scope && a.revision === b.revision && a.epoch === b.epoch && a.predecessor === b.predecessor; }
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((value, index) => value === b[index]); }
export function byteField(value: unknown, limit: number, field = "bytes"): Uint8Array {
  if (!(value instanceof Uint8Array) || !value.length || value.length > limit) fail("bounds", `${field} exceeds bounds or is empty`);
  return new Uint8Array(value);
}
function wireByte(value: unknown, limit: number): Uint8Array {
  if (typeof value !== "string") fail("invalid-wire", "byte field must be base64url");
  try { return base64urlToBytes(value, limit, "bytes"); } catch { return fail("invalid-wire", "invalid canonical base64url"); }
}
export function encodeJson(value: Json, limit = LIMITS.wireBytes): Uint8Array { const bytes = encoder.encode(canonicalJson(value)); if (bytes.length > limit) fail("bounds", "wire exceeds bounds"); return bytes; }
function parse(bytes: Uint8Array, limit = LIMITS.wireBytes): unknown {
  byteField(bytes, limit); let value: Json;
  try { value = JSON.parse(decoder.decode(bytes)) as Json; } catch { return fail("invalid-wire", "invalid UTF-8 JSON"); }
  if (!sameBytes(encodeJson(value, limit), bytes)) fail("invalid-wire", "wire must be canonical JSON");
  return value;
}
export function invitationJson(value: InvitationDefinition): Json {
  validateInvitation(value);
  return { invitationId: value.invitationId, scope: value.scope, expiresAt: value.expiresAt, maxUses: value.maxUses, approval: value.approval, issuedBy: { ...value.issuedBy } };
}
export function validateInvitation(value: InvitationDefinition): void {
  exact(value, ["invitationId", "scope", "expiresAt", "maxUses", "approval", "issuedBy"]);
  identifier(value.invitationId); identifier(value.scope); instant(value.expiresAt); validateMember(value.issuedBy);
  if (!Number.isSafeInteger(value.maxUses) || value.maxUses < 1 || value.maxUses > 1_000_000 || !["automatic", "required"].includes(value.approval)) fail("invalid-input", "invalid invitation");
}
function requestJson(request: AdmissionRequest, proof = true): Json {
  return { schema: request.schema, requestId: request.requestId, invitationId: request.invitationId, scope: request.scope,
    member: { ...request.member }, credential: bytesToBase64url(request.credential), keyPackage: bytesToBase64url(request.keyPackage), keyPackageDigest: request.keyPackageDigest,
    ...(request.deliveryBinding === undefined ? {} : { deliveryBinding: bytesToBase64url(request.deliveryBinding) }),
    ...(proof ? { proof: bytesToBase64url(request.proof) } : {}), requestedAt: request.requestedAt, expiresAt: request.expiresAt };
}
function parseRequest(value: unknown): AdmissionRequest {
  const row = exact(value, ["schema", "requestId", "invitationId", "scope", "member", "credential", "keyPackage", "keyPackageDigest", "proof", "requestedAt", "expiresAt"], ["deliveryBinding"]);
  if (row.schema !== ADMISSION_SCHEMA) fail("invalid-wire", "unsupported admission schema");
  const requestedAt = instant(row.requestedAt), expiresAt = instant(row.expiresAt);
  if (expiresAt <= requestedAt) fail("invalid-wire", "expiry must follow request time");
  return { schema: ADMISSION_SCHEMA, requestId: identifier(row.requestId), invitationId: identifier(row.invitationId), scope: identifier(row.scope), member: validateMember(row.member),
    credential: wireByte(row.credential, LIMITS.credentialBytes), keyPackage: wireByte(row.keyPackage, LIMITS.keyPackageBytes), keyPackageDigest: identifier(row.keyPackageDigest),
    proof: wireByte(row.proof, LIMITS.proofBytes), requestedAt, expiresAt,
    ...(row.deliveryBinding === undefined ? {} : { deliveryBinding: wireByte(row.deliveryBinding, LIMITS.deliveryBindingBytes) }) };
}
export function encodeAdmissionRequest(request: AdmissionRequest): Uint8Array { return encodeJson(requestJson(parseRequest(requestJson(request)))); }
export function decodeAdmissionRequest(wire: Uint8Array): AdmissionRequest { return parseRequest(parse(wire)); }
export function admissionRequestTranscript(request: Omit<AdmissionRequest, "proof">): Uint8Array { const checked = decodeAdmissionRequest(encodeAdmissionRequest({ ...request, proof: new Uint8Array([0]) })); return encodeJson({ domain: "group-foundation.admission.candidate-proof.v1", request: requestJson(checked, false) }); }
export function encodeRemovalRequest(value: RemovalRequest): Uint8Array {
  if (value.schema !== REMOVAL_SCHEMA) fail("invalid-wire", "unsupported removal schema");
  exact(value, ["schema", "operationId", "scope", "member", "expected"]);
  identifier(value.operationId); identifier(value.scope); validateMember(value.member); validateCursor(value.expected);
  if (value.scope !== value.expected.scope) fail("scope", "removal scope differs from cursor");
  return encodeJson({ ...value, member: { ...value.member }, expected: { ...value.expected } });
}
export function decodeRemovalRequest(wire: Uint8Array): RemovalRequest {
  const row = exact(parse(wire), ["schema", "operationId", "scope", "member", "expected"]);
  const value = { schema: row.schema, operationId: identifier(row.operationId), scope: identifier(row.scope), member: validateMember(row.member), expected: validateCursor(row.expected) } as RemovalRequest;
  encodeRemovalRequest(value); return value;
}
function selectionJson(value: PublicSelection): Json {
  const { commit, welcome, ratchetTree, ...rest } = value;
  return { ...rest, expected: { ...value.expected }, next: { ...value.next }, commit: bytesToBase64url(value.commit),
    ...(value.welcome === undefined ? {} : { welcome: bytesToBase64url(value.welcome) }), ...(value.ratchetTree === undefined ? {} : { ratchetTree: bytesToBase64url(value.ratchetTree) }) };
}
export function encodePublicSelection(value: PublicSelection): Uint8Array {
  const wire = encodeJson(selectionJson(value), LIMITS.outboxBytes); decodePublicSelection(wire); return wire;
}
export function decodePublicSelection(wire: Uint8Array): PublicSelection {
  const row = exact(parse(wire, LIMITS.outboxBytes), ["schema", "kind", "operationId", "operationHash", "retryId", "transitionId", "custodyDigest", "expected", "next", "authorityRevision", "commit"], ["candidateRevision", "welcome", "ratchetTree"]);
  if (row.schema !== OUTBOX_SCHEMA || !["add", "remove"].includes(String(row.kind))) fail("invalid-wire", "unsupported selection schema/kind");
  const expected = validateCursor(row.expected), next = validateCursor(row.next);
  if (expected.scope !== next.scope || next.revision !== expected.revision + 1 || BigInt(next.epoch) !== BigInt(expected.epoch) + 1n || next.predecessor === expected.predecessor) fail("stale-stage", "selection must advance one revision and epoch");
  const add = row.kind === "add";
  if (add !== Object.hasOwn(row, "candidateRevision") || add !== Object.hasOwn(row, "welcome") || (!add && Object.hasOwn(row, "ratchetTree"))) fail("invalid-wire", "Add/Remove public fields differ");
  return { schema: OUTBOX_SCHEMA, kind: row.kind as "add" | "remove", operationId: identifier(row.operationId), operationHash: identifier(row.operationHash), retryId: identifier(row.retryId), transitionId: identifier(row.transitionId), custodyDigest: identifier(row.custodyDigest), expected, next, authorityRevision: identifier(row.authorityRevision), commit: wireByte(row.commit, LIMITS.outboxBytes),
    ...(add ? { candidateRevision: identifier(row.candidateRevision), welcome: wireByte(row.welcome, LIMITS.outboxBytes) } : {}), ...(row.ratchetTree === undefined ? {} : { ratchetTree: wireByte(row.ratchetTree, LIMITS.outboxBytes) }) };
}
function receiptJson(value: InstallationReceipt, proof = true): Json {
  return { schema: value.schema, operationId: value.operationId, scope: value.scope, selectedWireHash: value.selectedWireHash, successor: value.successor, recipient: { ...value.recipient }, installedAt: value.installedAt,
    ...(proof ? { acknowledgement: bytesToBase64url(value.acknowledgement) } : {}) };
}
export function decodeInstallationReceipt(wire: Uint8Array): InstallationReceipt {
  const row = exact(parse(wire), ["schema", "operationId", "scope", "selectedWireHash", "successor", "recipient", "installedAt", "acknowledgement"]);
  if (row.schema !== INSTALLATION_SCHEMA) fail("invalid-wire", "unsupported installation schema");
  return { schema: INSTALLATION_SCHEMA, operationId: identifier(row.operationId), scope: identifier(row.scope), selectedWireHash: identifier(row.selectedWireHash), successor: identifier(row.successor), recipient: validateMember(row.recipient), installedAt: instant(row.installedAt), acknowledgement: wireByte(row.acknowledgement, LIMITS.proofBytes) };
}
export function encodeInstallationReceipt(receipt: InstallationReceipt): Uint8Array { const wire = encodeJson(receiptJson(receipt)); decodeInstallationReceipt(wire); return wire; }
export function recipientInstallationTranscript(receipt: Omit<InstallationReceipt, "acknowledgement">): Uint8Array { const checked = decodeInstallationReceipt(encodeInstallationReceipt({ ...receipt, acknowledgement: new Uint8Array([0]) })); return encodeJson({ domain: "group-foundation.admission.installation-proof.v1", receipt: receiptJson(checked, false) }); }
