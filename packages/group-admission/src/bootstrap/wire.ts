import { base64urlToBytes, bytesToBase64url, canonicalJson } from "@group-foundation/group-core/encoding";
import { decodeAdmissionRequest } from "../wire.js";
import {
  BOOTSTRAP_LIMITS, BOOTSTRAP_PRESENTATION_SCHEMA, BootstrapError,
  type BootstrapPresentation, type UnsignedBootstrapPresentation,
} from "./contracts.js";

export type BootstrapJson = null | boolean | number | string | readonly BootstrapJson[] | { readonly [key: string]: BootstrapJson };
const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

export function bootstrapFail(code: BootstrapError["code"], message: string): never { throw new BootstrapError(code, message); }

export function bootstrapIdentifier(value: unknown, field = "identifier"): string {
  if (typeof value !== "string" || !value.length || value.length > BOOTSTRAP_LIMITS.identifierChars || /[\u0000-\u001f\u007f]/u.test(value)) bootstrapFail("invalid-input", `${field} is invalid`);
  return value;
}

export function bootstrapUnixMs(value: unknown, field = "time"): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > BOOTSTRAP_LIMITS.maxUnixMs) bootstrapFail("clock", `${field} must be a nonnegative Unix millisecond timestamp`);
  return value as number;
}

export function bootstrapBytes(value: unknown, limit: number, field: string, exactLength?: number): Uint8Array {
  if (!(value instanceof Uint8Array) || value.length < 1 || value.length > limit || (exactLength !== undefined && value.length !== exactLength)) bootstrapFail("bounds", `${field} is outside bounds`);
  return new Uint8Array(value);
}

function exact(value: unknown, required: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || !required.every(key => Object.hasOwn(value, key)) || Object.keys(value).some(key => !required.includes(key))) bootstrapFail("invalid-wire", "unexpected bootstrap presentation fields");
  return value as Record<string, unknown>;
}

function wireBytes(value: unknown, limit: number, field: string, exactLength?: number): Uint8Array {
  if (typeof value !== "string") bootstrapFail("invalid-wire", `${field} must be canonical base64url`);
  let bytes: Uint8Array;
  try { bytes = base64urlToBytes(value, limit, field); } catch { return bootstrapFail("invalid-wire", `${field} must be canonical base64url`); }
  return bootstrapBytes(bytes, limit, field, exactLength);
}

function validateSessionId(value: unknown): string {
  if (typeof value !== "string") bootstrapFail("invalid-wire", "sessionId must be canonical base64url");
  const bytes = wireBytes(value, BOOTSTRAP_LIMITS.sessionIdBytesMax, "sessionId");
  if (bytes.length < BOOTSTRAP_LIMITS.sessionIdBytesMin) bootstrapFail("bounds", "sessionId is outside bounds");
  return value;
}

function validateSuite(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > BOOTSTRAP_LIMITS.suiteChars || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(value)) bootstrapFail("invalid-wire", "signature suite is invalid");
  return value;
}

export function encodeBootstrapJson(value: BootstrapJson, limit = BOOTSTRAP_LIMITS.wireBytes): Uint8Array {
  const bytes = encoder.encode(canonicalJson(value));
  if (bytes.length > limit) bootstrapFail("bounds", "bootstrap wire exceeds bounds");
  return bytes;
}

function parseCanonical(wire: Uint8Array): unknown {
  bootstrapBytes(wire, BOOTSTRAP_LIMITS.wireBytes, "wire");
  let parsed: BootstrapJson;
  try { parsed = JSON.parse(decoder.decode(wire)) as BootstrapJson; } catch { return bootstrapFail("invalid-wire", "bootstrap wire must be UTF-8 JSON"); }
  const canonical = encodeBootstrapJson(parsed);
  if (canonical.length !== wire.length || !canonical.every((byte, index) => byte === wire[index])) bootstrapFail("invalid-wire", "bootstrap wire must be canonical JSON");
  return parsed;
}

export function bootstrapPresentationJson(value: BootstrapPresentation | UnsignedBootstrapPresentation, includeProof: boolean): BootstrapJson {
  const common = {
    schema: value.schema, mode: value.mode, sessionId: value.sessionId, presenterRole: value.presenterRole,
    createdAtMs: value.createdAtMs, expiresAtMs: value.expiresAtMs, nonce: bytesToBase64url(value.nonce),
    suite: value.suite, verificationKey: bytesToBase64url(value.verificationKey),
  };
  const payload = value.mode === "offer-target"
    ? { target: bytesToBase64url(value.target) }
    : { membershipRequest: bytesToBase64url(value.membershipRequest) };
  const proof = includeProof ? { proof: bytesToBase64url((value as BootstrapPresentation).proof) } : {};
  return { ...common, ...payload, ...proof };
}

function validateCommon(value: BootstrapPresentation | UnsignedBootstrapPresentation): void {
  if (value.schema !== BOOTSTRAP_PRESENTATION_SCHEMA) bootstrapFail("invalid-wire", "unsupported bootstrap presentation schema");
  validateSessionId(value.sessionId); bootstrapUnixMs(value.createdAtMs, "createdAtMs"); bootstrapUnixMs(value.expiresAtMs, "expiresAtMs");
  if (value.expiresAtMs <= value.createdAtMs) bootstrapFail("clock", "presentation expiry must follow creation");
  bootstrapBytes(value.nonce, BOOTSTRAP_LIMITS.nonceBytes, "nonce", BOOTSTRAP_LIMITS.nonceBytes);
  validateSuite(value.suite); bootstrapBytes(value.verificationKey, BOOTSTRAP_LIMITS.verificationKeyBytes, "verificationKey");
  if (value.mode === "offer-target") {
    if (value.presenterRole !== "admission-host") bootstrapFail("role", "offer-target must be presented by the admission host");
    bootstrapBytes(value.target, BOOTSTRAP_LIMITS.targetBytes, "target");
  } else if (value.mode === "request-membership") {
    if (value.presenterRole !== "candidate") bootstrapFail("role", "request-membership must be presented by the candidate");
    const requestWire = bootstrapBytes(value.membershipRequest, BOOTSTRAP_LIMITS.requestBytes, "membershipRequest");
    decodeAdmissionRequest(requestWire);
  } else bootstrapFail("invalid-wire", "unsupported bootstrap mode");
}

export function validateUnsignedBootstrapPresentation(value: UnsignedBootstrapPresentation): UnsignedBootstrapPresentation {
  validateCommon(value); return value;
}

export function encodeBootstrapPresentation(value: BootstrapPresentation): Uint8Array {
  validateCommon(value); bootstrapBytes(value.proof, BOOTSTRAP_LIMITS.proofBytes, "proof");
  const wire = encodeBootstrapJson(bootstrapPresentationJson(value, true));
  decodeBootstrapPresentation(wire);
  return wire;
}

export function decodeBootstrapPresentation(wire: Uint8Array): BootstrapPresentation {
  const parsed = parseCanonical(wire);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) bootstrapFail("invalid-wire", "bootstrap presentation must be an object");
  const row0 = parsed as Record<string, unknown>;
  const mode = row0.mode;
  const common = ["schema", "mode", "sessionId", "presenterRole", "createdAtMs", "expiresAtMs", "nonce", "suite", "verificationKey", "proof"];
  const row = exact(parsed, mode === "offer-target" ? [...common, "target"] : mode === "request-membership" ? [...common, "membershipRequest"] : common);
  if (row.schema !== BOOTSTRAP_PRESENTATION_SCHEMA) bootstrapFail("invalid-wire", "unsupported bootstrap presentation schema");
  const base = {
    schema: BOOTSTRAP_PRESENTATION_SCHEMA, sessionId: validateSessionId(row.sessionId),
    createdAtMs: bootstrapUnixMs(row.createdAtMs, "createdAtMs"), expiresAtMs: bootstrapUnixMs(row.expiresAtMs, "expiresAtMs"),
    nonce: wireBytes(row.nonce, BOOTSTRAP_LIMITS.nonceBytes, "nonce", BOOTSTRAP_LIMITS.nonceBytes),
    suite: validateSuite(row.suite), verificationKey: wireBytes(row.verificationKey, BOOTSTRAP_LIMITS.verificationKeyBytes, "verificationKey"),
    proof: wireBytes(row.proof, BOOTSTRAP_LIMITS.proofBytes, "proof"),
  };
  const value: BootstrapPresentation = mode === "offer-target"
    ? { ...base, mode, presenterRole: row.presenterRole as "admission-host", target: wireBytes(row.target, BOOTSTRAP_LIMITS.targetBytes, "target") }
    : mode === "request-membership"
      ? { ...base, mode, presenterRole: row.presenterRole as "candidate", membershipRequest: wireBytes(row.membershipRequest, BOOTSTRAP_LIMITS.requestBytes, "membershipRequest") }
      : bootstrapFail("invalid-wire", "unsupported bootstrap mode");
  validateCommon(value); return value;
}
