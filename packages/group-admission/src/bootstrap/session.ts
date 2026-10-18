import { base64urlToBytes } from "@group-foundation/group-core/encoding";
import { decodeAdmissionRequest } from "../wire.js";
import {
  BOOTSTRAP_LIMITS, BOOTSTRAP_SESSION_SCHEMA,
  type BootstrapPresentationInspection, type BootstrapPresentationVerifier, type BootstrapRole,
  type BootstrapSessionSnapshot, type BootstrapSha256Port, type BootstrapTransition,
} from "./contracts.js";
import { authenticateBootstrapPresentation, bootstrapSha256 } from "./presentation.js";
import { bootstrapBytes, bootstrapFail, bootstrapIdentifier, bootstrapUnixMs, decodeBootstrapPresentation } from "./wire.js";

function sameBytes(a: Uint8Array, b: Uint8Array): boolean { return a.length === b.length && a.every((byte, index) => byte === b[index]); }
function otherRole(role: BootstrapRole): BootstrapRole { return role === "admission-host" ? "candidate" : "admission-host"; }
function clone(state: BootstrapSessionSnapshot): BootstrapSessionSnapshot { return structuredClone(state); }

function validateSha256(value: unknown, field: string): string {
  if (typeof value !== "string") bootstrapFail("invalid-input", `${field} is invalid`);
  let decoded: Uint8Array;
  try { decoded = base64urlToBytes(value, 32, field); } catch { return bootstrapFail("invalid-input", `${field} is invalid`); }
  if (decoded.length !== 32) bootstrapFail("invalid-input", `${field} is invalid`);
  return value;
}

function exactSnapshot(value: BootstrapSessionSnapshot): void {
  const required = ["schema", "sessionId", "mode", "localRole", "remoteRole", "presentationWire", "presentationSha256", "createdAtMs", "expiresAtMs", "phase", "revision"];
  const optional = ["requestWire", "requestSha256", "submission", "completion", "cancellation"];
  if (!value || typeof value !== "object" || required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) bootstrapFail("invalid-input", "unexpected bootstrap session fields");
}

export function validateBootstrapSession(value: BootstrapSessionSnapshot): BootstrapSessionSnapshot {
  exactSnapshot(value);
  if (value.schema !== BOOTSTRAP_SESSION_SCHEMA || !["offer-target", "request-membership"].includes(value.mode) || !["admission-host", "candidate"].includes(value.localRole) || value.remoteRole !== otherRole(value.localRole)) bootstrapFail("invalid-input", "invalid bootstrap session identity");
  bootstrapIdentifier(value.sessionId, "sessionId"); bootstrapBytes(value.presentationWire, BOOTSTRAP_LIMITS.wireBytes, "presentationWire"); validateSha256(value.presentationSha256, "presentationSha256");
  bootstrapUnixMs(value.createdAtMs, "createdAtMs"); bootstrapUnixMs(value.expiresAtMs, "expiresAtMs");
  if (!Number.isSafeInteger(value.revision) || value.revision < 0 || !["open", "request-ready", "submitted", "completed", "cancelled", "expired"].includes(value.phase)) bootstrapFail("invalid-input", "invalid bootstrap session revision or phase");
  const presentation = decodeBootstrapPresentation(value.presentationWire);
  if (presentation.sessionId !== value.sessionId || presentation.mode !== value.mode || presentation.createdAtMs !== value.createdAtMs || presentation.expiresAtMs !== value.expiresAtMs) bootstrapFail("replay", "session differs from its presentation");
  const hasRequest = value.requestWire !== undefined || value.requestSha256 !== undefined;
  if (hasRequest !== (value.requestWire !== undefined && value.requestSha256 !== undefined)) bootstrapFail("invalid-input", "request wire and digest must be stored together");
  if (value.requestWire !== undefined) { bootstrapBytes(value.requestWire, BOOTSTRAP_LIMITS.requestBytes, "requestWire"); decodeAdmissionRequest(value.requestWire); validateSha256(value.requestSha256, "requestSha256"); }
  if (value.mode === "request-membership" && !hasRequest) bootstrapFail("invalid-input", "request-membership session lost its request");
  if (value.phase === "open" && hasRequest || ["request-ready", "submitted", "completed"].includes(value.phase) && !hasRequest) bootstrapFail("invalid-input", "session phase differs from request state");
  if (value.submission !== undefined) {
    if (Object.keys(value.submission).sort().join(",") !== "submissionId,submittedAtMs") bootstrapFail("invalid-input", "invalid submission receipt");
    bootstrapIdentifier(value.submission.submissionId, "submissionId"); bootstrapUnixMs(value.submission.submittedAtMs, "submittedAtMs");
    if (value.submission.submittedAtMs < value.createdAtMs || value.submission.submittedAtMs >= value.expiresAtMs) bootstrapFail("clock", "submission is outside the session lifetime");
  }
  if ((value.phase === "submitted" || value.phase === "completed") !== (value.submission !== undefined)) bootstrapFail("invalid-input", "session phase differs from submission state");
  if (value.completion !== undefined) {
    if (Object.keys(value.completion).sort().join(",") !== "completedAtMs,completionId") bootstrapFail("invalid-input", "invalid completion receipt");
    bootstrapIdentifier(value.completion.completionId, "completionId"); bootstrapUnixMs(value.completion.completedAtMs, "completedAtMs");
    if (!value.submission || value.completion.completedAtMs < value.submission.submittedAtMs) bootstrapFail("clock", "completion precedes submission");
  }
  if ((value.phase === "completed") !== (value.completion !== undefined)) bootstrapFail("invalid-input", "session phase differs from completion state");
  if (value.cancellation !== undefined) {
    if (Object.keys(value.cancellation).sort().join(",") !== "cancellationId,cancelledAtMs,cancelledBy") bootstrapFail("invalid-input", "invalid cancellation receipt");
    bootstrapIdentifier(value.cancellation.cancellationId, "cancellationId"); bootstrapUnixMs(value.cancellation.cancelledAtMs, "cancelledAtMs");
    if (!["admission-host", "candidate"].includes(value.cancellation.cancelledBy) || value.cancellation.cancelledAtMs < value.createdAtMs || value.cancellation.cancelledAtMs >= value.expiresAtMs) bootstrapFail("invalid-input", "invalid session cancellation");
  }
  if ((value.phase === "cancelled") !== (value.cancellation !== undefined)) bootstrapFail("invalid-input", "session phase differs from cancellation state");
  return clone(value);
}

function live(state: BootstrapSessionSnapshot, nowMs: number): BootstrapTransition | undefined {
  const now = bootstrapUnixMs(nowMs, "nowMs");
  if (now < state.createdAtMs) bootstrapFail("clock", "session clock precedes presentation creation");
  if (["submitted", "completed", "cancelled", "expired"].includes(state.phase)) return undefined;
  if (now >= state.expiresAtMs) return { state: { ...clone(state), phase: "expired", revision: state.revision + 1 }, replayed: false };
  return undefined;
}

export async function createBootstrapSession(inspection: BootstrapPresentationInspection, localRole: BootstrapRole, hashes: BootstrapSha256Port): Promise<BootstrapSessionSnapshot> {
  if (![inspection.presentation.presenterRole, otherRole(inspection.presentation.presenterRole)].includes(localRole)) bootstrapFail("role", "local bootstrap role is invalid");
  const requestWire = inspection.presentation.mode === "request-membership" ? new Uint8Array(inspection.presentation.membershipRequest) : undefined;
  const requestSha256 = requestWire === undefined ? undefined : await bootstrapSha256(requestWire, hashes);
  const state: BootstrapSessionSnapshot = {
    schema: BOOTSTRAP_SESSION_SCHEMA, sessionId: inspection.presentation.sessionId, mode: inspection.presentation.mode,
    localRole, remoteRole: otherRole(localRole), presentationWire: new Uint8Array(inspection.wire), presentationSha256: inspection.wireSha256,
    createdAtMs: inspection.presentation.createdAtMs, expiresAtMs: inspection.presentation.expiresAtMs,
    phase: requestWire === undefined ? "open" : "request-ready", revision: 0,
    ...(requestWire === undefined ? {} : { requestWire, requestSha256: requestSha256! }),
  };
  return validateBootstrapSession(state);
}

export async function resumeBootstrapSession(
  snapshot: BootstrapSessionSnapshot, presentationWire: Uint8Array,
  dependencies: { readonly verifier: BootstrapPresentationVerifier; readonly hashes: BootstrapSha256Port }, nowMs: number,
): Promise<BootstrapTransition> {
  const state = validateBootstrapSession(snapshot);
  const presentation = await authenticateBootstrapPresentation(presentationWire, dependencies.verifier);
  const digest = await bootstrapSha256(presentationWire, dependencies.hashes);
  if (presentation.sessionId !== state.sessionId || digest !== state.presentationSha256 || !sameBytes(presentationWire, state.presentationWire)) bootstrapFail("replay", "resume presentation differs from the durable session");
  const expiration = live(state, nowMs);
  return expiration ?? { state, replayed: true };
}

export async function attachBootstrapMembershipRequest(snapshot: BootstrapSessionSnapshot, requestWire: Uint8Array, hashes: BootstrapSha256Port, nowMs: number): Promise<BootstrapTransition> {
  const state = validateBootstrapSession(snapshot);
  if (state.mode !== "offer-target") bootstrapFail("transition", "request-membership presentations already bind their request");
  const expiration = live(state, nowMs); if (expiration) return expiration;
  bootstrapBytes(requestWire, BOOTSTRAP_LIMITS.requestBytes, "requestWire"); decodeAdmissionRequest(requestWire);
  const requestSha256 = await bootstrapSha256(requestWire, hashes);
  if (state.requestWire !== undefined) {
    if (state.requestSha256 !== requestSha256 || !sameBytes(state.requestWire, requestWire)) bootstrapFail("replay", "membership request changed within the session");
    return { state, replayed: true };
  }
  if (state.phase !== "open") bootstrapFail("transition", "session cannot accept a membership request");
  return { state: validateBootstrapSession({ ...state, phase: "request-ready", revision: state.revision + 1, requestWire: new Uint8Array(requestWire), requestSha256 }), replayed: false };
}

export function recordBootstrapSubmission(snapshot: BootstrapSessionSnapshot, submissionId: string, nowMs: number): BootstrapTransition {
  const state = validateBootstrapSession(snapshot); bootstrapIdentifier(submissionId, "submissionId");
  if (state.localRole !== "admission-host") bootstrapFail("role", "only the admission-host session can record submission");
  if (state.submission !== undefined) {
    if (state.submission.submissionId !== submissionId) bootstrapFail("replay", "submission identity changed within the session");
    return { state, replayed: true };
  }
  const expiration = live(state, nowMs); if (expiration) return expiration;
  if (state.phase !== "request-ready" || state.requestWire === undefined) bootstrapFail("transition", "session has no membership request ready for submission");
  const request = decodeAdmissionRequest(state.requestWire);
  if (submissionId !== request.requestId) bootstrapFail("replay", "submission identity must equal the admission request ID");
  return { state: validateBootstrapSession({ ...state, phase: "submitted", revision: state.revision + 1, submission: { submissionId, submittedAtMs: nowMs } }), replayed: false };
}

export function completeBootstrapSession(snapshot: BootstrapSessionSnapshot, completionId: string, nowMs: number): BootstrapTransition {
  const state = validateBootstrapSession(snapshot); bootstrapIdentifier(completionId, "completionId"); bootstrapUnixMs(nowMs, "nowMs");
  if (state.localRole !== "admission-host") bootstrapFail("role", "only the admission-host session can record completion");
  if (state.completion !== undefined) {
    if (state.completion.completionId !== completionId) bootstrapFail("replay", "completion identity changed within the session");
    return { state, replayed: true };
  }
  if (state.phase !== "submitted" || !state.submission) bootstrapFail("transition", "only a submitted session can complete");
  if (nowMs < state.submission.submittedAtMs) bootstrapFail("clock", "completion precedes submission");
  return { state: validateBootstrapSession({ ...state, phase: "completed", revision: state.revision + 1, completion: { completionId, completedAtMs: nowMs } }), replayed: false };
}

export function cancelBootstrapSession(snapshot: BootstrapSessionSnapshot, cancellationId: string, cancelledBy: BootstrapRole, nowMs: number): BootstrapTransition {
  const state = validateBootstrapSession(snapshot); bootstrapIdentifier(cancellationId, "cancellationId");
  if (cancelledBy !== state.localRole) bootstrapFail("role", "a local session can only record its local role's cancellation");
  if (state.cancellation !== undefined) {
    if (state.cancellation.cancellationId !== cancellationId || state.cancellation.cancelledBy !== cancelledBy) bootstrapFail("replay", "cancellation identity changed within the session");
    return { state, replayed: true };
  }
  const expiration = live(state, nowMs); if (expiration) return expiration;
  if (state.phase !== "open" && state.phase !== "request-ready") bootstrapFail("transition", "submitted or completed admission must be managed by GroupAdmissionRuntime");
  return { state: validateBootstrapSession({ ...state, phase: "cancelled", revision: state.revision + 1, cancellation: { cancellationId, cancelledBy, cancelledAtMs: nowMs } }), replayed: false };
}
