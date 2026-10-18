import { base64urlToBytes, bytesToBase64url, canonicalJson } from "@group-foundation/group-core/encoding";
import { decodeAdmissionRequest } from "../wire.js";
import {
  BOOTSTRAP_CHANNEL_AAD_DOMAIN, BOOTSTRAP_CHANNEL_ENVELOPE_SCHEMA, BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA,
  BOOTSTRAP_CHANNEL_SCHEMA, BOOTSTRAP_LIMITS,
  type BootstrapChannelCryptoPort, type BootstrapChannelEmission, type BootstrapChannelEnvelope,
  type BootstrapChannelMessage, type BootstrapChannelReception, type BootstrapChannelSnapshot,
  type BootstrapPresentationInspection, type BootstrapRole, type BootstrapSha256Port,
  type BootstrapSessionSnapshot,
} from "./contracts.js";
import { bootstrapSha256 } from "./presentation.js";
import { attachBootstrapMembershipRequest } from "./session.js";
import { bootstrapBytes, bootstrapFail, bootstrapIdentifier, bootstrapUnixMs, encodeBootstrapJson, type BootstrapJson } from "./wire.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

function otherRole(role: BootstrapRole): BootstrapRole { return role === "admission-host" ? "candidate" : "admission-host"; }
function clone<T>(value: T): T { return structuredClone(value); }

function digest(value: unknown, field: string): string {
  if (typeof value !== "string") bootstrapFail("invalid-input", `${field} is invalid`);
  let bytes: Uint8Array;
  try { bytes = base64urlToBytes(value, 32, field); } catch { return bootstrapFail("invalid-input", `${field} is invalid`); }
  if (bytes.length !== 32) bootstrapFail("invalid-input", `${field} is invalid`);
  return value;
}

function suite(value: unknown): string {
  if (typeof value !== "string" || value.length < 1 || value.length > BOOTSTRAP_LIMITS.suiteChars || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/u.test(value)) bootstrapFail("invalid-input", "channel suite is invalid");
  return value;
}

function exactObject(value: unknown, required: readonly string[], code: "invalid-input" | "invalid-wire"): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value) || required.some(key => !Object.hasOwn(value, key)) || Object.keys(value).some(key => !required.includes(key))) bootstrapFail(code, "unexpected channel fields");
  return value as Record<string, unknown>;
}

function canonicalParse(wire: Uint8Array, limit: number): unknown {
  bootstrapBytes(wire, limit, "channel wire");
  let parsed: unknown;
  try { parsed = JSON.parse(decoder.decode(wire)); } catch { return bootstrapFail("invalid-wire", "channel wire must be UTF-8 JSON"); }
  const canonical = encoder.encode(canonicalJson(parsed as BootstrapJson));
  if (canonical.length !== wire.length || !canonical.every((byte, index) => byte === wire[index])) bootstrapFail("invalid-wire", "channel wire must be canonical JSON");
  return parsed;
}

function decodeWireBytes(value: unknown, limit: number, field: string): Uint8Array {
  if (typeof value !== "string") bootstrapFail("invalid-wire", `${field} must be canonical base64url`);
  try { return bootstrapBytes(base64urlToBytes(value, limit, field), limit, field); }
  catch { return bootstrapFail("invalid-wire", `${field} must be canonical base64url`); }
}

function messageJson(message: BootstrapChannelMessage): BootstrapJson {
  const base = { schema: message.schema, kind: message.kind };
  switch (message.kind) {
    case "peer-hello": return { ...base, channelOffer: bytesToBase64url(message.channelOffer) };
    case "target-selection": return { ...base, target: bytesToBase64url(message.target) };
    case "candidate-payload": return { ...base, candidate: bytesToBase64url(message.candidate) };
    case "acceptance": return { ...base, acceptance: bytesToBase64url(message.acceptance) };
    case "rejection": return { ...base, rejectionCode: message.rejectionCode };
    case "progress": return { ...base, progressCode: message.progressCode };
    case "admission-request": return { ...base, request: bytesToBase64url(message.request) };
  }
}

export function encodeBootstrapChannelMessage(message: BootstrapChannelMessage): Uint8Array {
  validateMessage(message);
  return encodeBootstrapJson(messageJson(message), BOOTSTRAP_LIMITS.channelMessageBytes);
}

export function decodeBootstrapChannelMessage(wire: Uint8Array): BootstrapChannelMessage {
  const parsed = canonicalParse(wire, BOOTSTRAP_LIMITS.channelMessageBytes);
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) bootstrapFail("invalid-wire", "channel message must be an object");
  const row0 = parsed as Record<string, unknown>;
  const fields: Record<string, string> = {
    "peer-hello": "channelOffer", "target-selection": "target", "candidate-payload": "candidate",
    acceptance: "acceptance", rejection: "rejectionCode", progress: "progressCode", "admission-request": "request",
  };
  const payloadField = typeof row0.kind === "string" ? fields[row0.kind] : undefined;
  if (!payloadField) bootstrapFail("invalid-wire", "unsupported channel message kind");
  const row = exactObject(parsed, ["schema", "kind", payloadField], "invalid-wire");
  if (row.schema !== BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA) bootstrapFail("invalid-wire", "unsupported channel message schema");
  let value: BootstrapChannelMessage;
  switch (row.kind) {
    case "peer-hello": value = { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: row.kind, channelOffer: decodeWireBytes(row.channelOffer, BOOTSTRAP_LIMITS.channelOfferBytes, "channelOffer") }; break;
    case "target-selection": value = { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: row.kind, target: decodeWireBytes(row.target, BOOTSTRAP_LIMITS.targetBytes, "target") }; break;
    case "candidate-payload": value = { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: row.kind, candidate: decodeWireBytes(row.candidate, BOOTSTRAP_LIMITS.candidateBytes, "candidate") }; break;
    case "acceptance": value = { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: row.kind, acceptance: decodeWireBytes(row.acceptance, BOOTSTRAP_LIMITS.targetBytes, "acceptance") }; break;
    case "rejection": value = { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: row.kind, rejectionCode: bootstrapIdentifier(row.rejectionCode, "rejectionCode") }; break;
    case "progress": value = { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: row.kind, progressCode: bootstrapIdentifier(row.progressCode, "progressCode") }; break;
    case "admission-request": {
      const request = decodeWireBytes(row.request, BOOTSTRAP_LIMITS.requestBytes, "request");
      decodeAdmissionRequest(request);
      value = { schema: BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA, kind: row.kind, request };
      break;
    }
    default: return bootstrapFail("invalid-wire", "unsupported channel message kind");
  }
  return value;
}

function validateMessage(message: BootstrapChannelMessage): void {
  if (message.schema !== BOOTSTRAP_CHANNEL_MESSAGE_SCHEMA) bootstrapFail("invalid-input", "unsupported channel message schema");
  switch (message.kind) {
    case "peer-hello": bootstrapBytes(message.channelOffer, BOOTSTRAP_LIMITS.channelOfferBytes, "channelOffer"); break;
    case "target-selection": bootstrapBytes(message.target, BOOTSTRAP_LIMITS.targetBytes, "target"); break;
    case "candidate-payload": bootstrapBytes(message.candidate, BOOTSTRAP_LIMITS.candidateBytes, "candidate"); break;
    case "acceptance": bootstrapBytes(message.acceptance, BOOTSTRAP_LIMITS.targetBytes, "acceptance"); break;
    case "rejection": bootstrapIdentifier(message.rejectionCode, "rejectionCode"); break;
    case "progress": bootstrapIdentifier(message.progressCode, "progressCode"); break;
    case "admission-request": bootstrapBytes(message.request, BOOTSTRAP_LIMITS.requestBytes, "request"); decodeAdmissionRequest(message.request); break;
  }
}

function envelopeJson(envelope: BootstrapChannelEnvelope, includeCiphertext: boolean): BootstrapJson {
  return {
    schema: envelope.schema, sessionId: envelope.sessionId, senderRole: envelope.senderRole, sequence: envelope.sequence,
    sentAtMs: envelope.sentAtMs, expiresAtMs: envelope.expiresAtMs,
    previousTranscriptSha256: envelope.previousTranscriptSha256, suite: envelope.suite,
    ...(includeCiphertext ? { ciphertext: bytesToBase64url(envelope.ciphertext) } : {}),
  };
}

export function encodeBootstrapChannelEnvelope(envelope: BootstrapChannelEnvelope): Uint8Array {
  validateEnvelope(envelope);
  return encodeBootstrapJson(envelopeJson(envelope, true), BOOTSTRAP_LIMITS.wireBytes);
}

export function decodeBootstrapChannelEnvelope(wire: Uint8Array): BootstrapChannelEnvelope {
  const row = exactObject(canonicalParse(wire, BOOTSTRAP_LIMITS.wireBytes), ["schema", "sessionId", "senderRole", "sequence", "sentAtMs", "expiresAtMs", "previousTranscriptSha256", "suite", "ciphertext"], "invalid-wire");
  const envelope: BootstrapChannelEnvelope = {
    schema: row.schema as typeof BOOTSTRAP_CHANNEL_ENVELOPE_SCHEMA,
    sessionId: bootstrapIdentifier(row.sessionId, "sessionId"), senderRole: row.senderRole as BootstrapRole,
    sequence: row.sequence as number, sentAtMs: bootstrapUnixMs(row.sentAtMs, "sentAtMs"), expiresAtMs: bootstrapUnixMs(row.expiresAtMs, "expiresAtMs"),
    previousTranscriptSha256: digest(row.previousTranscriptSha256, "previousTranscriptSha256"), suite: suite(row.suite),
    ciphertext: decodeWireBytes(row.ciphertext, BOOTSTRAP_LIMITS.channelCiphertextBytes, "ciphertext"),
  };
  validateEnvelope(envelope);
  return envelope;
}

function validateEnvelope(envelope: BootstrapChannelEnvelope): void {
  if (envelope.schema !== BOOTSTRAP_CHANNEL_ENVELOPE_SCHEMA) bootstrapFail("invalid-wire", "unsupported channel envelope schema");
  bootstrapIdentifier(envelope.sessionId, "sessionId");
  if (envelope.senderRole !== "admission-host" && envelope.senderRole !== "candidate") bootstrapFail("role", "invalid channel sender role");
  if (!Number.isSafeInteger(envelope.sequence) || envelope.sequence < 1) bootstrapFail("invalid-wire", "channel sequence is invalid");
  bootstrapUnixMs(envelope.sentAtMs, "sentAtMs"); bootstrapUnixMs(envelope.expiresAtMs, "expiresAtMs");
  digest(envelope.previousTranscriptSha256, "previousTranscriptSha256"); suite(envelope.suite);
  bootstrapBytes(envelope.ciphertext, BOOTSTRAP_LIMITS.channelCiphertextBytes, "ciphertext");
}

function channelAad(state: BootstrapChannelSnapshot, envelope: BootstrapChannelEnvelope): Uint8Array {
  return encodeBootstrapJson({ domain: BOOTSTRAP_CHANNEL_AAD_DOMAIN, presentationSha256: state.presentationSha256, envelope: envelopeJson(envelope, false) });
}

async function initialTranscript(presentationSha256: string, senderRole: BootstrapRole, hashes: BootstrapSha256Port): Promise<string> {
  return bootstrapSha256(encodeBootstrapJson({ domain: BOOTSTRAP_CHANNEL_AAD_DOMAIN, presentationSha256, senderRole }), hashes);
}

export async function createBootstrapChannelSession(
  inspection: BootstrapPresentationInspection,
  localRole: BootstrapRole,
  local: Readonly<{ custodyId: string; offer: Uint8Array; suite: string }>,
  hashes: BootstrapSha256Port,
): Promise<BootstrapChannelSnapshot> {
  const presentation = inspection.presentation;
  if (localRole !== "admission-host" && localRole !== "candidate") bootstrapFail("role", "invalid local channel role");
  if (local.suite !== presentation.channelSuite) bootstrapFail("crypto", "local channel suite differs from signed presentation");
  bootstrapIdentifier(local.custodyId, "localCustodyId");
  const localOffer = bootstrapBytes(local.offer, BOOTSTRAP_LIMITS.channelOfferBytes, "localOffer");
  const isPresenter = localRole === presentation.presenterRole;
  if (isPresenter && !sameBytes(localOffer, presentation.channelOffer)) bootstrapFail("crypto", "presenter channel offer differs from signed presentation");
  const outboundTranscriptSha256 = await initialTranscript(inspection.wireSha256, localRole, hashes);
  const inboundTranscriptSha256 = await initialTranscript(inspection.wireSha256, otherRole(localRole), hashes);
  const state: BootstrapChannelSnapshot = {
    schema: BOOTSTRAP_CHANNEL_SCHEMA, sessionId: presentation.sessionId, mode: presentation.mode,
    localRole, remoteRole: otherRole(localRole), presenterRole: presentation.presenterRole,
    presentationSha256: inspection.wireSha256, createdAtMs: presentation.createdAtMs, expiresAtMs: presentation.expiresAtMs,
    suite: presentation.channelSuite, localCustodyId: local.custodyId, localOffer,
    ...(isPresenter ? {} : { remoteOffer: new Uint8Array(presentation.channelOffer) }),
    outboundSequence: 0, inboundSequence: 0, outboundTranscriptSha256, inboundTranscriptSha256,
    helloSent: false, helloReceived: false,
    ...(presentation.mode === "offer-target" ? { targetSha256: await bootstrapSha256(presentation.target, hashes) } : {}),
    revision: 0, terminal: false,
  };
  return validateBootstrapChannelSession(state);
}

export function validateBootstrapChannelSession(value: BootstrapChannelSnapshot): BootstrapChannelSnapshot {
  const required = ["schema", "sessionId", "mode", "localRole", "remoteRole", "presenterRole", "presentationSha256", "createdAtMs", "expiresAtMs", "suite", "localCustodyId", "localOffer", "outboundSequence", "inboundSequence", "outboundTranscriptSha256", "inboundTranscriptSha256", "helloSent", "helloReceived", "revision", "terminal"];
  const optional = ["remoteOffer", "targetSha256", "candidateSha256", "decision", "requestWire", "requestSha256"];
  exactObject(value, [...required, ...optional.filter(key => Object.hasOwn(value, key))], "invalid-input");
  if (value.schema !== BOOTSTRAP_CHANNEL_SCHEMA || !["offer-target", "request-membership"].includes(value.mode)) bootstrapFail("invalid-input", "invalid channel identity");
  if (!["admission-host", "candidate"].includes(value.localRole) || value.remoteRole !== otherRole(value.localRole) || ![value.localRole, value.remoteRole].includes(value.presenterRole)) bootstrapFail("role", "invalid channel roles");
  bootstrapIdentifier(value.sessionId, "sessionId"); digest(value.presentationSha256, "presentationSha256");
  bootstrapUnixMs(value.createdAtMs, "createdAtMs"); bootstrapUnixMs(value.expiresAtMs, "expiresAtMs");
  if (value.expiresAtMs <= value.createdAtMs) bootstrapFail("clock", "channel expiry must follow creation");
  suite(value.suite); bootstrapIdentifier(value.localCustodyId, "localCustodyId"); bootstrapBytes(value.localOffer, BOOTSTRAP_LIMITS.channelOfferBytes, "localOffer");
  if (value.remoteOffer !== undefined) bootstrapBytes(value.remoteOffer, BOOTSTRAP_LIMITS.channelOfferBytes, "remoteOffer");
  for (const [field, sequence] of [["outboundSequence", value.outboundSequence], ["inboundSequence", value.inboundSequence]] as const) if (!Number.isSafeInteger(sequence) || sequence < 0) bootstrapFail("invalid-input", `${field} is invalid`);
  if (!Number.isSafeInteger(value.revision) || value.revision < 0) bootstrapFail("invalid-input", "revision is invalid");
  digest(value.outboundTranscriptSha256, "outboundTranscriptSha256"); digest(value.inboundTranscriptSha256, "inboundTranscriptSha256");
  if (typeof value.helloSent !== "boolean" || typeof value.helloReceived !== "boolean" || typeof value.terminal !== "boolean") bootstrapFail("invalid-input", "channel flags are invalid");
  if (value.helloSent !== (value.outboundSequence > 0) || value.helloReceived !== (value.inboundSequence > 0)) bootstrapFail("invalid-input", "hello state differs from channel sequence");
  if (value.helloReceived && value.remoteOffer === undefined) bootstrapFail("invalid-input", "received hello lost its channel offer");
  if (value.targetSha256 !== undefined) digest(value.targetSha256, "targetSha256");
  if (value.candidateSha256 !== undefined) digest(value.candidateSha256, "candidateSha256");
  if (value.decision !== undefined && value.decision !== "accepted" && value.decision !== "rejected") bootstrapFail("invalid-input", "decision is invalid");
  const hasRequest = value.requestWire !== undefined || value.requestSha256 !== undefined;
  if (hasRequest !== (value.requestWire !== undefined && value.requestSha256 !== undefined)) bootstrapFail("invalid-input", "request and digest must be retained together");
  if (value.requestWire !== undefined) { bootstrapBytes(value.requestWire, BOOTSTRAP_LIMITS.requestBytes, "requestWire"); decodeAdmissionRequest(value.requestWire); digest(value.requestSha256, "requestSha256"); }
  if (value.terminal !== (value.decision === "rejected" || hasRequest) || hasRequest && value.decision !== "accepted") bootstrapFail("invalid-input", "terminal state is inconsistent");
  return clone(value);
}

function ensureLive(state: BootstrapChannelSnapshot, nowMs: number): void {
  const now = bootstrapUnixMs(nowMs, "nowMs");
  if (now < state.createdAtMs) bootstrapFail("clock", "channel clock precedes presentation creation");
  if (now >= state.expiresAtMs) bootstrapFail("expired", "bootstrap channel expired");
  if (state.terminal) bootstrapFail("transition", "bootstrap channel is terminal");
}

async function applyMessage(state0: BootstrapChannelSnapshot, message: BootstrapChannelMessage, senderRole: BootstrapRole, hashes: BootstrapSha256Port): Promise<BootstrapChannelSnapshot> {
  const state = clone(state0);
  if (message.kind !== "peer-hello" && (!state.helloSent || !state.helloReceived)) bootstrapFail("transition", "peer hello exchange is incomplete");
  switch (message.kind) {
    case "peer-hello": {
      const local = senderRole === state.localRole;
      if (local ? state.helloSent : state.helloReceived) bootstrapFail("replay", "peer hello already recorded");
      if (local && !sameBytes(message.channelOffer, state.localOffer)) bootstrapFail("crypto", "local hello offer changed");
      if (!local && state.remoteOffer !== undefined && !sameBytes(message.channelOffer, state.remoteOffer)) bootstrapFail("crypto", "remote hello offer differs from signed presentation");
      return { ...state, ...(local ? { helloSent: true } : { helloReceived: true, remoteOffer: new Uint8Array(message.channelOffer) }) };
    }
    case "target-selection":
      if (senderRole !== "admission-host" || state.mode !== "request-membership" || state.targetSha256 !== undefined) bootstrapFail("role", "target selection is not allowed");
      return { ...state, targetSha256: await bootstrapSha256(message.target, hashes) };
    case "candidate-payload":
      if (senderRole !== "candidate" || state.targetSha256 === undefined || state.candidateSha256 !== undefined) bootstrapFail("role", "candidate payload is not allowed");
      return { ...state, candidateSha256: await bootstrapSha256(message.candidate, hashes) };
    case "acceptance":
      if (senderRole !== "admission-host" || state.targetSha256 === undefined || state.candidateSha256 === undefined || state.decision !== undefined) bootstrapFail("role", "acceptance is not allowed");
      return { ...state, decision: "accepted" };
    case "rejection":
      if (senderRole !== "admission-host" || state.targetSha256 === undefined || state.decision !== undefined) bootstrapFail("role", "rejection is not allowed");
      return { ...state, decision: "rejected", terminal: true };
    case "progress": return state;
    case "admission-request":
      if (senderRole !== "candidate" || state.decision !== "accepted" || state.requestWire !== undefined) bootstrapFail("role", "admission request handoff is not allowed");
      return { ...state, requestWire: new Uint8Array(message.request), requestSha256: await bootstrapSha256(message.request, hashes), terminal: true };
  }
}

export async function emitBootstrapChannelMessage(
  snapshot: BootstrapChannelSnapshot, message: BootstrapChannelMessage,
  dependencies: { readonly crypto: BootstrapChannelCryptoPort; readonly hashes: BootstrapSha256Port }, nowMs: number,
): Promise<BootstrapChannelEmission> {
  const state = validateBootstrapChannelSession(snapshot); ensureLive(state, nowMs); validateMessage(message);
  if (dependencies.crypto.suite !== state.suite) bootstrapFail("crypto", "channel crypto suite differs from session");
  if (state.remoteOffer === undefined) bootstrapFail("transition", "remote channel offer is not known");
  const next = await applyMessage(state, message, state.localRole, dependencies.hashes);
  const envelopeBase: BootstrapChannelEnvelope = {
    schema: BOOTSTRAP_CHANNEL_ENVELOPE_SCHEMA, sessionId: state.sessionId, senderRole: state.localRole,
    sequence: state.outboundSequence + 1, sentAtMs: nowMs, expiresAtMs: state.expiresAtMs,
    previousTranscriptSha256: state.outboundTranscriptSha256, suite: state.suite, ciphertext: new Uint8Array([1]),
  };
  let ciphertext: Uint8Array;
  try {
    ciphertext = await dependencies.crypto.seal({ localCustodyId: state.localCustodyId, recipientOffer: new Uint8Array(state.remoteOffer), aad: channelAad(state, envelopeBase), plaintext: encodeBootstrapChannelMessage(message) });
  } catch { return bootstrapFail("crypto", "channel sealing failed"); }
  bootstrapBytes(ciphertext, BOOTSTRAP_LIMITS.channelCiphertextBytes, "ciphertext");
  const envelope = { ...envelopeBase, ciphertext: new Uint8Array(ciphertext) };
  const wire = encodeBootstrapChannelEnvelope(envelope);
  const updated = validateBootstrapChannelSession({ ...next, outboundSequence: envelope.sequence, outboundTranscriptSha256: await bootstrapSha256(wire, dependencies.hashes), revision: state.revision + 1 });
  return { state: updated, envelope, wire };
}

export async function receiveBootstrapChannelMessage(
  snapshot: BootstrapChannelSnapshot, exactEnvelopeWire: Uint8Array,
  dependencies: { readonly crypto: BootstrapChannelCryptoPort; readonly hashes: BootstrapSha256Port }, nowMs: number,
): Promise<BootstrapChannelReception> {
  const state = validateBootstrapChannelSession(snapshot); ensureLive(state, nowMs);
  const envelope = decodeBootstrapChannelEnvelope(exactEnvelopeWire);
  if (dependencies.crypto.suite !== state.suite || envelope.suite !== state.suite) bootstrapFail("crypto", "channel suite differs from session");
  if (envelope.sessionId !== state.sessionId || envelope.senderRole !== state.remoteRole) bootstrapFail("role", "envelope is for a different session or role");
  if (envelope.expiresAtMs !== state.expiresAtMs || envelope.sentAtMs < state.createdAtMs || envelope.sentAtMs >= state.expiresAtMs) bootstrapFail("clock", "envelope time is invalid");
  if (envelope.sequence !== state.inboundSequence + 1) bootstrapFail("replay", "envelope sequence is not the next expected value");
  if (envelope.previousTranscriptSha256 !== state.inboundTranscriptSha256) bootstrapFail("replay", "envelope transcript predecessor differs");
  let plaintext: Uint8Array;
  try { plaintext = await dependencies.crypto.open({ localCustodyId: state.localCustodyId, aad: channelAad(state, envelope), ciphertext: new Uint8Array(envelope.ciphertext) }); }
  catch { return bootstrapFail("crypto", "channel opening failed"); }
  const message = decodeBootstrapChannelMessage(plaintext);
  const next = await applyMessage(state, message, state.remoteRole, dependencies.hashes);
  const updated = validateBootstrapChannelSession({ ...next, inboundSequence: envelope.sequence, inboundTranscriptSha256: await bootstrapSha256(exactEnvelopeWire, dependencies.hashes), revision: state.revision + 1 });
  return { state: updated, message, ...(message.kind === "admission-request" ? { admissionRequest: decodeAdmissionRequest(message.request) } : {}) };
}

export async function handoffBootstrapChannelRequest(
  channelSnapshot: BootstrapChannelSnapshot, admissionSnapshot: BootstrapSessionSnapshot,
  hashes: BootstrapSha256Port, nowMs: number,
) {
  const channel = validateBootstrapChannelSession(channelSnapshot);
  if (channel.localRole !== "admission-host" || channel.requestWire === undefined) bootstrapFail("role", "host has no exact admission request to hand off");
  if (channel.sessionId !== admissionSnapshot.sessionId || channel.presentationSha256 !== admissionSnapshot.presentationSha256) bootstrapFail("replay", "channel differs from admission session");
  return attachBootstrapMembershipRequest(admissionSnapshot, channel.requestWire, hashes, nowMs);
}
