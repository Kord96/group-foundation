import { bytesToBase64url } from "@group-foundation/group-core/encoding";
import { decodeAdmissionRequest } from "../wire.js";
import {
  BOOTSTRAP_LIMITS, BOOTSTRAP_PRESENTATION_SCHEMA, BootstrapError,
  type BootstrapEntropyPort, type BootstrapInspectionPolicy, type BootstrapPresentation,
  type BootstrapPresentationArtifact, type BootstrapPresentationInput, type BootstrapPresentationInspection,
  type BootstrapPresentationSigner, type BootstrapPresentationVerifier, type BootstrapSha256Port,
  type UnsignedBootstrapPresentation,
} from "./contracts.js";
import { bootstrapPresentationTranscript } from "./transcript.js";
import {
  bootstrapBytes, bootstrapFail, bootstrapUnixMs, decodeBootstrapPresentation,
  encodeBootstrapPresentation, validateUnsignedBootstrapPresentation,
} from "./wire.js";

export async function bootstrapSha256(bytes: Uint8Array, hashes: BootstrapSha256Port): Promise<string> {
  let digest: Uint8Array;
  try { digest = await hashes.sha256(new Uint8Array(bytes)); } catch { return bootstrapFail("crypto", "SHA-256 provider failed"); }
  bootstrapBytes(digest, 32, "SHA-256 digest", 32);
  return bytesToBase64url(digest);
}

export async function createBootstrapPresentation(
  input: BootstrapPresentationInput,
  dependencies: { readonly entropy: BootstrapEntropyPort; readonly signer: BootstrapPresentationSigner; readonly hashes: BootstrapSha256Port },
): Promise<BootstrapPresentationArtifact> {
  bootstrapUnixMs(input.createdAtMs, "createdAtMs"); bootstrapUnixMs(input.expiresAtMs, "expiresAtMs");
  if (input.expiresAtMs <= input.createdAtMs) bootstrapFail("clock", "presentation expiry must follow creation");
  let sessionBytes: Uint8Array, nonce: Uint8Array;
  try {
    sessionBytes = await dependencies.entropy.randomBytes(32);
    nonce = await dependencies.entropy.randomBytes(BOOTSTRAP_LIMITS.nonceBytes);
  } catch { return bootstrapFail("crypto", "entropy provider failed"); }
  bootstrapBytes(sessionBytes, 32, "session entropy", 32); bootstrapBytes(nonce, BOOTSTRAP_LIMITS.nonceBytes, "nonce", BOOTSTRAP_LIMITS.nonceBytes);
  const common = {
    schema: BOOTSTRAP_PRESENTATION_SCHEMA, sessionId: bytesToBase64url(sessionBytes),
    createdAtMs: input.createdAtMs, expiresAtMs: input.expiresAtMs, nonce: new Uint8Array(nonce),
    suite: dependencies.signer.suite, verificationKey: new Uint8Array(dependencies.signer.verificationKey),
  };
  const unsigned: UnsignedBootstrapPresentation = input.mode === "offer-target"
    ? { ...common, mode: input.mode, presenterRole: "admission-host", target: new Uint8Array(input.target) }
    : { ...common, mode: input.mode, presenterRole: "candidate", membershipRequest: new Uint8Array(input.membershipRequest) };
  validateUnsignedBootstrapPresentation(unsigned);
  let proof: Uint8Array;
  try { proof = await dependencies.signer.sign(bootstrapPresentationTranscript(unsigned)); }
  catch { return bootstrapFail("crypto", "presentation signer failed"); }
  bootstrapBytes(proof, BOOTSTRAP_LIMITS.proofBytes, "proof");
  const presentation = { ...unsigned, proof: new Uint8Array(proof) } as BootstrapPresentation;
  const wire = encodeBootstrapPresentation(presentation);
  return { presentation: decodeBootstrapPresentation(wire), wire, wireSha256: await bootstrapSha256(wire, dependencies.hashes) };
}

/** Authenticate exact wire without applying the caller's live-time acceptance policy. */
export async function authenticateBootstrapPresentation(wire: Uint8Array, verifier: BootstrapPresentationVerifier): Promise<BootstrapPresentation> {
  const presentation = decodeBootstrapPresentation(wire);
  try {
    await verifier.verify({
      suite: presentation.suite, verificationKey: new Uint8Array(presentation.verificationKey),
      transcript: bootstrapPresentationTranscript(presentation), proof: new Uint8Array(presentation.proof),
    });
  } catch (error) {
    if (error instanceof BootstrapError) throw error;
    return bootstrapFail("crypto", "presentation proof verification failed");
  }
  return presentation;
}

/** Decode, authenticate, enforce explicit time policy, and expose bounded presentation metadata. */
export async function inspectBootstrapPresentation(
  wire: Uint8Array,
  dependencies: { readonly verifier: BootstrapPresentationVerifier; readonly hashes: BootstrapSha256Port },
  policy: BootstrapInspectionPolicy,
): Promise<BootstrapPresentationInspection> {
  const now = bootstrapUnixMs(policy.nowMs, "nowMs");
  if (!Number.isSafeInteger(policy.maxLifetimeMs) || policy.maxLifetimeMs < 1 || !Number.isSafeInteger(policy.maxFutureSkewMs) || policy.maxFutureSkewMs < 0) bootstrapFail("invalid-input", "inspection time policy is invalid");
  const presentation = await authenticateBootstrapPresentation(wire, dependencies.verifier);
  if (presentation.expiresAtMs <= now) bootstrapFail("expired", "bootstrap presentation expired");
  if (presentation.createdAtMs > now + policy.maxFutureSkewMs) bootstrapFail("clock", "bootstrap presentation is from the future");
  if (presentation.expiresAtMs - presentation.createdAtMs > policy.maxLifetimeMs) bootstrapFail("expired", "bootstrap presentation exceeds the accepted lifetime");
  const localRole = presentation.presenterRole === "admission-host" ? "candidate" : "admission-host";
  const result: BootstrapPresentationInspection = {
    presentation, wire: new Uint8Array(wire), wireSha256: await bootstrapSha256(wire, dependencies.hashes),
    localRole, remoteRole: presentation.presenterRole,
    ...(presentation.mode === "request-membership" ? { membershipRequest: decodeAdmissionRequest(presentation.membershipRequest) } : {}),
  };
  return result;
}
