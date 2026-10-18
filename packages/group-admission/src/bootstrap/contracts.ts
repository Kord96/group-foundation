import type { AdmissionRequest } from "../contracts.js";

export const BOOTSTRAP_PRESENTATION_SCHEMA = "group-foundation.admission.bootstrap.presentation.v1" as const;
export const BOOTSTRAP_SESSION_SCHEMA = "group-foundation.admission.bootstrap.session.v1" as const;
export const BOOTSTRAP_PRESENTATION_DOMAIN = "group-foundation.admission.bootstrap.presentation-proof.v1" as const;

export const BOOTSTRAP_LIMITS = Object.freeze({
  wireBytes: 768 * 1024,
  targetBytes: 64 * 1024,
  requestBytes: 512 * 1024,
  verificationKeyBytes: 8 * 1024,
  proofBytes: 16 * 1024,
  sessionIdBytesMin: 16,
  sessionIdBytesMax: 64,
  nonceBytes: 32,
  suiteChars: 128,
  identifierChars: 1024,
  maxUnixMs: 8_640_000_000_000_000,
});

export type BootstrapMode = "offer-target" | "request-membership";
/** Protocol roles only. They do not grant a product, group, or governance role. */
export type BootstrapRole = "admission-host" | "candidate";
export type BootstrapSessionPhase = "open" | "request-ready" | "submitted" | "completed" | "cancelled" | "expired";

interface BootstrapPresentationBase {
  readonly schema: typeof BOOTSTRAP_PRESENTATION_SCHEMA;
  readonly sessionId: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly nonce: Uint8Array;
  readonly suite: string;
  readonly verificationKey: Uint8Array;
  readonly proof: Uint8Array;
}

export interface OfferTargetPresentation extends BootstrapPresentationBase {
  readonly mode: "offer-target";
  readonly presenterRole: "admission-host";
  /** Opaque consumer-defined target/invitation material. Foundation does not interpret routing or policy. */
  readonly target: Uint8Array;
}

export interface RequestMembershipPresentation extends BootstrapPresentationBase {
  readonly mode: "request-membership";
  readonly presenterRole: "candidate";
  /** Exact canonical `AdmissionRequest` wire, suitable for the admission submission bridge. */
  readonly membershipRequest: Uint8Array;
}

export type BootstrapPresentation = OfferTargetPresentation | RequestMembershipPresentation;
export type UnsignedBootstrapPresentation =
  | Omit<OfferTargetPresentation, "proof">
  | Omit<RequestMembershipPresentation, "proof">;

export type BootstrapPresentationInput =
  | { readonly mode: "offer-target"; readonly target: Uint8Array; readonly createdAtMs: number; readonly expiresAtMs: number }
  | { readonly mode: "request-membership"; readonly membershipRequest: Uint8Array; readonly createdAtMs: number; readonly expiresAtMs: number };

export interface BootstrapPresentationSigner {
  /** A stable, bounded suite name. Implementations must use a reviewed signature primitive. */
  readonly suite: string;
  readonly verificationKey: Uint8Array;
  sign(transcript: Uint8Array): Promise<Uint8Array>;
}

export interface BootstrapPresentationVerifier {
  /** Reject unsupported suites rather than selecting an algorithm from untrusted key bytes. */
  verify(input: {
    readonly suite: string;
    readonly verificationKey: Uint8Array;
    readonly transcript: Uint8Array;
    readonly proof: Uint8Array;
  }): Promise<void>;
}

export interface BootstrapEntropyPort {
  /** Must return cryptographically secure random bytes and exactly the requested length. */
  randomBytes(length: number): Promise<Uint8Array> | Uint8Array;
}

export interface BootstrapSha256Port {
  /** SHA-256 only; return exactly 32 bytes. */
  sha256(bytes: Uint8Array): Promise<Uint8Array>;
}

export interface BootstrapInspectionPolicy {
  readonly nowMs: number;
  /** Product-selected acceptance window. Wire validity may be shorter. */
  readonly maxLifetimeMs: number;
  /** Product-selected allowance for a presenter's clock being ahead. */
  readonly maxFutureSkewMs: number;
}

export interface BootstrapPresentationInspection {
  readonly presentation: BootstrapPresentation;
  readonly wire: Uint8Array;
  readonly wireSha256: string;
  readonly localRole: BootstrapRole;
  readonly remoteRole: BootstrapRole;
  readonly membershipRequest?: AdmissionRequest;
}

export interface BootstrapPresentationArtifact {
  readonly presentation: BootstrapPresentation;
  readonly wire: Uint8Array;
  readonly wireSha256: string;
}

export interface BootstrapSessionSnapshot {
  readonly schema: typeof BOOTSTRAP_SESSION_SCHEMA;
  readonly sessionId: string;
  readonly mode: BootstrapMode;
  readonly localRole: BootstrapRole;
  readonly remoteRole: BootstrapRole;
  readonly presentationWire: Uint8Array;
  readonly presentationSha256: string;
  readonly createdAtMs: number;
  readonly expiresAtMs: number;
  readonly phase: BootstrapSessionPhase;
  readonly revision: number;
  readonly requestWire?: Uint8Array;
  readonly requestSha256?: string;
  readonly submission?: Readonly<{ submissionId: string; submittedAtMs: number }>;
  readonly completion?: Readonly<{ completionId: string; completedAtMs: number }>;
  readonly cancellation?: Readonly<{ cancellationId: string; cancelledBy: BootstrapRole; cancelledAtMs: number }>;
}

export interface BootstrapTransition {
  readonly state: BootstrapSessionSnapshot;
  readonly replayed: boolean;
}

/**
 * Structural boundary to the durable admission-submission lane. A production adapter passes its
 * existing physical transaction so the session handoff and admission insertion commit together.
 */
export interface MembershipSubmissionPort<Transaction, Result = unknown> {
  commitSubmission(transaction: Transaction, exactRequest: Uint8Array): Promise<Result>;
}

export class BootstrapError extends Error {
  constructor(readonly code: "bounds" | "clock" | "crypto" | "expired" | "invalid-input" | "invalid-wire" | "replay" | "role" | "transition", message: string) {
    super(message); this.name = "BootstrapError";
  }
}
