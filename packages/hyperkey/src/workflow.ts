import { assertHyperKeyDescriptor, type HyperKeyDescriptor } from "./descriptor.js";
import type { CopyIdentity } from "./group-ports.js";

/** Product progress is distinct from Group membership and local key readiness. */
export type HyperKeyCopyStep = "candidate" | "requested" | "approved" | "group-installed" | "ready" | "denied" | "cancelled" | "forgotten";

export interface HyperKeyCopyProgress {
  readonly schema: "hyperkey.copy-progress.v1";
  readonly descriptorId: string;
  readonly descriptor: HyperKeyDescriptor;
  readonly copy: CopyIdentity;
  readonly step: HyperKeyCopyStep;
  readonly admissionId?: string;
  readonly selectedCommitId?: string;
  readonly deliveryId?: string;
}

export interface HyperKeyCopyProgressStore {
  read(descriptorId: string, copyId: string, signal?: AbortSignal): Promise<HyperKeyCopyProgress | undefined>;
  /** Initial creation or an exact forward transition; stale writes must fail. */
  write(progress: HyperKeyCopyProgress, signal?: AbortSignal): Promise<void>;
}

export class HyperKeyCopyProgressError extends Error { override name = "HyperKeyCopyProgressError"; }

export function assertHyperKeyCopyProgress(value: HyperKeyCopyProgress): void {
  if (!value || value.schema !== "hyperkey.copy-progress.v1" || !identifier(value.descriptorId) || !value.copy || !identifier(value.copy.copyId) || !identifier(value.copy.member?.signingKeyFingerprint) || !identifier(value.copy.keyPackageDigest) || !identifier(value.copy.recipientDeliveryKey)) throw new HyperKeyCopyProgressError("Invalid Copy progress binding");
  assertHyperKeyDescriptor(value.descriptor);
  if (!["candidate", "requested", "approved", "group-installed", "ready", "denied", "cancelled", "forgotten"].includes(value.step)) throw new HyperKeyCopyProgressError("Invalid Copy progress step");
  if (["requested", "approved", "group-installed", "ready", "denied"].includes(value.step) && !identifier(value.admissionId)) throw new HyperKeyCopyProgressError("Copy progress lacks its admission ID");
  if (["group-installed", "ready"].includes(value.step) && !identifier(value.selectedCommitId)) throw new HyperKeyCopyProgressError("Copy progress lacks its selected Commit");
  if (value.step === "ready" && !identifier(value.deliveryId)) throw new HyperKeyCopyProgressError("Ready Copy progress lacks its installation delivery");
  for (const optional of [value.admissionId, value.selectedCommitId, value.deliveryId]) if (optional !== undefined && !identifier(optional)) throw new HyperKeyCopyProgressError("Invalid Copy progress identifier");
}

/** No terminal record may be revived by a delayed transport event. */
export function assertHyperKeyCopyProgressTransition(previous: HyperKeyCopyProgress | undefined, next: HyperKeyCopyProgress): void {
  assertHyperKeyCopyProgress(next);
  if (!previous) { if (next.step !== "candidate") throw new HyperKeyCopyProgressError("A Copy workflow begins as a candidate"); return; }
  assertHyperKeyCopyProgress(previous);
  if (previous.descriptorId !== next.descriptorId || JSON.stringify(previous.descriptor) !== JSON.stringify(next.descriptor) || JSON.stringify(previous.copy) !== JSON.stringify(next.copy)) throw new HyperKeyCopyProgressError("Copy progress identity changed");
  for (const key of ["admissionId", "selectedCommitId", "deliveryId"] as const) if (previous[key] !== undefined && previous[key] !== next[key]) throw new HyperKeyCopyProgressError("Copy progress transcript changed");
  const transitions: Record<HyperKeyCopyStep, readonly HyperKeyCopyStep[]> = {
    candidate: ["candidate", "requested", "cancelled", "forgotten"],
    requested: ["requested", "approved", "denied", "cancelled", "forgotten"],
    approved: ["approved", "group-installed", "cancelled", "forgotten"],
    "group-installed": ["group-installed", "ready", "forgotten"],
    ready: ["ready", "forgotten"],
    denied: ["denied", "forgotten"],
    cancelled: ["cancelled", "forgotten"],
    forgotten: ["forgotten"],
  };
  if (!transitions[previous.step].includes(next.step)) throw new HyperKeyCopyProgressError(`Copy progress cannot move from ${previous.step} to ${next.step}`);
}

function identifier(value: unknown): value is string { return typeof value === "string" && value.length > 0 && value.length <= 256; }
