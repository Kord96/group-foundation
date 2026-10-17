import { HYPERKEY_GROUP_PROFILE, type CopyIdentity } from "./group-ports.js";
import { base64url } from "./encoding.js";
import { type HyperKeyFounderGroupPort } from "./founder.js";
import type { StagedNativeGroupTransition } from "@group-foundation/group-core";
/** Minimal native handles; generated core bindings satisfy these interfaces. */
export interface HyperKeyNativeAuthorityHandle { free(): void; }
export interface HyperKeyNativeClientHandle {
  createKeyPackage(profile: Uint8Array): Readonly<{ snapshot: Uint8Array; keyPackage: Uint8Array }>;
  memberId(): Uint8Array;
  createGroup(groupId: Uint8Array, profile: Uint8Array, authority: HyperKeyNativeAuthorityHandle, now: bigint): Readonly<{ snapshot: Uint8Array; groupId: Uint8Array; profile: Uint8Array; epoch: string }>;
  free(): void;
}
export interface HyperKeyNativeModule {
  readonly NativeClient: {
    new(evidence: Uint8Array): HyperKeyNativeClientHandle;
    fromSnapshot(snapshot: Uint8Array): HyperKeyNativeClientHandle;
  };
  readonly NativeAuthorityFacts: new(identityRevision: bigint, identityValidUntil: bigint, governanceRevision: bigint, governanceValidUntil: bigint) => HyperKeyNativeAuthorityHandle;
}

/** Supplied by the authenticated host. No authority is invented by this adapter. */
export interface NativeHyperKeyFounderAuthority {
  authorizeFounder(input: Readonly<{ groupId: string; profile: typeof HYPERKEY_GROUP_PROFILE; founder: CopyIdentity; evidence: Uint8Array; nowMs: number }>, signal?: AbortSignal): Promise<Readonly<{
    identityRevision: bigint;
    identityValidUntilMs: bigint;
    governanceRevision: bigint;
    governanceValidUntilMs: bigint;
  }>>;
}

/** Prepares independently generated MLS material; never receives a conventional seed. */
export async function prepareNativeHyperKeyFounder(input: Readonly<{
  native: HyperKeyNativeModule;
  evidence: Uint8Array;
  copyId: string;
  /** Independently generated X25519 key retained by the host's device custody. */
  recipientDeliveryKey: Uint8Array;
  authority: NativeHyperKeyFounderAuthority;
  nowMs?: () => number;
}>): Promise<Readonly<{ founder: CopyIdentity; group: HyperKeyFounderGroupPort }>> {
  if (!input.authority || typeof input.authority.authorizeFounder !== "function" || !(input.evidence instanceof Uint8Array) || !input.evidence.length || input.evidence.length > 65_536 || !/^[A-Za-z0-9_-]{16,256}$/u.test(input.copyId) || !(input.recipientDeliveryKey instanceof Uint8Array) || input.recipientDeliveryKey.length !== 32) throw new Error("Native HyperKey founder requires explicit host evidence, authority and independent Copy keys");
  const encoder = new TextEncoder(), evidence = new Uint8Array(input.evidence);
  const client = new input.native.NativeClient(evidence);
  let initialSnapshot: Uint8Array;
  let founder: CopyIdentity;
  try {
    const prepared = client.createKeyPackage(encoder.encode(HYPERKEY_GROUP_PROFILE));
    if (!(prepared.snapshot instanceof Uint8Array) || !(prepared.keyPackage instanceof Uint8Array)) throw new Error("Native Group returned an invalid founder KeyPackage");
    initialSnapshot = new Uint8Array(prepared.snapshot);
    founder = Object.freeze({ copyId: input.copyId, member: Object.freeze({ signingKeyFingerprint: base64url(client.memberId()) }), keyPackageDigest: base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(prepared.keyPackage)))), recipientDeliveryKey: base64url(input.recipientDeliveryKey) });
  } finally { client.free(); }
  let staged: StagedNativeGroupTransition | undefined;
  let stageTail = Promise.resolve();
  const group: HyperKeyFounderGroupPort = {
    async stageFounder(request, signal) {
      const operation = stageTail.then(async () => {
      signal?.throwIfAborted();
      if (request.profile !== HYPERKEY_GROUP_PROFILE || JSON.stringify(request.founder) !== JSON.stringify(founder)) throw new Error("Native founder Copy binding differs");
      if (staged) { if (staged.next.groupId !== request.groupId) throw new Error("A prepared founder may create only one Group"); return structuredClone(staged); }
      const nowMs = input.nowMs?.() ?? Date.now();
      if (!Number.isSafeInteger(nowMs) || nowMs < 0) throw new Error("Native Group clock is invalid");
      const facts = await input.authority.authorizeFounder({ groupId: request.groupId, profile: HYPERKEY_GROUP_PROFILE, founder, evidence: new Uint8Array(evidence), nowMs }, signal);
      if ([facts.identityRevision, facts.governanceRevision].some(value => typeof value !== "bigint" || value < 0n) || [facts.identityValidUntilMs, facts.governanceValidUntilMs].some(value => typeof value !== "bigint" || value <= BigInt(nowMs))) throw new Error("Native founder authority facts are invalid or expired");
      const authority = new input.native.NativeAuthorityFacts(facts.identityRevision, facts.identityValidUntilMs, facts.governanceRevision, facts.governanceValidUntilMs);
      const restored = input.native.NativeClient.fromSnapshot(initialSnapshot);
      try {
        const result = restored.createGroup(encoder.encode(request.groupId), encoder.encode(HYPERKEY_GROUP_PROFILE), authority, BigInt(nowMs));
        if (!(result.snapshot instanceof Uint8Array) || !(result.groupId instanceof Uint8Array) || !(result.profile instanceof Uint8Array) || new TextDecoder().decode(result.groupId) !== request.groupId || new TextDecoder().decode(result.profile) !== HYPERKEY_GROUP_PROFILE || !/^(0|[1-9][0-9]*)$/u.test(result.epoch)) throw new Error("Native Group founder result differs from requested scope");
        const transitionId = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(JSON.stringify(["hyperkey.native-founder.v1", request.groupId, founder.member.signingKeyFingerprint])))));
        staged = { schema: "group-foundation.group.native-transition.v1", transitionId, kind: "create", expectedRevision: null, next: { schema: "group-foundation.group.native-state.v1", groupId: request.groupId, profile: HYPERKEY_GROUP_PROFILE, member: founder.member, revision: 0, epoch: result.epoch, snapshot: new Uint8Array(result.snapshot) }, outbox: [] };
        initialSnapshot.fill(0);
        return structuredClone(staged);
      } finally { restored.free(); authority.free(); }
      });
      stageTail = operation.then(() => undefined, () => undefined);
      return operation;
    },
  };
  return Object.freeze({ founder, group });
}
