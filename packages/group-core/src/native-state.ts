import { GroupError, type MemberIdentity } from "./contracts.js";

/** Private, authenticated local MLS state. Never put this record on a transport. */
export interface NativeGroupState {
  readonly schema: "group-foundation.group.native-state.v1";
  readonly groupId: string;
  readonly profile: string;
  readonly member: MemberIdentity;
  readonly revision: number;
  readonly epoch: string;
  readonly snapshot: Uint8Array;
}
export interface NativeGroupOutboxRecord {
  readonly id: string;
  readonly kind: "commit" | "welcome" | "installation" | "application";
  readonly bytes: Uint8Array;
  readonly digest: string;
}
/** One physical CAS must stage private state and the exact public work it produces. */
export interface StagedNativeGroupTransition {
  readonly schema: "group-foundation.group.native-transition.v1";
  readonly transitionId: string;
  readonly kind: "create" | "key-package" | "add" | "remove" | "join" | "commit" | "application-send" | "application-receive";
  readonly expectedRevision: number | null;
  readonly next: NativeGroupState;
  readonly outbox: readonly NativeGroupOutboxRecord[];
}
export interface NativeGroupTransitionStoragePort {
  read(groupId: string, member: MemberIdentity): Promise<NativeGroupState | undefined>;
  /** Atomically compare revision, store next snapshot/outbox, and remember transitionId.
   * Equal transition retries return replayed=true; changed bytes for an ID must fail.
   * No transport publishing is allowed before this returns durably. */
  commit(transition: StagedNativeGroupTransition): Promise<Readonly<{ state: NativeGroupState; replayed: boolean }>>;
}

/** Typed shape of the detached WASM results, after validation by the integration. */
export interface NativeGroupResult { readonly snapshot: Uint8Array; readonly groupId: Uint8Array; readonly profile: Uint8Array; readonly epoch: string; }
export interface NativeGroupAddResult extends NativeGroupResult { readonly priorEpoch: string; readonly commit: Uint8Array; readonly welcome: Uint8Array; readonly ratchetTree: Uint8Array; }
export interface NativeGroupCommitResult extends NativeGroupResult { readonly priorEpoch: string; readonly ratchetTree: Uint8Array; }
export interface NativeGroupRemoveResult extends NativeGroupCommitResult { readonly commit: Uint8Array; }
export interface NativeGroupSealResult extends NativeGroupResult { readonly message: Uint8Array; }
export interface NativeGroupOpenResult extends NativeGroupResult { readonly sender: Uint8Array; readonly plaintext: Uint8Array; }

export function assertNativeGroupState(state: NativeGroupState): void {
  if (!state || state.schema !== "group-foundation.group.native-state.v1" || typeof state.groupId !== "string" || !state.groupId.length || state.groupId.length > 256 || typeof state.profile !== "string" || !state.profile.length || state.profile.length > 4096 || typeof state.member?.signingKeyFingerprint !== "string" || !state.member.signingKeyFingerprint.length || state.member.signingKeyFingerprint.length > 86 || !Number.isSafeInteger(state.revision) || state.revision < 0 || typeof state.epoch !== "string" || state.epoch.length > 20 || !/^(0|[1-9][0-9]*)$/u.test(state.epoch) || BigInt(state.epoch) > 18446744073709551615n || !(state.snapshot instanceof Uint8Array) || !state.snapshot.length || state.snapshot.length > 17 * 1024 * 1024) throw new GroupError("native-transition", "invalid native Group state");
}

/** Validates storage boundary bounds; native MLS results must still be authenticated by the caller. */
export function assertStagedNativeGroupTransition(value: StagedNativeGroupTransition): void {
  const state = value?.next;
  assertNativeGroupState(state);
  if (!exactFields(value, ["schema", "transitionId", "kind", "expectedRevision", "next", "outbox"]) || value?.schema !== "group-foundation.group.native-transition.v1" || typeof value.transitionId !== "string" || !value.transitionId.length || value.transitionId.length > 256 || !["create", "key-package", "add", "remove", "join", "commit", "application-send", "application-receive"].includes(value.kind) || !Array.isArray(value.outbox) || value.outbox.length > 256 || (value.expectedRevision === null ? state.revision !== 0 : !Number.isSafeInteger(value.expectedRevision) || value.expectedRevision < 0 || state.revision !== value.expectedRevision + 1)) throw new GroupError("native-transition", "invalid staged native Group transition");
  const ids = new Set<string>();
  for (const record of value.outbox) {
    if (!exactFields(record, ["id", "kind", "bytes", "digest"]) || typeof record.id !== "string" || !record.id.length || record.id.length > 256 || ids.has(record.id) || !["commit", "welcome", "installation", "application"].includes(record.kind) || typeof record.digest !== "string" || !record.digest.length || record.digest.length > 256 || !(record.bytes instanceof Uint8Array) || !record.bytes.length || record.bytes.length > 1024 * 1024) throw new GroupError("native-transition", "invalid or duplicate native outbox record");
    ids.add(record.id);
  }
}

function exactFields(value: unknown, fields: readonly string[]): boolean {
  return !!value && typeof value === "object" && !Array.isArray(value)
    && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null)
    && Object.keys(value).length === fields.length && fields.every(field => Object.hasOwn(value, field));
}
