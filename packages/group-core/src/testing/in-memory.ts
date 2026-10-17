import { GroupError, assertNativeGroupState, assertStagedNativeGroupTransition, type MemberIdentity, type NativeGroupState, type NativeGroupOutboxRecord, type NativeGroupTransitionStoragePort, type StagedNativeGroupTransition } from "../contracts.js";
import { bytesToBase64url, canonicalJson } from "../encoding.js";

/** Reference CAS implementation for conformance tests; applications supply a durable writer. */
export class InMemoryNativeGroupStorage implements NativeGroupTransitionStoragePort {
  private readonly states = new Map<string, NativeGroupState>();
  private readonly transitions = new Map<string, { fingerprint: string; state: NativeGroupState }>();
  private readonly outbox = new Map<string, NativeGroupOutboxRecord>();

  constructor(initial: readonly NativeGroupState[] = []) {
    for (const state of initial) {
      assertNativeGroupState(state);
      const key = this.key(state.groupId, state.member);
      if (this.states.has(key)) throw new GroupError("conflict", "duplicate initial Group state");
      this.states.set(key, structuredClone(state));
    }
  }
  async read(groupId: string, member: MemberIdentity): Promise<NativeGroupState | undefined> {
    return structuredClone(this.states.get(this.key(groupId, member)));
  }
  readOutbox(): readonly NativeGroupOutboxRecord[] { return structuredClone([...this.outbox.values()]); }

  async commit(transition: StagedNativeGroupTransition): Promise<Readonly<{ state: NativeGroupState; replayed: boolean }>> {
    assertStagedNativeGroupTransition(transition);
    const next = transition.next;
    const fingerprint = canonicalJson({
      schema: transition.schema, transitionId: transition.transitionId, kind: transition.kind, expectedRevision: transition.expectedRevision,
      next: { ...next, member: { ...next.member }, snapshot: bytesToBase64url(next.snapshot) },
      outbox: transition.outbox.map(row => ({ ...row, bytes: bytesToBase64url(row.bytes) })),
    });
    const previous = this.transitions.get(transition.transitionId);
    if (previous) {
      if (previous.fingerprint !== fingerprint) throw new GroupError("conflict", "transition ID reused with changed bytes");
      return { state: structuredClone(previous.state), replayed: true };
    }
    const key = this.key(next.groupId, next.member);
    const current = this.states.get(key);
    if ((current?.revision ?? null) !== transition.expectedRevision || (current && current.profile !== next.profile)) throw new GroupError("conflict", "Group state changed before commit");
    for (const row of transition.outbox) {
      if (this.outbox.has(row.id)) throw new GroupError("conflict", "outbox ID already exists");
    }
    this.states.set(key, structuredClone(next));
    for (const row of transition.outbox) this.outbox.set(row.id, structuredClone(row));
    this.transitions.set(transition.transitionId, { fingerprint, state: structuredClone(next) });
    return { state: structuredClone(next), replayed: false };
  }
  private key(groupId: string, member: MemberIdentity): string {
    return canonicalJson([groupId, member.signingKeyFingerprint]);
  }
}
