import { OUTBOX_SCHEMA, type GroupCursor, type InvitationDefinition, type AdmissionRequest, type RemovalRequest, type ActingMember, type Authority, type CandidateEvidencePort, type GovernancePort, type ActorAuthenticationPort, type SelectionPort, type StagedSelection, type PublicSelection, type AdmissionOutboxRecord, type InstallationReceipt, type InstallationAuthenticationPort, type DeliveryPort, type DigestPort, type AdmissionAction, type RequestState, LIMITS } from "./contracts.js";
import { identifier, instant, fail, sameBytes, sameCursor, validateCursor, validateInvitation, validateMember, byteField, encodeJson, invitationJson, encodeAdmissionRequest, decodeAdmissionRequest, encodeRemovalRequest, decodeRemovalRequest, encodePublicSelection, encodeInstallationReceipt, decodeInstallationReceipt, bytesToBase64url } from "./wire.js";

export interface StoredInvitation { definition: InvitationDefinition; uses: number; revokedAt?: number; }
export interface StoredRequest { wire: Uint8Array; hash: string; state: RequestState; reservation?: Reservation; }
export interface StoredOutbox extends AdmissionOutboxRecord { publication: "pending" | "acknowledged"; }
export interface AdmissionLedger {
  revision: number; group: GroupCursor;
  invitations: Record<string, StoredInvitation>; requests: Record<string, StoredRequest>;
  removals: Record<string, { wire: Uint8Array; hash: string }>;
  outbox: Record<string, StoredOutbox>; installations: Record<string, Uint8Array>;
  /** Durable immutable transition ID -> stage hash; custody itself remains host-owned. */
  transitions: Record<string, string>;
}
export interface Reservation { retryId: string; until: number; }
/** The host owns the writer. It must roll back ALL effects if callback or commit fails. */
export interface AdmissionTransaction<Custody> {
  readonly ledger: AdmissionLedger;
  /** Validate exact opaque custody/digest/core outbox, CAS revision and compose its writes in this SAME transaction. */
  stageCustody(selection: StagedSelection<Custody>): Promise<void>;
}
export interface TransactionCompositionPort<Custody> {
  transact<T>(operation: (transaction: AdmissionTransaction<Custody>) => Promise<T>): Promise<T>;
  /** Linearizable read of durable state, including after a lost transaction reply. */
  read(): Promise<AdmissionLedger>;
}
export interface AdmissionProgress { operationId: string; state: RequestState | "removed"; publication?: "pending" | "acknowledged"; installed: boolean; }
export interface SelectionTicket {
  readonly input: import("./contracts.js").SelectionInput;
  readonly actor: ActingMember; readonly authority: Authority; readonly candidate?: Authority;
  readonly reservationUntil?: number;
}
export interface RuntimeOptions<Custody> {
  readonly transactions: TransactionCompositionPort<Custody>;
  readonly candidates: CandidateEvidencePort; readonly governance: GovernancePort;
  readonly actors: ActorAuthenticationPort; readonly installations: InstallationAuthenticationPort;
  readonly selection: SelectionPort<Custody>; readonly delivery: DeliveryPort; readonly digest: DigestPort;
  readonly now: () => number; readonly reservationDuration: number;
}
export interface InstalledAdmission {
  readonly request: AdmissionRequest; readonly selected: AdmissionOutboxRecord; readonly receipt: InstallationReceipt;
}
export function createAdmissionLedger(group: GroupCursor): AdmissionLedger {
  return { revision: 0, group: validateCursor(group), invitations: Object.create(null), requests: Object.create(null), removals: Object.create(null), outbox: Object.create(null), installations: Object.create(null), transitions: Object.create(null) };
}
/** Pure cursor/public-output validation; no persistence and no native MLS implementation. */
export function validateStagedSelection<C>(stage: StagedSelection<C>, ticket: SelectionTicket): void {
  const input = ticket.input;
  validateCursor(stage.expected); validateCursor(stage.next); identifier(stage.transitionId); identifier(stage.custodyDigest);
  if (stage.kind !== input.kind || stage.operationId !== input.operationId || stage.operationHash !== input.operationHash || stage.retryId !== input.retryId || !sameCursor(stage.expected, input.group) || stage.next.scope !== input.group.scope || stage.next.revision !== input.group.revision + 1 || BigInt(stage.next.epoch) !== BigInt(input.group.epoch) + 1n || stage.next.predecessor === input.group.predecessor || stage.custody === undefined || stage.custody === null) fail("stale-stage", "stage differs from operation or expected revision/epoch");
  byteField(stage.commit, LIMITS.outboxBytes);
  if (stage.kind === "add") { byteField(stage.welcome, LIMITS.outboxBytes); if (stage.ratchetTree !== undefined) byteField(stage.ratchetTree, LIMITS.outboxBytes); }
  else if (stage.welcome !== undefined || stage.ratchetTree !== undefined) fail("selection", "Remove cannot carry recipient installation material");
}

/** Coordination over host transactions; every returned public selection is already durable. */
export class GroupAdmissionRuntime<Custody> {
  constructor(private readonly options: RuntimeOptions<Custody>) { if (instant(options.reservationDuration) < 1) fail("clock", "reservationDuration must be positive"); }
  async issue(definition: InvitationDefinition, actor: ActingMember): Promise<void> {
    validateInvitation(definition); const immutable = structuredClone(definition), payload = encodeJson(invitationJson(immutable));
    await this.write(async ({ ledger }) => {
      this.scope(ledger, immutable.scope); await this.authorize("issue", immutable.invitationId, ledger.group, actor, payload);
      if (actor.member.signingKeyFingerprint !== immutable.issuedBy.signingKeyFingerprint) fail("actor", "issuer differs from actor");
      const existing = own(ledger.invitations, immutable.invitationId);
      if (existing) { if (!sameBytes(encodeJson(invitationJson(existing.definition)), payload)) fail("conflict", "invitation ID changed"); return; }
      if (immutable.expiresAt <= this.now()) fail("expired", "invitation expired");
      put(ledger.invitations, immutable.invitationId, { definition: immutable, uses: 0 });
    });
  }
  async revoke(invitationId: string, actor: ActingMember): Promise<void> {
    identifier(invitationId);
    await this.write(async ({ ledger }) => {
      const invitation = required(ledger.invitations, invitationId, "invitation");
      await this.authorize("revoke", invitationId, ledger.group, actor, encodeJson(invitationJson(invitation.definition)));
      invitation.revokedAt ??= this.now();
      for (const request of Object.values(ledger.requests)) if (request.state === "reserved" && decodeAdmissionRequest(request.wire).invitationId === invitationId) { request.state = "approved"; delete request.reservation; }
    });
  }
  async submit(wire: Uint8Array): Promise<AdmissionProgress> {
    const exact = new Uint8Array(wire);
    return this.options.transactions.transact(transaction => this.commitSubmission(transaction, exact));
  }
  /**
   * Validate and compose exact canonical request bytes in the caller's existing physical transaction.
   * This method never opens or commits a transaction; the caller owns atomic commit and rollback.
   */
  async commitSubmission(transaction: AdmissionTransaction<Custody>, exactRequest: Uint8Array): Promise<AdmissionProgress> {
    const { ledger } = transaction; validateCursor(ledger.group);
    const exact = new Uint8Array(exactRequest), request = decodeAdmissionRequest(exact), hash = await this.digest(exact);
    this.scope(ledger, request.scope);
    const prior = own(ledger.requests, request.requestId);
    // Durable selected retries survive expiry/revocation; changed bytes always fail first.
    if (prior) assertExact(prior, exact, hash);
    else {
      if (own(ledger.removals, request.requestId)) fail("conflict", "operation ID already names a removal");
      const now = this.now(), invitation = currentInvitation(ledger, request.invitationId, now);
      if (request.requestedAt > now || request.expiresAt <= now) fail("expired", "candidate request is outside validity interval");
      const verified = await this.options.candidates.verify(structuredClone(request), this.now()); this.checkCandidate(request, verified);
      if (request.expiresAt <= this.now() || invitation.definition.expiresAt <= this.now() || invitation.revokedAt !== undefined) fail("expired", "admission expired during validation");
      put(ledger.requests, request.requestId, { wire: exact, hash, state: invitation.definition.approval === "automatic" ? "approved" : "pending" });
    }
    const result = progress(ledger, request.requestId); ledger.revision++;
    return result;
  }
  async approve(requestId: string, actor: ActingMember): Promise<AdmissionProgress> { return this.decide(requestId, actor, "approve"); }
  async deny(requestId: string, actor: ActingMember): Promise<AdmissionProgress> { return this.decide(requestId, actor, "deny"); }
  async cancel(requestId: string, actor: ActingMember): Promise<AdmissionProgress> { return this.decide(requestId, actor, "cancel"); }
  private async decide(requestId: string, actor: ActingMember, action: "approve" | "deny" | "cancel"): Promise<AdmissionProgress> {
    return this.write(async ({ ledger }) => {
      const stored = required(ledger.requests, requestId, "request"), request = decodeAdmissionRequest(stored.wire);
      await this.authorize(action, requestId, ledger.group, actor, stored.wire);
      if (stored.state === "selected") return progress(ledger, requestId);
      if (stored.state === "cancelled" || (stored.state === "denied" && action !== "deny")) fail("transition", "request decision is final");
      if (action === "approve") { currentInvitation(ledger, request.invitationId, this.now()); if (request.expiresAt <= this.now()) fail("expired", "candidate expired"); }
      stored.state = action === "approve" ? "approved" : action === "deny" ? "denied" : "cancelled"; delete stored.reservation;
      return progress(ledger, requestId);
    });
  }
  /** Reserve without consuming capacity. Caller can stage and commit through its own physical writer. */
  async reserveAdd(requestId: string, actor: ActingMember, retryId: string): Promise<SelectionTicket | AdmissionOutboxRecord> {
    identifier(retryId); const acting = structuredClone(actor);
    return this.write(async ({ ledger }) => {
      expireReservations(ledger, this.now()); const stored = required(ledger.requests, requestId, "request"), request = decodeAdmissionRequest(stored.wire);
      const existing = own(ledger.outbox, requestId); if (existing) return publicOutbox(existing);
      if (!["approved", "reserved"].includes(stored.state)) fail("transition", "candidate is not approved");
      const invitation = currentInvitation(ledger, request.invitationId, this.now());
      if (request.expiresAt <= this.now()) fail("expired", "candidate expired");
      if (stored.reservation && stored.reservation.retryId !== retryId) fail("reservation-held", "another retry holds the reservation");
      const held = Object.values(ledger.requests).filter(row => row !== stored && row.state === "reserved" && row.reservation && row.reservation.until > this.now() && decodeAdmissionRequest(row.wire).invitationId === request.invitationId).length;
      if (invitation.uses + held >= invitation.definition.maxUses) fail("capacity", "invitation capacity is consumed or reserved");
      const candidate = await this.options.candidates.verify(structuredClone(request), this.now()); this.checkCandidate(request, candidate);
      const authority = await this.authorize("add", requestId, ledger.group, acting, stored.wire);
      const until = Math.min(this.now() + this.options.reservationDuration, request.expiresAt, invitation.definition.expiresAt, candidate.validUntil, authority.validUntil);
      if (!Number.isSafeInteger(until) || until <= this.now()) fail("expired", "reservation has no remaining validity");
      stored.state = "reserved"; stored.reservation = { retryId, until };
      return { input: { kind: "add", operationId: requestId, operationHash: stored.hash, retryId, group: structuredClone(ledger.group), request, now: this.now() }, actor: acting, authority, candidate, reservationUntil: until };
    });
  }
  async reserveRemove(removal: RemovalRequest, actor: ActingMember, retryId: string): Promise<SelectionTicket | AdmissionOutboxRecord> {
    identifier(retryId); const wire = encodeRemovalRequest(removal), checked = decodeRemovalRequest(wire), hash = await this.digest(wire), acting = structuredClone(actor);
    return this.write(async ({ ledger }) => {
      this.scope(ledger, checked.scope);
      const prior = own(ledger.removals, checked.operationId); if (prior) assertExact(prior, wire, hash);
      if (own(ledger.requests, checked.operationId)) fail("conflict", "operation ID already names an Add");
      const selected = own(ledger.outbox, checked.operationId); if (selected) return publicOutbox(selected);
      if (!sameCursor(ledger.group, checked.expected)) fail("stale-stage", "removal targets a stale revision or epoch");
      const authority = await this.authorize("remove", checked.operationId, ledger.group, acting, wire);
      put(ledger.removals, checked.operationId, { wire, hash });
      return { input: { kind: "remove", operationId: checked.operationId, operationHash: hash, retryId, group: structuredClone(ledger.group), removal: checked, now: this.now() }, actor: acting, authority };
    });
  }
  async prepare(ticket: SelectionTicket): Promise<StagedSelection<Custody>> {
    const stage = await this.options.selection.prepare(structuredClone(ticket.input)); validateStagedSelection(stage, ticket); return stage;
  }
  /** Compose selection with caller state/custody/outbox in an existing physical transaction. */
  async commitSelection(transaction: AdmissionTransaction<Custody>, ticket: SelectionTicket, stage: StagedSelection<Custody>): Promise<AdmissionOutboxRecord> {
    validateStagedSelection(stage, ticket); const { ledger } = transaction, input = ticket.input;
    const stageHash = await this.stageHash(stage), existing = own(ledger.outbox, input.operationId);
    if (existing) { if (existing.stageHash !== stageHash || existing.selection.operationHash !== input.operationHash || !sameBytes(existing.wire, encodePublicSelection(publicSelection(stage, ticket)))) fail("conflict", "retry changed selected bytes or custody"); return publicOutbox(existing); }
    if (!sameCursor(ledger.group, stage.expected)) fail("stale-stage", "group revision/epoch advanced during staging");
    if (own(ledger.transitions, stage.transitionId)) fail("conflict", "transition ID already selected");
    const payload = input.kind === "add" ? required(ledger.requests, input.operationId, "request").wire : required(ledger.removals, input.operationId, "removal").wire;
    if ((input.kind === "add" && (!input.request || !sameBytes(encodeAdmissionRequest(input.request), payload))) || (input.kind === "remove" && (!input.removal || !sameBytes(encodeRemovalRequest(input.removal), payload)))) fail("conflict", "ticket payload changed");
    if (await this.digest(payload) !== input.operationHash) fail("conflict", "stored operation changed");
    const selection = publicSelection(stage, ticket);
    const wire = encodePublicSelection(selection), wireHash = await this.digest(wire);
    // Compose detached custody first; final identity and governance checks follow in this same writer.
    await transaction.stageCustody(structuredClone(stage));
    let candidate: Authority | undefined, invitation: StoredInvitation | undefined, stored: StoredRequest | undefined;
    if (input.kind === "add") {
      stored = required(ledger.requests, input.operationId, "request"); const request = decodeAdmissionRequest(payload);
      if (stored.state !== "reserved" || !stored.reservation || stored.reservation.retryId !== input.retryId || stored.reservation.until <= this.now()) fail("reservation-lost", "Add reservation no longer held");
      invitation = currentInvitation(ledger, request.invitationId, this.now());
      if (request.expiresAt <= this.now()) fail("expired", "candidate expired");
      const verified = await this.options.candidates.verify(structuredClone(request), this.now()); this.checkCandidate(request, verified); candidate = verified;
      if (!ticket.candidate || verified.revision !== ticket.candidate.revision) fail("stale-authority", "candidate authority changed during staging");
    } else {
      const removal = decodeRemovalRequest(payload); if (!sameCursor(removal.expected, ledger.group)) fail("stale-stage", "removal expected cursor changed");
    }
    const authority = await this.authorize(input.kind, input.operationId, ledger.group, ticket.actor, payload);
    if (authority.revision !== ticket.authority.revision) fail("stale-authority", "governance authority changed during staging");
    this.checkAuthority(authority); if (candidate) this.checkAuthority(candidate);
    if (stored && invitation) {
      const request = decodeAdmissionRequest(stored.wire);
      if (!stored.reservation || stored.reservation.until <= this.now() || request.expiresAt <= this.now()) fail("reservation-lost", "reservation expired before physical commit");
      currentInvitation(ledger, request.invitationId, this.now());
      if (invitation.uses >= invitation.definition.maxUses) fail("capacity", "final allowed use was consumed");
      invitation.uses++; stored.state = "selected"; delete stored.reservation;
    }
    ledger.group = structuredClone(stage.next); put(ledger.transitions, stage.transitionId, stageHash);
    put(ledger.outbox, input.operationId, { selection, wire, wireHash, stageHash, publication: "pending" });
    return publicOutbox(ledger.outbox[input.operationId]!);
  }
  async select(requestId: string, actor: ActingMember, retryId = requestId): Promise<AdmissionOutboxRecord> {
    return this.finish(await this.reserveAdd(requestId, actor, retryId));
  }
  async remove(request: RemovalRequest, actor: ActingMember, retryId = request.operationId): Promise<AdmissionOutboxRecord> {
    return this.finish(await this.reserveRemove(request, actor, retryId));
  }
  private async finish(value: SelectionTicket | AdmissionOutboxRecord): Promise<AdmissionOutboxRecord> {
    if ("wire" in value) return value;
    const stage = await this.prepare(value), expectedHash = await this.stageHash(stage);
    try { return await this.write(transaction => this.commitSelection(transaction, value, stage)); }
    catch (error) {
      // Commit may have succeeded despite an ambiguous reply: require BOTH public and custody receipts.
      const ledger = await this.options.transactions.read(), record = own(ledger.outbox, value.input.operationId);
      if (record) {
        if (record.stageHash !== expectedHash || own(ledger.transitions, stage.transitionId) !== expectedHash || !sameBytes(record.wire, encodePublicSelection(publicSelection(stage, value))) || record.wireHash !== await this.digest(record.wire)) fail("conflict", "ambiguous reply recovered a different transition");
        return publicOutbox(record);
      }
      throw error;
    }
  }
  async publish(operationId: string): Promise<AdmissionProgress> {
    const ledger = await this.options.transactions.read(), record = required(ledger.outbox, operationId, "selection");
    if (record.publication === "pending") {
      await this.options.delivery.publish(publicOutbox(record));
      await this.write(async ({ ledger: draft }) => { const current = required(draft.outbox, operationId, "selection"); if (current.wireHash !== record.wireHash || !sameBytes(current.wire, record.wire)) fail("conflict", "durable outbox changed"); current.publication = "acknowledged"; });
    }
    return this.status(operationId);
  }
  async recover(): Promise<readonly AdmissionProgress[]> {
    const ledger = await this.options.transactions.read(), result: AdmissionProgress[] = [];
    for (const id of Object.keys(ledger.outbox).sort()) result.push(await this.publish(id));
    return result;
  }
  async acknowledgeInstallation(receipt: InstallationReceipt): Promise<AdmissionProgress> {
    const wire = encodeInstallationReceipt(receipt), checked = decodeInstallationReceipt(wire);
    return this.write(async ({ ledger }) => {
      const prior = own(ledger.installations, checked.operationId);
      if (prior) { if (!sameBytes(prior, wire)) fail("conflict", "installation receipt changed"); return progress(ledger, checked.operationId); }
      const record = required(ledger.outbox, checked.operationId, "selection"), stored = required(ledger.requests, checked.operationId, "request"), request = decodeAdmissionRequest(stored.wire);
      if (record.selection.kind !== "add" || stored.state !== "selected" || checked.scope !== request.scope || checked.scope !== record.selection.next.scope || checked.selectedWireHash !== record.wireHash || checked.successor !== record.selection.next.predecessor || checked.recipient.signingKeyFingerprint !== request.member.signingKeyFingerprint || checked.installedAt > this.now()) fail("installation", "receipt differs from selected Add");
      await this.options.installations.verify({ receipt: structuredClone(checked), request, selected: publicOutbox(record), now: this.now() });
      const authority = await this.options.governance.authorize({ action: "accept", group: structuredClone(ledger.group), actor: checked.recipient, payload: wire, now: this.now() }); this.checkAuthority(authority);
      put(ledger.installations, checked.operationId, wire); return progress(ledger, checked.operationId);
    });
  }
  async installed(operationId: string): Promise<InstalledAdmission | undefined> {
    const ledger = await this.options.transactions.read(), wire = own(ledger.installations, operationId); if (!wire) return undefined;
    return { request: decodeAdmissionRequest(required(ledger.requests, operationId, "request").wire), selected: publicOutbox(required(ledger.outbox, operationId, "selection")), receipt: decodeInstallationReceipt(wire) };
  }
  async status(operationId: string): Promise<AdmissionProgress> { return progress(await this.options.transactions.read(), operationId); }
  private async authorize(action: AdmissionAction, targetId: string, group: GroupCursor, acting: ActingMember, payload: Uint8Array): Promise<Authority> {
    validateMember(acting.member); byteField(acting.authentication, LIMITS.proofBytes);
    const member = await this.options.actors.verify({ action, targetId, group: structuredClone(group), actor: structuredClone(acting), payload: new Uint8Array(payload), now: this.now() });
    if (member.signingKeyFingerprint !== acting.member.signingKeyFingerprint) fail("actor", "authentication changed acting identity");
    const authority = await this.options.governance.authorize({ action, group: structuredClone(group), actor: validateMember(member), payload: new Uint8Array(payload), now: this.now() }); this.checkAuthority(authority); return structuredClone(authority);
  }
  private checkCandidate(request: AdmissionRequest, verified: import("./contracts.js").VerifiedCandidate): void { if (verified.member.signingKeyFingerprint !== request.member.signingKeyFingerprint) fail("identity", "candidate verification changed member"); this.checkAuthority(verified); }
  private checkAuthority(value: Authority): void { identifier(value.revision); if (instant(value.validUntil) <= this.now()) fail("expired", "authority expired"); }
  private now(): number { return instant(this.options.now()); }
  private scope(ledger: AdmissionLedger, scope: string): void { if (ledger.group.scope !== scope) fail("scope", "scope differs from current group"); }
  private async digest(bytes: Uint8Array): Promise<string> { return identifier(await this.options.digest.digest(new Uint8Array(bytes)), "digest"); }
  private async stageHash(stage: StagedSelection<Custody>): Promise<string> {
    return this.digest(encodeJson({ kind: stage.kind, operationId: stage.operationId, operationHash: stage.operationHash, retryId: stage.retryId, transitionId: stage.transitionId, custodyDigest: stage.custodyDigest, expected: { ...stage.expected }, next: { ...stage.next }, commit: bytesToBase64url(stage.commit), ...(stage.welcome === undefined ? {} : { welcome: bytesToBase64url(stage.welcome) }), ...(stage.ratchetTree === undefined ? {} : { ratchetTree: bytesToBase64url(stage.ratchetTree) }) }, LIMITS.outboxBytes));
  }
  private async write<T>(operation: (transaction: AdmissionTransaction<Custody>) => Promise<T>): Promise<T> {
    return this.options.transactions.transact(async tx => { validateCursor(tx.ledger.group); const result = await operation(tx); tx.ledger.revision++; return result; });
  }
}
function publicSelection<C>(stage: StagedSelection<C>, ticket: SelectionTicket): PublicSelection {
  return { schema: OUTBOX_SCHEMA, kind: stage.kind, operationId: stage.operationId, operationHash: stage.operationHash, retryId: stage.retryId, transitionId: stage.transitionId, custodyDigest: stage.custodyDigest, expected: structuredClone(stage.expected), next: structuredClone(stage.next), authorityRevision: ticket.authority.revision,
      ...(ticket.candidate ? { candidateRevision: ticket.candidate.revision } : {}), commit: new Uint8Array(stage.commit), ...(stage.welcome === undefined ? {} : { welcome: new Uint8Array(stage.welcome) }), ...(stage.ratchetTree === undefined ? {} : { ratchetTree: new Uint8Array(stage.ratchetTree) }) };
}
function put<T>(table: Record<string, T>, key: string, value: T): void { Object.defineProperty(table, key, { value, enumerable: true, writable: true, configurable: true }); }
function own<T>(table: Record<string, T>, key: string): T | undefined { return Object.hasOwn(table, key) ? table[key] : undefined; }
function required<T>(table: Record<string, T>, key: string, name: string): T { const value = own(table, key); if (!value) fail(`unknown-${name}`, `${name} not found`); return value; }
function assertExact(row: { wire: Uint8Array; hash: string }, wire: Uint8Array, hash: string): void { if (row.hash !== hash || !sameBytes(row.wire, wire)) fail("conflict", "operation ID has changed canonical bytes"); }
function currentInvitation(ledger: AdmissionLedger, id: string, now: number): StoredInvitation { const value = required(ledger.invitations, id, "invitation"); if (value.revokedAt !== undefined) fail("revoked", "invitation revoked"); if (value.definition.expiresAt <= now) fail("expired", "invitation expired"); return value; }
function expireReservations(ledger: AdmissionLedger, now: number): void { for (const row of Object.values(ledger.requests)) if (row.state === "reserved" && (!row.reservation || row.reservation.until <= now)) { row.state = "approved"; delete row.reservation; } }
function progress(ledger: AdmissionLedger, id: string): AdmissionProgress {
  const selected = own(ledger.outbox, id), request = own(ledger.requests, id);
  if (!request && !selected) fail("unknown-operation", "operation not found");
  return { operationId: id, state: selected?.selection.kind === "remove" ? "removed" : request!.state, ...(selected ? { publication: selected.publication } : {}), installed: !!own(ledger.installations, id) };
}
function publicOutbox(value: AdmissionOutboxRecord): AdmissionOutboxRecord { return structuredClone({ selection: value.selection, wire: value.wire, wireHash: value.wireHash, stageHash: value.stageHash }); }
