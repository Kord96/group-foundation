import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import {
  ADMISSION_SCHEMA, REMOVAL_SCHEMA, INSTALLATION_SCHEMA, GroupAdmissionRuntime, createAdmissionLedger,
  encodeAdmissionRequest, decodeAdmissionRequest, encodeRemovalRequest, decodeRemovalRequest,
  decodePublicSelection, encodePublicSelection, encodeInstallationReceipt, decodeInstallationReceipt,
  admissionRequestTranscript, recipientInstallationTranscript, actingMemberTranscript,
} from "../dist/index.js";
import { InMemoryAdmissionTransactions, RecordingDelivery } from "../dist/testing/in-memory.js";

const bytes = value => new TextEncoder().encode(value);
const digest = value => createHash("sha256").update(value).digest("base64url");
const actor = { member: { signingKeyFingerprint: "member:owner" }, authentication: bytes("auth") };
const scope = "arbitrary host scope / roomless";
const request = (id = "candidate", changes = {}) => ({ schema: ADMISSION_SCHEMA, requestId: id, scope,
  invitationId: "invitation", member: { signingKeyFingerprint: `member:${id}` }, credential: bytes(`evidence:${id}`),
  keyPackage: bytes(`key-package:${id}`), keyPackageDigest: digest(bytes(`key-package:${id}`)), proof: bytes("candidate proof"),
  requestedAt: 1, expiresAt: 100, ...changes });
const code = expected => error => error.code === expected;
function setup({ compose, prepare, transactionFactory } = {}) {
  const environment = { now: 2, authority: "policy:1", candidate: "identity:1", candidateCalls: 0, prepares: 0, authCalls: [], deny: false, candidateValidUntil: 200, authorityValidUntil: 200 };
  const group = { scope, revision: 0, epoch: "9007199254740992", predecessor: "genesis" };
  const composeCustody = async (current, stage) => {
    assert.equal(current.revision, stage.expected.revision, "physical custody CAS");
    assert.equal(stage.custodyDigest, digest(bytes(JSON.stringify(stage.custody))), "physical custody digest binding");
    if (compose) await compose(environment, current, stage);
    return stage.custody;
  };
  const transactions = transactionFactory
    ? transactionFactory(createAdmissionLedger(group), { revision: 0, secret: "private" }, composeCustody)
    : new InMemoryAdmissionTransactions(createAdmissionLedger(group), { revision: 0, secret: "private" }, composeCustody);
  const delivery = new RecordingDelivery();
  const runtime = new GroupAdmissionRuntime({ transactions, delivery, now: () => environment.now, reservationDuration: 20,
    digest: { async digest(value) { return digest(value); } },
    candidates: { async verify(value) { environment.candidateCalls++; return { member: value.member, revision: environment.candidate, validUntil: environment.candidateValidUntil }; } },
    actors: { async verify(input) { environment.authCalls.push(input); return input.actor.member; } },
    installations: { async verify({ receipt }) { assert.deepEqual(receipt.acknowledgement, bytes("signed acknowledgement")); } },
    governance: { async authorize(input) { if (environment.deny && ["add", "remove"].includes(input.action)) throw new Error("current actor removed"); return { revision: environment.authority, validUntil: environment.authorityValidUntil }; } },
    selection: { async prepare(input) {
      environment.prepares++;
      const custody = { revision: input.group.revision + 1, secret: "advanced private" };
      const stage = { kind: input.kind, operationId: input.operationId, operationHash: input.operationHash, retryId: input.retryId,
        transitionId: `transition:${input.operationId}`, expected: input.group,
        next: { ...input.group, revision: input.group.revision + 1, epoch: String(BigInt(input.group.epoch) + 1n), predecessor: `successor:${input.operationId}` },
        custody, custodyDigest: digest(bytes(JSON.stringify(custody))), commit: bytes(`commit:${input.operationId}`),
        ...(input.kind === "add" ? { welcome: bytes(`welcome:${input.operationId}`), ratchetTree: bytes("tree") } : {}) };
      if (prepare) await prepare(environment, stage);
      return stage;
    } },
  });
  return { runtime, transactions, delivery, environment, group };
}
async function invite(runtime, changes = {}) {
  await runtime.issue({ invitationId: "invitation", scope, expiresAt: 150, maxUses: 1, approval: "automatic", issuedBy: actor.member, ...changes }, actor);
}
async function submit(runtime, id = "candidate", changes) { const value = request(id, changes); await runtime.submit(encodeAdmissionRequest(value)); return value; }
function removal(group, changes = {}) { return { schema: REMOVAL_SCHEMA, operationId: "remove:1", scope, member: { signingKeyFingerprint: "member:departing" }, expected: group, ...changes }; }
function receipt(candidate, selected, changes = {}) { return { schema: INSTALLATION_SCHEMA, operationId: candidate.requestId, scope, selectedWireHash: selected.wireHash,
  successor: selected.selection.next.predecessor, recipient: candidate.member, installedAt: 3, acknowledgement: bytes("signed acknowledgement"), ...changes }; }

class SessionAdmissionTransactions {
  #ledger;
  #session = "bootstrap-pending";
  #writer = Promise.resolve();
  loseNextCommitReply = false;
  constructor(ledger) { this.#ledger = structuredClone(ledger); }
  async read() { return structuredClone(this.#ledger); }
  async readSession() { return this.#session; }
  async transact(operation) {
    const previous = this.#writer; let release;
    this.#writer = new Promise(resolve => { release = resolve; }); await previous;
    try {
      const transaction = { ledger: structuredClone(this.#ledger), session: this.#session,
        async stageCustody() { throw new Error("submission must not stage custody"); } };
      const result = await operation(transaction);
      this.#ledger = structuredClone(transaction.ledger); this.#session = transaction.session;
      if (this.loseNextCommitReply) { this.loseNextCommitReply = false; throw new Error("physical commit reply lost"); }
      return structuredClone(result);
    } finally { release(); }
  }
}

test("canonical neutral request supports absent or opaque delivery binding and rejects predecessor schemas", () => {
  for (const value of [request(), request("bound", { deliveryBinding: bytes("opaque non-key data") })]) {
    const wire = encodeAdmissionRequest(value);
    assert.deepEqual(decodeAdmissionRequest(wire), value);
    assert.throws(() => decodeAdmissionRequest(bytes(` ${new TextDecoder().decode(wire)}`)), code("invalid-wire"));
    const old = bytes(new TextDecoder().decode(wire).replace(ADMISSION_SCHEMA, "zagel.group-admission.v1"));
    assert.throws(() => decodeAdmissionRequest(old), code("invalid-wire"));
  }
  assert.throws(() => encodeAdmissionRequest(request("bad", { schema: "zagel.group-admission.v1" })), code("invalid-wire"));
  const raw = JSON.parse(new TextDecoder().decode(encodeAdmissionRequest(request())));
  raw.extra = true;
  assert.throws(() => decodeAdmissionRequest(bytes(JSON.stringify(raw))), code("invalid-wire"));
});

test("request wire rejects alternate base64, duplicate fields, invalid UTF8, and unknown fields", () => {
  const wire = new TextDecoder().decode(encodeAdmissionRequest(request()));
  for (const invalid of [wire.replace('"proof":"', '"proof":"='), wire.replace('{', '{"schema":"ignored",'), wire.replace('"requestedAt":1', '"requestedAt":1.5'), wire.replace('"expiresAt":100', '"expiresAt":0')]) {
    assert.throws(() => decodeAdmissionRequest(bytes(invalid)));
  }
  assert.throws(() => decodeAdmissionRequest(new Uint8Array([0xff])));
  assert.throws(() => encodeAdmissionRequest(request("large", { credential: new Uint8Array(17000) })));
});

test("caller-composed submission rolls back session handoff and admission together before physical commit", async () => {
  const { runtime, transactions } = setup({ transactionFactory: ledger => new SessionAdmissionTransactions(ledger) });
  await invite(runtime); const before = await transactions.read(), exact = encodeAdmissionRequest(request());
  await assert.rejects(transactions.transact(async transaction => {
    transaction.session = "bootstrap-handed-off";
    await runtime.commitSubmission(transaction, exact);
    throw new Error("crash before physical commit");
  }), /crash before physical commit/u);
  assert.equal(await transactions.readSession(), "bootstrap-pending");
  assert.equal((await transactions.read()).requests.candidate, undefined);
  assert.equal((await transactions.read()).revision, before.revision);
});

test("caller-composed submission survives a lost commit reply and exact retry without revalidating candidate", async () => {
  const { runtime, transactions, environment } = setup({ transactionFactory: ledger => new SessionAdmissionTransactions(ledger) });
  await invite(runtime); const exact = encodeAdmissionRequest(request());
  transactions.loseNextCommitReply = true;
  await assert.rejects(transactions.transact(async transaction => {
    transaction.session = "bootstrap-handed-off";
    return runtime.commitSubmission(transaction, exact);
  }), /physical commit reply lost/u);
  assert.equal(await transactions.readSession(), "bootstrap-handed-off");
  assert.deepEqual((await transactions.read()).requests.candidate.wire, exact);
  assert.equal(environment.candidateCalls, 1);
  const retry = await transactions.transact(transaction => runtime.commitSubmission(transaction, exact));
  assert.equal(retry.state, "approved");
  assert.equal(environment.candidateCalls, 1);
  await assert.rejects(transactions.transact(async transaction => {
    transaction.session = "must-roll-back";
    return runtime.commitSubmission(transaction, encodeAdmissionRequest(request("candidate", { proof: bytes("changed") })));
  }), code("conflict"));
  assert.equal(await transactions.readSession(), "bootstrap-handed-off");
});

test("submit delegates exact wire admission to commitSubmission", async () => {
  const { runtime, transactions } = setup(); await invite(runtime);
  const commitSubmission = runtime.commitSubmission.bind(runtime); let calls = 0;
  runtime.commitSubmission = async (transaction, exactRequest) => { calls++; return commitSubmission(transaction, exactRequest); };
  const exact = encodeAdmissionRequest(request());
  assert.equal((await runtime.submit(exact)).state, "approved");
  assert.equal(calls, 1);
  assert.deepEqual((await transactions.read()).requests.candidate.wire, exact);
});

test("explicit approval, denial, cancellation and scoped immutable invitations", async () => {
  const { runtime } = setup(); await invite(runtime, { approval: "required" });
  await invite(runtime, { approval: "required" });
  await assert.rejects(invite(runtime, { maxUses: 2 }), code("conflict"));
  await assert.rejects(invite(runtime, { scope: "other" }), code("scope"));
  await submit(runtime);
  await assert.rejects(runtime.select("candidate", actor), code("transition"));
  await runtime.approve("candidate", actor); await runtime.select("candidate", actor);
  await submit(runtime, "denied"); await runtime.deny("denied", actor);
  await assert.rejects(runtime.approve("denied", actor), code("transition"));
  await submit(runtime, "cancelled"); await runtime.cancel("cancelled", actor);
  await assert.rejects(runtime.approve("cancelled", actor), code("transition"));
});

test("reservation does not consume; Add atomically installs custody and exact durable public outbox once", async () => {
  const { runtime, transactions, environment } = setup(); await invite(runtime); await submit(runtime);
  const ticket = await runtime.reserveAdd("candidate", actor, "attempt:1");
  assert.equal((await transactions.read()).invitations.invitation.uses, 0);
  assert.equal((await transactions.readCustody()).revision, 0);
  const stage = await runtime.prepare(ticket);
  const selected = await transactions.transact(tx => runtime.commitSelection(tx, ticket, stage));
  const ledger = await transactions.read();
  assert.equal(ledger.invitations.invitation.uses, 1);
  assert.equal(ledger.requests.candidate.state, "selected");
  assert.equal((await transactions.readCustody()).revision, 1);
  assert.deepEqual(decodePublicSelection(selected.wire), selected.selection);
  assert.equal(selected.wireHash, digest(selected.wire));
  assert.equal(new TextDecoder().decode(selected.wire).includes("advanced private"), false);
  assert.deepEqual((await runtime.select("candidate", actor)).wire, selected.wire);
  assert.equal(environment.prepares, 1);
});

test("Remove has no invitation accounting, stages custody, checks expected revision/epoch, and retries once", async () => {
  const { runtime, transactions, environment, group } = setup();
  const operation = removal(group), wire = encodeRemovalRequest(operation);
  assert.deepEqual(decodeRemovalRequest(wire), operation);
  const outbox = await runtime.remove(operation, actor, "remove-attempt");
  assert.equal(outbox.selection.kind, "remove");
  assert.equal(outbox.selection.welcome, undefined);
  assert.equal((await transactions.readCustody()).revision, 1);
  assert.equal(Object.keys((await transactions.read()).invitations).length, 0);
  assert.equal((await runtime.status(operation.operationId)).state, "removed");
  assert.deepEqual((await runtime.remove(operation, actor)).wire, outbox.wire);
  assert.equal(environment.prepares, 1);
  await assert.rejects(runtime.remove(removal(group, { operationId: "other" }), actor), code("stale-stage"));
  await assert.rejects(runtime.remove({ ...operation, member: actor.member }, actor), code("conflict"));
  assert.throws(() => encodeRemovalRequest({ ...operation, schema: "zagel.group-removal.v1" }), code("invalid-wire"));
});

for (const mutation of ["revoke", "invitation-expiry", "request-expiry", "lease-expiry"]) {
  test(`${mutation} during detached Add cannot consume a use or install custody`, async () => {
    const { runtime, transactions, environment } = setup(); await invite(runtime); await submit(runtime);
    const ticket = await runtime.reserveAdd("candidate", actor, "attempt"), stage = await runtime.prepare(ticket);
    if (mutation === "revoke") await runtime.revoke("invitation", actor);
    else environment.now = mutation === "invitation-expiry" ? 150 : mutation === "request-expiry" ? 100 : 22;
    await assert.rejects(transactions.transact(tx => runtime.commitSelection(tx, ticket, stage)));
    const ledger = await transactions.read();
    assert.equal(ledger.invitations.invitation.uses, 0);
    assert.equal(ledger.outbox.candidate, undefined);
    assert.equal((await transactions.readCustody()).revision, 0);
  });
}

test("expiry during physical custody composition rolls all draft effects back", async () => {
  const { runtime, transactions } = setup({ compose(environment) { environment.now = 100; } }); await invite(runtime); await submit(runtime);
  await assert.rejects(runtime.select("candidate", actor));
  assert.equal((await transactions.read()).invitations.invitation.uses, 0);
  assert.equal((await transactions.readCustody()).revision, 0);
});

test("contention on final use reserves exactly one candidate and expired lease is reclaimable", async () => {
  const { runtime, transactions, environment } = setup(); await invite(runtime); await submit(runtime, "one"); await submit(runtime, "two");
  const results = await Promise.allSettled([runtime.reserveAdd("one", actor, "one-attempt"), runtime.reserveAdd("two", actor, "two-attempt")]);
  assert.equal(results.filter(value => value.status === "fulfilled").length, 1);
  assert.equal(results.find(value => value.status === "rejected").reason.code, "capacity");
  assert.equal((await transactions.read()).invitations.invitation.uses, 0);
  environment.now = 22;
  const second = await runtime.reserveAdd("two", actor, "second-attempt");
  const stage = await runtime.prepare(second);
  await transactions.transact(tx => runtime.commitSelection(tx, second, stage));
  assert.equal((await transactions.read()).invitations.invitation.uses, 1);
  await assert.rejects(runtime.select("one", actor), code("capacity"));
});

test("concurrent Add and Remove on same cursor commit only one physical successor", async () => {
  const { runtime, transactions, group } = setup(); await invite(runtime); await submit(runtime);
  const add = await runtime.reserveAdd("candidate", actor, "add"), remove = await runtime.reserveRemove(removal(group), actor, "remove");
  const [addStage, removeStage] = await Promise.all([runtime.prepare(add), runtime.prepare(remove)]);
  await transactions.transact(tx => runtime.commitSelection(tx, remove, removeStage));
  await assert.rejects(transactions.transact(tx => runtime.commitSelection(tx, add, addStage)), code("stale-stage"));
  assert.equal((await transactions.read()).invitations.invitation.uses, 0);
  assert.equal((await transactions.readCustody()).revision, 1);
});

test("changed request bytes or changed retry commit/custody are rejected", async () => {
  const { runtime, transactions } = setup(); await invite(runtime); await submit(runtime);
  await assert.rejects(runtime.submit(encodeAdmissionRequest(request("candidate", { proof: bytes("changed") }))), code("conflict"));
  const ticket = await runtime.reserveAdd("candidate", actor, "attempt"), stage = await runtime.prepare(ticket);
  await transactions.transact(tx => runtime.commitSelection(tx, ticket, stage));
  for (const mutation of [{ commit: bytes("different") }, { custodyDigest: "different-digest" }, { retryId: "other" }]) {
    await assert.rejects(transactions.transact(tx => runtime.commitSelection(tx, ticket, { ...stage, ...mutation })));
  }
  assert.equal((await transactions.read()).invitations.invitation.uses, 1);
});

for (const action of ["add", "remove"]) {
  for (const change of ["authority", "candidate", "denied", "revision", "epoch"]) {
    if (action === "remove" && change === "candidate") continue;
    test(`${action} rejects stale ${change} after staging`, async () => {
      const { runtime, transactions, environment, group } = setup();
      let ticket;
      if (action === "add") { await invite(runtime); await submit(runtime); ticket = await runtime.reserveAdd("candidate", actor, "attempt"); }
      else ticket = await runtime.reserveRemove(removal(group), actor, "attempt");
      const stage = await runtime.prepare(ticket);
      if (change === "authority") environment.authority = "policy:2";
      if (change === "candidate") environment.candidate = "identity:2";
      if (change === "denied") environment.deny = true;
      if (change === "revision" || change === "epoch") await transactions.transact(async ({ ledger }) => { ledger.group[change] = change === "revision" ? 1 : "9007199254740993"; });
      await assert.rejects(transactions.transact(tx => runtime.commitSelection(tx, ticket, stage)));
      assert.equal((await transactions.readCustody()).revision, 0);
      assert.equal(Object.keys((await transactions.read()).outbox).length, 0);
    });
  }
}

test("governance is rechecked after host custody composition, immediately before selection", async () => {
  const { runtime, transactions } = setup({ compose(environment) { environment.authority = "changed inside composer"; } });
  await invite(runtime); await submit(runtime);
  await assert.rejects(runtime.select("candidate", actor), code("stale-authority"));
  assert.equal((await transactions.readCustody()).revision, 0);
});

test("lost physical commit replies for Add and Remove reopen exact custody/public receipts", async () => {
  for (const kind of ["add", "remove"]) {
    const { runtime, transactions, environment, group } = setup();
    if (kind === "add") { await invite(runtime); await submit(runtime); }
    transactions.loseNextCommitReply = true;
    const selected = kind === "add" ? await runtime.select("candidate", actor) : await runtime.remove(removal(group), actor);
    assert.equal(environment.prepares, 1);
    assert.equal((await transactions.readCustody()).revision, 1);
    assert.equal((await transactions.read()).transitions[selected.selection.transitionId], selected.stageHash);
  }
});

test("selected Add recovery survives request expiry and invitation revocation", async () => {
  const { runtime, delivery, transactions, environment } = setup(); await invite(runtime); const candidate = await submit(runtime);
  const selected = await runtime.select(candidate.requestId, actor);
  delivery.fail = true; await assert.rejects(runtime.publish(candidate.requestId));
  await runtime.revoke("invitation", actor); environment.now = 1000;
  assert.equal((await runtime.submit(encodeAdmissionRequest(candidate))).state, "selected");
  assert.deepEqual((await runtime.select(candidate.requestId, actor)).wire, selected.wire);
  delivery.fail = false; await runtime.recover();
  assert.deepEqual(delivery.records[0].wire, selected.wire);
  assert.equal((await transactions.read()).invitations.invitation.uses, 1);
  assert.equal(environment.prepares, 1);
});

test("installation authenticates exact Add/member, is independent of publishing, and exposes durable lookup", async () => {
  const { runtime, transactions, environment } = setup(); await invite(runtime); const candidate = await submit(runtime);
  const selected = await runtime.select(candidate.requestId, actor); environment.now = 4;
  assert.equal(await runtime.installed(candidate.requestId), undefined);
  for (const change of [{ selectedWireHash: "different" }, { successor: "different" }, { recipient: actor.member }, { scope: "different" }, { installedAt: 5 }, { acknowledgement: bytes("forged") }]) {
    await assert.rejects(runtime.acknowledgeInstallation(receipt(candidate, selected, change)));
  }
  const signed = receipt(candidate, selected);
  assert.deepEqual(decodeInstallationReceipt(encodeInstallationReceipt(signed)), signed);
  assert.equal((await runtime.acknowledgeInstallation(signed)).installed, true);
  assert.equal((await runtime.acknowledgeInstallation(signed)).installed, true);
  const installed = await runtime.installed(candidate.requestId);
  assert.deepEqual(installed.request, candidate); assert.deepEqual(installed.receipt, signed);
  await assert.rejects(runtime.acknowledgeInstallation({ ...signed, installedAt: 2 }), code("conflict"));
  assert.equal((await transactions.read()).outbox.candidate.publication, "pending");
});

test("all detached effects roll back when physical composer rejects custody", async () => {
  const { runtime, transactions } = setup({ compose() { throw new Error("custody CAS mismatch"); } });
  await invite(runtime); await submit(runtime); await assert.rejects(runtime.select("candidate", actor), /CAS/u);
  assert.equal((await transactions.read()).invitations.invitation.uses, 0);
  assert.equal((await transactions.readCustody()).revision, 0);
});

test("opaque identifiers are safe even when equal to object prototype properties", async () => {
  const { runtime, transactions } = setup(); await invite(runtime); await submit(runtime, "__proto__");
  await runtime.select("__proto__", actor);
  assert.equal((await transactions.read()).requests.__proto__.state, "selected");
  assert.equal((await runtime.status("__proto__")).state, "selected");
});

for (const malformed of ["scope", "revision", "epoch", "welcome", "custody"]) {
  test(`detached Add rejects malformed ${malformed} without accounting effects`, async () => {
    const { runtime, transactions } = setup({ prepare(_environment, stage) {
      if (malformed === "scope") stage.next.scope = "different";
      if (malformed === "revision") stage.next.revision++;
      if (malformed === "epoch") stage.next.epoch = stage.expected.epoch;
      if (malformed === "welcome") delete stage.welcome;
      if (malformed === "custody") delete stage.custody;
    } });
    await invite(runtime); await submit(runtime); await assert.rejects(runtime.select("candidate", actor));
    assert.equal((await transactions.read()).invitations.invitation.uses, 0);
    assert.equal((await transactions.readCustody()).revision, 0);
  });
}

test("lost reply recovery rejects altered public wire even when transition IDs match", async () => {
  const { runtime, transactions } = setup(); await invite(runtime); await submit(runtime);
  transactions.loseNextCommitReply = true;
  const read = transactions.read.bind(transactions);
  transactions.read = async () => {
    const ledger = await read();
    if (ledger.outbox.candidate) ledger.outbox.candidate.wire = bytes("substituted durable public wire");
    return ledger;
  };
  await assert.rejects(runtime.select("candidate", actor), code("conflict"));
});
