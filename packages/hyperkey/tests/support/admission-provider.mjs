import assert from "node:assert/strict";
/** Explicit qualification fixture. Production must adapt group-admission. */
export class AdmissionProviderFixture {
  requests = new Map();
  selected = new Map();
  installed = new Map();
  async submit(request) {
    const previous = this.requests.get(request.admissionId);
    if (previous) assert.deepEqual(previous, request, "admission request retry changed");
    this.requests.set(request.admissionId, structuredClone(request));
  }
  async approveAndSelect({ groupId, copy, admissionId }) {
    const request = this.requests.get(admissionId);
    assert.equal(request.groupId, groupId);
    assert.deepEqual(request.copy, copy);
    if (!this.selected.has(admissionId)) this.selected.set(admissionId, crypto.randomUUID());
    return { selectedCommitId: this.selected.get(admissionId) };
  }
  async acknowledgeInstallation(receipt) {
    const request = this.requests.get(receipt.admissionId);
    assert.equal(receipt.groupId, request.groupId);
    assert.equal(receipt.selectedCommitId, this.selected.get(receipt.admissionId));
    assert.deepEqual(receipt.recipient, request.copy.member);
    assert.ok(receipt.proof.length, "installation proof required by fixture");
    this.installed.set(receipt.admissionId, structuredClone(receipt));
  }
  async canonicalInstallation(admissionId) {
    if (!this.installed.has(admissionId)) return undefined;
    const request = this.requests.get(admissionId);
    return { groupId: request.groupId, profile: request.profile, copy: structuredClone(request.copy), admissionId, selectedCommitId: this.selected.get(admissionId) };
  }
}
