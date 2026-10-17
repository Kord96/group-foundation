import { ADMISSION_SCHEMA, INSTALLATION_SCHEMA, encodeAdmissionRequest, type GroupAdmissionRuntime, type TransactionCompositionPort, type AdmissionRequest, type Scope } from "@group-foundation/group-admission";
import { canonicalBytes, equalBytes } from "./encoding.js";
import { HYPERKEY_GROUP_PROFILE, HyperKeyGroupCompositionError, type CopyIdentity, type CanonicalCopyInstallation } from "./group-ports.js";
import type { AuthenticatedCopyAdmissionRequest, HyperKeyAdmissionProvider, HyperKeyActingMember, HyperKeyRecipientInstallation } from "./admission.js";

/** Consumer scope must bind both the Group ID and pinned HyperKey profile. */
export interface GroupAdmissionHyperKeyProviderOptions<Custody> {
  readonly runtime: GroupAdmissionRuntime<Custody>;
  readonly transactions: Pick<TransactionCompositionPort<Custody>, "read">;
  readonly scopeFor: (groupId: string, profile: typeof HYPERKEY_GROUP_PROFILE) => Scope;
}

/** Concrete bridge to the generic admission runtime; it owns no admission ledger. */
export class GroupAdmissionHyperKeyProvider<Custody> implements HyperKeyAdmissionProvider {
  constructor(private readonly options: GroupAdmissionHyperKeyProviderOptions<Custody>) {}

  async submit(request: AuthenticatedCopyAdmissionRequest & Readonly<{ profile: typeof HYPERKEY_GROUP_PROFILE }>, signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    if (request.profile !== HYPERKEY_GROUP_PROFILE) throw new HyperKeyGroupCompositionError("Invalid Copy admission profile");
    await this.options.runtime.submit(encodeAdmissionRequest({
      schema: ADMISSION_SCHEMA, requestId: request.admissionId, invitationId: request.invitationId,
      scope: this.options.scopeFor(request.groupId, HYPERKEY_GROUP_PROFILE), member: request.copy.member,
      credential: new Uint8Array(request.evidence), keyPackage: new Uint8Array(request.keyPackage), keyPackageDigest: request.copy.keyPackageDigest,
      deliveryBinding: hyperKeyAdmissionBinding(request.groupId, request.copy), proof: new Uint8Array(request.proof), requestedAt: request.requestedAtMs, expiresAt: request.expiresAtMs,
    }));
  }

  async approveAndSelect(input: Readonly<{ groupId: Scope; copy: CopyIdentity; admissionId: string; actors: Readonly<{ approval: HyperKeyActingMember; selection: HyperKeyActingMember }> }>, signal?: AbortSignal): Promise<Readonly<{ selectedCommitId: string }>> {
    signal?.throwIfAborted();
    await this.options.runtime.approve(input.admissionId, input.actors.approval);
    const selected = await this.options.runtime.select(input.admissionId, input.actors.selection);
    if (selected.selection.next.scope !== this.options.scopeFor(input.groupId, HYPERKEY_GROUP_PROFILE)) throw new HyperKeyGroupCompositionError("Selected admission has another scope");
    return Object.freeze({ selectedCommitId: selected.selection.next.predecessor });
  }

  async acknowledgeInstallation(input: HyperKeyRecipientInstallation, signal?: AbortSignal): Promise<void> {
    signal?.throwIfAborted();
    const ledger = await this.options.transactions.read();
    const selected = Object.hasOwn(ledger.outbox, input.admissionId) ? ledger.outbox[input.admissionId] : undefined;
    if (!selected || selected.selection.next.scope !== this.options.scopeFor(input.groupId, HYPERKEY_GROUP_PROFILE) || selected.selection.next.predecessor !== input.selectedCommitId) throw new HyperKeyGroupCompositionError("Installation differs from selected Add");
    await this.options.runtime.acknowledgeInstallation({ schema: INSTALLATION_SCHEMA, operationId: input.admissionId, scope: selected.selection.next.scope, selectedWireHash: selected.wireHash, successor: input.selectedCommitId, recipient: input.recipient, installedAt: input.installedAtMs, acknowledgement: new Uint8Array(input.proof) });
  }

  async canonicalInstallation(admissionId: string, signal?: AbortSignal): Promise<CanonicalCopyInstallation | undefined> {
    signal?.throwIfAborted();
    const installed = await this.options.runtime.installed(admissionId);
    if (!installed) return undefined;
    const binding = decodeHyperKeyAdmissionBinding(installed.request);
    if (installed.request.scope !== this.options.scopeFor(binding.groupId, HYPERKEY_GROUP_PROFILE) || installed.selected.selection.kind !== "add" || installed.selected.selection.operationId !== admissionId) throw new HyperKeyGroupCompositionError("Installed admission has another Copy scope");
    return Object.freeze({ groupId: binding.groupId, profile: HYPERKEY_GROUP_PROFILE, copy: Object.freeze({ copyId: binding.copyId, member: installed.request.member, keyPackageDigest: installed.request.keyPackageDigest, recipientDeliveryKey: binding.recipientDeliveryKey }), admissionId, selectedCommitId: installed.receipt.successor });
  }
}

export function hyperKeyAdmissionBinding(groupId: string, copy: CopyIdentity): Uint8Array {
  return canonicalBytes(["hyperkey.admission-binding.v1", { groupId, profile: HYPERKEY_GROUP_PROFILE, copyId: copy.copyId, recipientDeliveryKey: copy.recipientDeliveryKey }]);
}

export function decodeHyperKeyAdmissionBinding(request: AdmissionRequest): Readonly<{ groupId: string; copyId: string; recipientDeliveryKey: string }> {
  try {
    if (!request.deliveryBinding || request.deliveryBinding.length > 4096) throw new Error("Missing Copy binding");
    const [domain, value] = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(request.deliveryBinding));
    if (domain !== "hyperkey.admission-binding.v1" || !value || value.profile !== HYPERKEY_GROUP_PROFILE || Object.keys(value).sort().join(",") !== "copyId,groupId,profile,recipientDeliveryKey" || [value.groupId, value.copyId, value.recipientDeliveryKey].some(entry => typeof entry !== "string" || !entry.length || entry.length > 256)) throw new Error("Invalid Copy binding");
    const copy = { copyId: value.copyId, member: request.member, keyPackageDigest: request.keyPackageDigest, recipientDeliveryKey: value.recipientDeliveryKey };
    if (!equalBytes(hyperKeyAdmissionBinding(value.groupId, copy), request.deliveryBinding)) throw new Error("Noncanonical Copy binding");
    return Object.freeze({ groupId: value.groupId, copyId: value.copyId, recipientDeliveryKey: value.recipientDeliveryKey });
  } catch (cause) { throw new HyperKeyGroupCompositionError("Invalid HyperKey admission binding", { cause }); }
}
