import { HyperKeyCopyAdmissions } from "./admission.js";
import { createFounderHyperKey, type HyperKeyFounderGroupPort } from "./founder.js";
import { forgetHyperKeyLocally, installPrivateSeedDelivery } from "./custody.js";
import { hyperKeyDescriptorId, type HyperKeyDescriptor } from "./descriptor.js";
import { prepareHyperKeyCandidate, type HyperKeyCandidateGroupPort } from "./candidate.js";
import { HyperKeyProviderUnavailableError, type CopyIdentity } from "./group-ports.js";
import { type HyperKeyCopyProgress } from "./workflow.js";
import { type HyperKeyPrivateDelivery, type PrivateDeliveryContext } from "./delivery.js";
import { type AuthenticatedHyperKeyApplicationDelivery } from "./application-delivery.js";
import type { StagedNativeGroupTransition } from "@group-foundation/group-core";
import type { HyperKeyAdmissionProvider } from "./admission.js";
import { HyperKeyDeviceState, type HyperKeyDeviceStateOptions, type StoredHyperKeyProduct } from "./state.js";

export interface HyperKeyHostOptions extends HyperKeyDeviceStateOptions {
  /** Product-owned Group founder creation; Group controls MLS state. */
  readonly group: HyperKeyFounderGroupPort;
  readonly candidates?: HyperKeyCandidateGroupPort;
  /**
   * An already composed Group admission runtime and storage. It is absent by
   * default: the host never invents production identity or governance ports.
   */
  readonly admissions?: HyperKeyAdmissionProvider;
}

export interface CreateLocalHyperKeyInput {
  readonly founder: CopyIdentity;
  /** A caller may supply a stable Group ID; otherwise the host makes an opaque one. */
  readonly groupId?: string;
}

export interface LocalHyperKey {
  readonly id: string;
  readonly descriptor: import("./descriptor.js").HyperKeyDescriptor;
  readonly copyId: string;
  readonly status: "ready" | "forgotten";
  /** Ordinary Ed25519 signing; no seed is returned to the caller. */
  sign(message: Uint8Array, signal?: AbortSignal): Promise<Uint8Array>;
  forget(signal?: AbortSignal): Promise<void>;
}

/** Consumer-facing local HyperKey facade. It never exposes conventional private seeds. */
export class HyperKeyHost {
  readonly state: HyperKeyDeviceState;
  readonly admissions: HyperKeyCopyAdmissions | undefined;

  constructor(private readonly options: HyperKeyHostOptions) {
    this.state = new HyperKeyDeviceState(options);
    this.admissions = options.admissions && new HyperKeyCopyAdmissions(options.admissions, this.state.copyAdmissionRecords());
  }

  async create(input: CreateLocalHyperKeyInput, signal?: AbortSignal): Promise<LocalHyperKey> {
    const groupId = input.groupId ?? randomIdentifier();
    const atomic = {
      createAtomically: async (value: Parameters<import("./founder.js").HyperKeyFounderAtomicPort["createAtomically"]>[0], active?: AbortSignal): Promise<void> => {
        active?.throwIfAborted();
        await this.state.createFounderProduct({ descriptor: value.descriptor, descriptorId: value.descriptorId, readiness: value.readiness, founder: input.founder, seed: value.seed, stagedGroup: value.stagedGroup });
      },
    };
    const created = await createFounderHyperKey({ groupId, founder: input.founder, group: this.options.group, atomic }, signal);
    return this.toLocal({ schema: "hyperkey.product-state.v1", descriptor: created.descriptor, readiness: created.readiness });
  }

  async open(id: string, copyId?: string): Promise<LocalHyperKey | undefined> {
    const matches = (await this.state.listProducts()).filter(value => value.descriptor && value.readiness.descriptorId === id && (copyId === undefined || value.readiness.copyId === copyId));
    if (matches.length > 1) throw new Error("HyperKey ID has multiple local Copies; specify copyId");
    return matches[0] && this.toLocal(matches[0]);
  }

  async list(): Promise<readonly LocalHyperKey[]> {
    return Object.freeze((await this.state.listProducts()).map(value => this.toLocal(value)));
  }

  async createCopyCandidate(input: Readonly<{ descriptor: HyperKeyDescriptor; evidence: Uint8Array; copyId?: string }>, signal?: AbortSignal): Promise<HyperKeyCopyProgress> {
    if (!this.options.candidates) throw new HyperKeyProviderUnavailableError();
    const descriptorId = await hyperKeyDescriptorId(input.descriptor);
    const candidate = await prepareHyperKeyCandidate({ groupId: input.descriptor.groupId, copyId: input.copyId ?? randomIdentifier(), evidence: input.evidence, group: this.options.candidates }, signal);
    try { return await this.state.createCandidate(input.descriptor, descriptorId, candidate); }
    finally { candidate.deliveryPrivateKey.fill(0); }
  }

  listCopies(): Promise<readonly HyperKeyCopyProgress[]> { return this.state.listCopyProgress(); }
  copyProgress(descriptorId: string, copyId: string): Promise<HyperKeyCopyProgress | undefined> { return this.state.copyProgress().read(descriptorId, copyId); }

  async requestCopy(input: Readonly<{ descriptorId: string; copyId: string; admissionId: string; invitationId: string; evidence: Uint8Array; proof: Uint8Array; requestedAtMs: number; expiresAtMs: number }>, signal?: AbortSignal): Promise<HyperKeyCopyProgress> {
    const admissions = this.requiredAdmissions();
    const progress = await this.state.copyProgress().read(input.descriptorId, input.copyId);
    if (!progress || !["candidate", "requested"].includes(progress.step)) throw new Error("Copy candidate is not awaiting admission");
    if (progress.admissionId && progress.admissionId !== input.admissionId) throw new Error("Copy candidate is already bound to another admission");
    const keyPackage = await this.state.candidateKeyPackage(input.descriptorId, input.copyId);
    await admissions.request({ ...input, groupId: progress.descriptor.groupId, copy: progress.copy, keyPackage }, signal);
    const next: HyperKeyCopyProgress = { ...progress, admissionId: input.admissionId, step: "requested" };
    await this.state.copyProgress().write(next, signal);
    return Object.freeze(next);
  }

  approveCopy(...input: Parameters<HyperKeyCopyAdmissions["approve"]>): ReturnType<HyperKeyCopyAdmissions["approve"]> { return this.requiredAdmissions().approve(...input); }

  /** The trusted Group adapter validates the selected Welcome before staging this transition. */
  installCopyGroup(input: Readonly<{ descriptorId: string; copyId: string; admissionId: string; selectedCommitId: string; transition: StagedNativeGroupTransition }>): Promise<HyperKeyCopyProgress> { return this.state.installCandidateGroup(input); }

  acknowledgeCopyInstallation(...input: Parameters<HyperKeyCopyAdmissions["acknowledgeCanonicalInstallation"]>): ReturnType<HyperKeyCopyAdmissions["acknowledgeCanonicalInstallation"]> { return this.requiredAdmissions().acknowledgeCanonicalInstallation(...input); }

  async preparePrivateDelivery(context: Omit<PrivateDeliveryContext, "admissions" | "outbox">, signal?: AbortSignal): Promise<HyperKeyPrivateDelivery> {
    return this.state.preparePrivateDelivery(await hyperKeyDescriptorId(context.descriptor), context.senderCopyId, { ...context, admissions: this.requiredAdmissions() }, signal);
  }

  async installPrivateDelivery(input: Readonly<{ delivery: HyperKeyPrivateDelivery; authenticatedSender: AuthenticatedHyperKeyApplicationDelivery }>, signal?: AbortSignal): Promise<LocalHyperKey> {
    const { descriptorId, recipientCopyId } = input.delivery;
    const progress = await this.state.copyProgress().read(descriptorId, recipientCopyId);
    if (!progress) throw new Error("Private delivery has no local Copy candidate");
    const recipientPrivateDeliveryKey = await this.state.candidateDeliveryKey(descriptorId, recipientCopyId);
    await installPrivateSeedDelivery({ ...input, descriptor: progress.descriptor, recipientPrivateDeliveryKey, admissions: this.requiredAdmissions(), state: this.state.localState(descriptorId, recipientCopyId), custody: this.state.custody(descriptorId, recipientCopyId) }, signal);
    const installed = await this.open(descriptorId, recipientCopyId);
    if (!installed) throw new Error("Installed HyperKey Copy is not durably visible");
    return installed;
  }

  async forgetCopy(descriptorId: string, copyId: string, signal?: AbortSignal): Promise<void> {
    const progress = await this.state.copyProgress().read(descriptorId, copyId);
    if (!progress) throw new Error("Local HyperKey Copy is unknown");
    await forgetHyperKeyLocally({ descriptorId, groupId: progress.descriptor.groupId, copyId, state: this.state.localState(descriptorId, copyId), custody: this.state.custody(descriptorId, copyId) }, signal);
  }

  close(): Promise<void> { return this.state.close(); }

  private toLocal(record: StoredHyperKeyProduct): LocalHyperKey {
    const { descriptor, readiness } = record;
    return Object.freeze({
      id: readiness.descriptorId,
      descriptor: Object.freeze(structuredClone(descriptor)),
      copyId: readiness.copyId,
      status: readiness.status,
      sign: (message: Uint8Array, signal?: AbortSignal) => this.state.sign(readiness.descriptorId, readiness.copyId, message, signal),
      forget: async (signal?: AbortSignal) => forgetHyperKeyLocally({ descriptorId: readiness.descriptorId, groupId: descriptor.groupId, copyId: readiness.copyId, state: this.state.localState(readiness.descriptorId, readiness.copyId), custody: this.state.custody(readiness.descriptorId, readiness.copyId) }, signal),
    });
  }

  private requiredAdmissions(): HyperKeyCopyAdmissions { if (!this.admissions) throw new HyperKeyProviderUnavailableError(); return this.admissions; }
}

function randomIdentifier(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
