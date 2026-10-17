import { assertStagedNativeGroupTransition, type MemberIdentity, type NativeGroupState, type NativeGroupTransitionStoragePort, type StagedNativeGroupTransition } from "@group-foundation/group-core";
import { HYPERKEY_GROUP_PROFILE, type HyperKeyCopyAdmissionRecord, type HyperKeyCopyAdmissionRecordStore, type CopyIdentity } from "./group-ports.js";
import { assertHyperKeyDescriptor, hyperKeyDescriptorId, type HyperKeyDescriptor } from "./descriptor.js";
import { createPrivateSeedDelivery, type PrivateDeliveryContext, type HyperKeyPrivateDelivery, type HyperKeyPrivateDeliveryOutboxPort, type HyperKeyPrivateDeliveryOutboxRecord } from "./delivery.js";
import { publicKeyForEd25519Seed, signEd25519 } from "./ed25519.js";
import { HyperKeyCopyUnavailableError, type HyperKeyCopyReadiness, type HyperKeyLocalStateMutation, type HyperKeyLocalStatePort, type HyperKeySeedCustody } from "./custody.js";
import { assertHyperKeyCopyProgress, assertHyperKeyCopyProgressTransition, type HyperKeyCopyProgress, type HyperKeyCopyProgressStore } from "./workflow.js";
import { restoreCandidateDeliveryPrivateKey, type HyperKeyPreparedCandidate } from "./candidate.js";
import type { HyperKeyPersistencePort, HyperKeySealingPort, HyperKeyCommitOutcomePort } from "./persistence.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true });
const MAX_RECORD_BYTES = 1_048_576;
const GROUP_PURPOSE = "hyperkey-group-client-v1";
const PRODUCT_PURPOSE = "hyperkey-product-v1";
const CUSTODY_PURPOSE = "hyperkey-custody-v1";
const INDEX_KEY = "hyperkey/product-index/v1";
const COPY_INDEX_KEY = "hyperkey/copy-index/v1";

type RecordKind = "group" | "product" | "custody" | "index" | "admission" | "delivery" | "candidate" | "progress" | "native" | "native-outbox" | "native-transition";

export interface HyperKeyDeviceStateOptions {
  readonly persistence: HyperKeyPersistencePort;
  readonly sealing: HyperKeySealingPort;
  readonly commitOutcome: HyperKeyCommitOutcomePort;
}

export interface StoredHyperKeyProduct {
  readonly schema: "hyperkey.product-state.v1";
  readonly descriptor: import("./descriptor.js").HyperKeyDescriptor;
  readonly readiness: HyperKeyCopyReadiness;
}

interface StoredCandidate {
  readonly schema: "hyperkey.candidate.v1";
  readonly descriptor: HyperKeyDescriptor;
  readonly copy: CopyIdentity;
  readonly keyPackage: Uint8Array;
  readonly deliveryPrivateKey: Uint8Array;
}

/**
 * A sealed record coordinator for native Group and HyperKey records.
 * Records have separate device-key purposes and associated data, while every
 * visibility change goes through the consumer-owned physical transaction.
 */
export class HyperKeyDeviceState {
  private tail: Promise<void> = Promise.resolve();
  private activeRecords?: Map<string, unknown>;
  private activeKeys?: ReadonlySet<string>;
  private closed = false;

  constructor(private readonly options: HyperKeyDeviceStateOptions) {}

  async close(): Promise<void> {
    await this.serial(async () => { this.closed = true; });
  }

  /** Native snapshots, exact outboxes and admission accounting share one CAS. */
  nativeGroupStorage(): NativeGroupTransitionStoragePort {
    return {
      read: async (groupId, member) => this.read<NativeGroupState>("native", await recordKey("native", nativeLocator(groupId, member))),
      commit: async transition => {
        const prepared = await prepareNativeTransition(transition);
        return this.transaction(prepared.entries, records => applyNativeTransition(records, transition, prepared));
      },
    };
  }

  localState(descriptorId: string, copyId: string): HyperKeyLocalStatePort {
    return new PersistentHyperKeyLocalState(this, descriptorId, copyId);
  }

  custody(descriptorId: string, copyId: string): HyperKeySeedCustody {
    return new PersistentHyperKeySeedCustody(this, descriptorId, copyId);
  }

  /** Product-side Copy/admission bindings required by @group-foundation/hyperkey. */
  copyAdmissionRecords(): HyperKeyCopyAdmissionRecordStore {
    return new PersistentCopyAdmissionRecords(this);
  }

  copyProgress(): HyperKeyCopyProgressStore { return new PersistentCopyProgress(this); }

  async listCopyProgress(): Promise<readonly HyperKeyCopyProgress[]> {
    const index = await this.read<ProductIndex>("index", COPY_INDEX_KEY) ?? { schema: "hyperkey.product-index.v1", entries: [] };
    assertIndex(index);
    const records = await Promise.all(index.entries.map(entry => this.copyProgress().read(entry.descriptorId, entry.copyId)));
    if (records.some(record => record === undefined)) throw new Error("HyperKey Copy index references a missing record");
    return Object.freeze(records as HyperKeyCopyProgress[]);
  }

  async createCandidate(descriptor: HyperKeyDescriptor, descriptorId: string, candidate: HyperKeyPreparedCandidate): Promise<HyperKeyCopyProgress> {
    assertHyperKeyDescriptor(descriptor);
    if (await hyperKeyDescriptorId(descriptor) !== descriptorId || candidate.stagedGroup.next.groupId !== descriptor.groupId || candidate.stagedGroup.next.member.signingKeyFingerprint !== candidate.copy.member.signingKeyFingerprint || candidate.stagedGroup.kind !== "key-package") throw new Error("Candidate staging differs from HyperKey descriptor");
    const locator = productLocator(descriptorId, candidate.copy.copyId);
    const [candidateKey, progressKey] = await Promise.all([recordKey("candidate", locator), recordKey("progress", locator)]);
    const native = await prepareNativeTransition(candidate.stagedGroup);
    const progress: HyperKeyCopyProgress = { schema: "hyperkey.copy-progress.v1", descriptorId, descriptor: structuredClone(descriptor), copy: structuredClone(candidate.copy), step: "candidate" };
    assertHyperKeyCopyProgressTransition(undefined, progress);
    await this.transaction([keyFor("candidate", candidateKey), keyFor("progress", progressKey), keyFor("index", COPY_INDEX_KEY), ...native.entries], records => {
      if (records.has(keyFor("candidate", candidateKey)) || records.has(keyFor("progress", progressKey))) throw new Error("HyperKey Copy candidate already exists");
      applyNativeTransition(records, candidate.stagedGroup, native);
      records.set(keyFor("candidate", candidateKey), { schema: "hyperkey.candidate.v1", descriptor, copy: candidate.copy, keyPackage: new Uint8Array(candidate.keyPackage), deliveryPrivateKey: new Uint8Array(candidate.deliveryPrivateKey) } satisfies StoredCandidate);
      records.set(keyFor("progress", progressKey), structuredClone(progress));
      appendIndex(records, COPY_INDEX_KEY, descriptorId, candidate.copy.copyId);
    });
    return Object.freeze(progress);
  }

  async candidateKeyPackage(descriptorId: string, copyId: string): Promise<Uint8Array> {
    const candidate = await this.read<StoredCandidate>("candidate", await recordKey("candidate", productLocator(descriptorId, copyId)));
    if (!candidate) throw new HyperKeyCopyUnavailableError("not-ready");
    if (candidate.schema !== "hyperkey.candidate.v1") throw new Error("Unknown HyperKey candidate schema");
    return new Uint8Array(candidate.keyPackage);
  }

  async candidateDeliveryKey(descriptorId: string, copyId: string): Promise<CryptoKey | undefined> {
    const candidate = await this.read<StoredCandidate>("candidate", await recordKey("candidate", productLocator(descriptorId, copyId)));
    if (!candidate) return undefined;
    if (candidate.schema !== "hyperkey.candidate.v1") throw new Error("Unknown HyperKey candidate schema");
    try { return await restoreCandidateDeliveryPrivateKey(candidate.deliveryPrivateKey); }
    finally { candidate.deliveryPrivateKey.fill(0); }
  }

  async installCandidateGroup(input: Readonly<{ descriptorId: string; copyId: string; admissionId: string; selectedCommitId: string; transition: StagedNativeGroupTransition }>): Promise<HyperKeyCopyProgress> {
    const progressKey = await recordKey("progress", productLocator(input.descriptorId, input.copyId));
    const prepared = await prepareNativeTransition(input.transition);
    return this.transaction([keyFor("progress", progressKey), ...prepared.entries], records => {
      const current = records.get(keyFor("progress", progressKey)) as HyperKeyCopyProgress | undefined;
      if (!current || current.admissionId !== input.admissionId || current.descriptor.groupId !== input.transition.next.groupId || input.transition.next.profile !== HYPERKEY_GROUP_PROFILE || current.copy.member.signingKeyFingerprint !== input.transition.next.member.signingKeyFingerprint || input.transition.kind !== "join") throw new Error("Candidate Group installation differs from Copy request");
      if (current.step === "forgotten") throw new HyperKeyCopyUnavailableError("forgotten");
      if (current.step === "requested") assertHyperKeyCopyProgressTransition(current, { ...current, step: "approved" });
      const approved = current.step === "requested" ? { ...current, step: "approved" as const } : current;
      const next: HyperKeyCopyProgress = { ...approved, step: "group-installed", selectedCommitId: input.selectedCommitId };
      assertHyperKeyCopyProgressTransition(approved, next);
      applyNativeTransition(records, input.transition, prepared);
      records.set(keyFor("progress", progressKey), structuredClone(next));
      return Object.freeze(next);
    });
  }

  async product(descriptorId: string, copyId: string): Promise<StoredHyperKeyProduct | undefined> {
    const key = await recordKey("product", productLocator(descriptorId, copyId));
    const value = await this.read<StoredHyperKeyProduct>("product", key);
    if (value) {
      assertProduct(value, descriptorId, copyId);
      if (await hyperKeyDescriptorId(value.descriptor) !== descriptorId) throw new Error("HyperKey descriptor ID differs from persisted scope");
    }
    return value;
  }

  async listProducts(): Promise<readonly StoredHyperKeyProduct[]> {
    const index = await this.read<ProductIndex>("index", INDEX_KEY) ?? { schema: "hyperkey.product-index.v1", entries: [] };
    assertIndex(index);
    const records = await Promise.all(index.entries.map(async entry => this.product(entry.descriptorId, entry.copyId)));
    if (records.some(value => value === undefined)) throw new Error("HyperKey product index references a missing record");
    return Object.freeze(records as StoredHyperKeyProduct[]);
  }

  /** The conventional seed stays inside sealed custody throughout ordinary use. */
  async sign(descriptorId: string, copyId: string, message: Uint8Array, signal?: AbortSignal): Promise<Uint8Array> {
    if (!(message instanceof Uint8Array)) throw new TypeError("Signing input must be bytes");
    const ownedMessage = new Uint8Array(message);
    return this.useReadySeed(descriptorId, copyId, seed => signEd25519(seed, ownedMessage), signal);
  }

  /** Admission delivery is the only internal operation that uses a seed as plaintext. */
  async preparePrivateDelivery(descriptorId: string, copyId: string, context: Omit<PrivateDeliveryContext, "outbox">, signal?: AbortSignal): Promise<HyperKeyPrivateDelivery> {
    if (context.senderCopyId !== copyId || await hyperKeyDescriptorId(context.descriptor) !== descriptorId) throw new Error("Private delivery sender does not match local Copy");
    // Outbox persistence uses this same coordinator and cannot be called while
    // its serial section is held. The seed is used only by the
    // authenticated delivery function, never returned to a consumer.
    return this.useReadySeed(descriptorId, copyId, seed => createPrivateSeedDelivery({ ...context, outbox: this.deliveryOutbox(descriptorId, copyId) }, seed), signal, false);
  }

  deliveryOutbox(descriptorId: string, copyId: string): HyperKeyPrivateDeliveryOutboxPort {
    return new PersistentPrivateDeliveryOutbox(this, descriptorId, copyId);
  }

  private async useReadySeed<T>(descriptorId: string, copyId: string, use: (seed: Uint8Array) => Promise<T>, signal?: AbortSignal, holdWriter = true): Promise<T> {
    const locator = productLocator(descriptorId, copyId);
    const [productKey, custodyKey] = await Promise.all([recordKey("product", locator), recordKey("custody", locator)]);
    const read = async (): Promise<Uint8Array> => {
      signal?.throwIfAborted();
      this.assertOpen();
      const keys = [keyFor("product", productKey), keyFor("custody", custodyKey)];
      const before = await this.options.persistence.read(keys);
      const productValue = before.get(keys[0]!);
      if (!productValue) throw new HyperKeyCopyUnavailableError("not-ready");
      const product = await this.open<StoredHyperKeyProduct>("product", productKey, productValue);
      assertProduct(product, descriptorId, copyId);
      if (product.readiness.status === "forgotten") throw new HyperKeyCopyUnavailableError("forgotten");
      const custodyValue = before.get(keys[1]!);
      if (!custodyValue) throw new HyperKeyCopyUnavailableError("missing-custody");
      const custody = await this.open<{ schema: string; seed: string }>("custody", custodyKey, custodyValue);
      if (custody.schema !== "hyperkey.seed-custody.v1") throw new HyperKeyCopyUnavailableError("changed-custody");
      const seed = fromBase64url(custody.seed);
      try {
        const actual = base64url(await publicKeyForEd25519Seed(seed));
        if (actual !== product.descriptor.publicKey || await hyperKeyDescriptorId(product.descriptor) !== descriptorId) throw new HyperKeyCopyUnavailableError("changed-custody");
        return seed;
      } catch (cause) { seed.fill(0); if (cause instanceof HyperKeyCopyUnavailableError) throw cause; throw new HyperKeyCopyUnavailableError("changed-custody"); }
    };
    const consume = async (seed: Uint8Array): Promise<T> => { try { signal?.throwIfAborted(); return await use(seed); } finally { seed.fill(0); } };
    if (holdWriter) return this.serial(async () => consume(await read()));
    return consume(await this.serial(read));
  }

  /** Founder Group state and key readiness become visible in one physical CAS. */
  async createFounderProduct(input: Readonly<{ descriptor: import("./descriptor.js").HyperKeyDescriptor; descriptorId: string; readiness: HyperKeyCopyReadiness; founder: CopyIdentity; seed: Uint8Array; stagedGroup: StagedNativeGroupTransition }>): Promise<void> {
    assertHyperKeyDescriptor(input.descriptor);
    assertReadiness(input.readiness, input.descriptorId, input.readiness.copyId);
    if (input.readiness.groupId !== input.descriptor.groupId || input.readiness.status !== "ready" || input.founder.copyId !== input.readiness.copyId || input.founder.member.signingKeyFingerprint !== input.readiness.receipt?.recipientMemberSigningKeyFingerprint || input.founder.recipientDeliveryKey !== input.readiness.receipt?.recipientDeliveryKey || input.readiness.receipt?.seedPublicKey !== input.descriptor.publicKey) throw new Error("Founder HyperKey readiness differs from descriptor");
    const locator = productLocator(input.descriptorId, input.readiness.copyId);
    const [productKey, custodyKey, progressKey] = await Promise.all([recordKey("product", locator), recordKey("custody", locator), recordKey("progress", locator)]);
    if (input.stagedGroup.kind !== "create" || input.stagedGroup.next.groupId !== input.descriptor.groupId || input.stagedGroup.next.profile !== HYPERKEY_GROUP_PROFILE || input.stagedGroup.next.member.signingKeyFingerprint !== input.readiness.receipt?.recipientMemberSigningKeyFingerprint) throw new Error("Founder Group state does not match its Copy");
    if (await hyperKeyDescriptorId(input.descriptor) !== input.descriptorId || base64url(await publicKeyForEd25519Seed(input.seed)) !== input.descriptor.publicKey) throw new Error("Founder private seed differs from descriptor");
    const native = await prepareNativeTransition(input.stagedGroup);
    await this.transaction([keyFor("product", productKey), keyFor("custody", custodyKey), keyFor("progress", progressKey), keyFor("index", COPY_INDEX_KEY), keyFor("index", INDEX_KEY), ...native.entries], async records => {
      if (records.get(keyFor("product", productKey)) || records.get(keyFor("custody", custodyKey))) throw new Error("Founder HyperKey already exists locally");
      const product: StoredHyperKeyProduct = Object.freeze({ schema: "hyperkey.product-state.v1", descriptor: structuredClone(input.descriptor), readiness: structuredClone(input.readiness) });
      const index = records.get(keyFor("index", INDEX_KEY)) as ProductIndex | undefined ?? { schema: "hyperkey.product-index.v1", entries: [] };
      assertIndex(index);
      if (index.entries.some(value => value.descriptorId === input.descriptorId && value.copyId === input.readiness.copyId)) throw new Error("Founder HyperKey index already exists");
      applyNativeTransition(records, input.stagedGroup, native);
      records.set(keyFor("product", productKey), product);
      records.set(keyFor("custody", custodyKey), { schema: "hyperkey.seed-custody.v1", seed: base64url(input.seed) });
      records.set(keyFor("progress", progressKey), { schema: "hyperkey.copy-progress.v1", descriptorId: input.descriptorId, descriptor: structuredClone(input.descriptor), copy: structuredClone(input.founder), step: "ready", admissionId: "founder", selectedCommitId: "founder", deliveryId: input.readiness.receipt!.deliveryId } satisfies HyperKeyCopyProgress);
      appendIndex(records, COPY_INDEX_KEY, input.descriptorId, input.readiness.copyId);
      records.set(keyFor("index", INDEX_KEY), { schema: "hyperkey.product-index.v1", entries: [...index.entries, { descriptorId: input.descriptorId, copyId: input.readiness.copyId }].sort(compareIndex) });
    });
  }

  async read<T>(kind: RecordKind, key: string): Promise<T | undefined> {
    return this.serial(async () => {
      this.assertOpen();
      const physicalKey = keyFor(kind, key);
      const response = await this.options.persistence.read([physicalKey]);
      const value = response.get(physicalKey);
      return value === undefined ? undefined : this.open<T>(kind, key, value);
    });
  }

  async transaction<T>(entries: readonly string[], operation: (records: Map<string, unknown>) => Promise<T> | T): Promise<T> {
    return this.serial(async () => {
      this.assertOpen();
      const unique = [...new Set(entries)];
      if (unique.length !== entries.length || unique.length === 0 || unique.length > 512) throw new Error("HyperKey state transaction entries are invalid");
      try {
        return await this.options.persistence.transact(unique, async sealed => {
          const records = new Map<string, unknown>();
          for (const key of unique) {
            const value = sealed.get(key);
            if (value !== undefined) records.set(key, await this.open(kindFromKey(key), rawKey(key), value));
          }
          if (this.activeRecords) throw new Error("Nested HyperKey state transaction is invalid");
          this.activeRecords = records;
          this.activeKeys = new Set(unique);
          let result: T;
          try { result = await operation(records); }
          finally { this.activeRecords = undefined; this.activeKeys = undefined; }
          for (const key of records.keys()) if (!unique.includes(key)) throw new Error("HyperKey transaction wrote an undeclared record");
          for (const key of unique) {
            if (!records.has(key)) sealed.delete(key);
            else sealed.set(key, await this.seal(kindFromKey(key), rawKey(key), records.get(key)));
          }
          return result;
        });
      } catch (cause) {
        if (this.options.commitOutcome.isUncertain(cause)) this.closed = true;
        throw cause;
      }
    });
  }

  /** Internal bridge for custody invoked by @group-foundation/hyperkey inside a readiness transaction. */
  mutateActive(key: string, value: unknown | undefined): boolean {
    if (!this.activeRecords || !this.activeKeys?.has(key)) return false;
    if (value === undefined) this.activeRecords.delete(key); else this.activeRecords.set(key, value);
    return true;
  }

  private assertOpen(): void {
    if (this.closed) throw new Error("HyperKey state is closed; reopen from committed persistence");
  }

  private async seal(kind: RecordKind, key: string, value: unknown): Promise<Uint8Array> {
    const plaintext = encoder.encode(JSON.stringify(jsonValue(value)));
    try {
      if (plaintext.length > MAX_RECORD_BYTES) throw new Error("HyperKey state record exceeds its bound");
      return await this.options.sealing.seal(purpose(kind), plaintext, associatedData(kind, key));
    }
    finally { plaintext.fill(0); }
  }

  private async open<T>(kind: RecordKind, key: string, sealed: Uint8Array): Promise<T> {
    const plaintext = await this.options.sealing.open(purpose(kind), sealed, associatedData(kind, key));
    try {
      if (plaintext.length > MAX_RECORD_BYTES) throw new Error("HyperKey state record exceeds its bound");
      return restoreJsonValue(JSON.parse(decoder.decode(plaintext))) as T; }
    catch (cause) { throw new Error("HyperKey state record is invalid", { cause }); }
    finally { plaintext.fill(0); }
  }

  private serial<T>(work: () => Promise<T>): Promise<T> {
    const next = this.tail.then(work, work);
    this.tail = next.then(() => undefined, () => undefined);
    return next;
  }
}

class PersistentHyperKeyLocalState implements HyperKeyLocalStatePort {
  constructor(private readonly state: HyperKeyDeviceState, private readonly descriptorId: string, private readonly copyId: string) {}
  async read(descriptorId: string, copyId: string): Promise<HyperKeyCopyReadiness | undefined> {
    this.assertTarget(descriptorId, copyId);
    return (await this.state.product(descriptorId, copyId))?.readiness;
  }
  async transaction<T>(operation: (state: HyperKeyLocalStateMutation) => Promise<T> | T): Promise<T> {
    const locator = productLocator(this.descriptorId, this.copyId), key = await recordKey("product", locator);
    const [custodyKey, candidateKey, progressKey] = await Promise.all([recordKey("custody", locator), recordKey("candidate", locator), recordKey("progress", locator)]);
    const progressBefore = await this.state.copyProgress().read(this.descriptorId, this.copyId);
    const nativeKey = progressBefore ? keyFor("native", await recordKey("native", nativeLocator(progressBefore.descriptor.groupId, progressBefore.copy.member))) : undefined;
    return this.state.transaction([keyFor("product", key), keyFor("custody", custodyKey), keyFor("candidate", candidateKey), keyFor("progress", progressKey), keyFor("index", INDEX_KEY), ...(nativeKey ? [nativeKey] : [])], async records => {
      const product = records.get(keyFor("product", key)) as StoredHyperKeyProduct | undefined;
      const progress = records.get(keyFor("progress", progressKey)) as HyperKeyCopyProgress | undefined;
      let replacement: HyperKeyCopyReadiness | undefined;
      const result = await operation({
        read: (descriptorId, copyId) => { this.assertTarget(descriptorId, copyId); return product?.readiness && structuredClone(product.readiness); },
        write: readiness => { this.assertTarget(readiness.descriptorId, readiness.copyId); assertReadiness(readiness, this.descriptorId, this.copyId); replacement = structuredClone(readiness); },
      });
      if (!replacement) return result;
      const descriptor = product?.descriptor ?? progress?.descriptor;
      if (!descriptor) throw new Error("HyperKey descriptor is not locally known");
      if (replacement.status === "ready" && progress?.step !== "group-installed" && progress?.step !== "ready") throw new Error("Copy Group installation is not durable");
      records.set(keyFor("product", key), { schema: "hyperkey.product-state.v1", descriptor: structuredClone(descriptor), readiness: replacement } satisfies StoredHyperKeyProduct);
      appendIndex(records, INDEX_KEY, this.descriptorId, this.copyId);
      if (progress) {
        const next: HyperKeyCopyProgress = replacement.status === "forgotten" ? { ...progress, step: "forgotten" } : { ...progress, step: "ready", deliveryId: replacement.receipt!.deliveryId };
        assertHyperKeyCopyProgressTransition(progress, next);
        records.set(keyFor("progress", progressKey), next);
      }
      records.delete(keyFor("candidate", candidateKey));
      if (replacement.status === "forgotten" && nativeKey) {
        records.delete(nativeKey);

      }
      return result;
    });
  }
  private assertTarget(descriptorId: string, copyId: string): void { if (descriptorId !== this.descriptorId || copyId !== this.copyId) throw new Error("HyperKey local state adapter is scoped to one Copy"); }
}

class PersistentCopyProgress implements HyperKeyCopyProgressStore {
  constructor(private readonly state: HyperKeyDeviceState) {}
  async read(descriptorId: string, copyId: string): Promise<HyperKeyCopyProgress | undefined> {
    const key = await recordKey("progress", productLocator(descriptorId, copyId));
    const value = await this.state.read<HyperKeyCopyProgress>("progress", key);
    if (value) assertHyperKeyCopyProgress(value);
    if (value && (value.descriptorId !== descriptorId || value.copy.copyId !== copyId || await hyperKeyDescriptorId(value.descriptor) !== descriptorId)) throw new Error("HyperKey Copy progress binding differs");
    return value && structuredClone(value);
  }
  async write(next: HyperKeyCopyProgress): Promise<void> {
    if (await hyperKeyDescriptorId(next.descriptor) !== next.descriptorId) throw new Error("Copy progress descriptor ID differs");
    const key = await recordKey("progress", productLocator(next.descriptorId, next.copy.copyId));
    await this.state.transaction([keyFor("progress", key)], records => {
      const previous = records.get(keyFor("progress", key)) as HyperKeyCopyProgress | undefined;
      if (!previous) throw new Error("Create the independently staged Copy candidate first");
      if (["group-installed", "ready", "forgotten"].includes(next.step) && previous.step !== next.step) throw new Error("Copy installation and forgetting require their atomic workflow");
      assertHyperKeyCopyProgressTransition(previous, next);
      records.set(keyFor("progress", key), structuredClone(next));
    });
  }
}

class PersistentHyperKeySeedCustody implements HyperKeySeedCustody {
  constructor(private readonly state: HyperKeyDeviceState, private readonly descriptorId: string, private readonly copyId: string) {}
  async seal(input: Readonly<{ descriptorId: string; copyId: string; seed: Uint8Array }>): Promise<void> {
    this.assertTarget(input.descriptorId, input.copyId); if (input.seed.length !== 32) throw new Error("HyperKey seed must be 32 bytes");
    const key = await recordKey("custody", productLocator(this.descriptorId, this.copyId));
    if (this.state.mutateActive(keyFor("custody", key), { schema: "hyperkey.seed-custody.v1", seed: base64url(input.seed) })) return;
    await this.state.transaction([keyFor("custody", key)], records => { records.set(keyFor("custody", key), { schema: "hyperkey.seed-custody.v1", seed: base64url(input.seed) }); });
  }
  async remove(input: Readonly<{ descriptorId: string; copyId: string }>): Promise<void> {
    this.assertTarget(input.descriptorId, input.copyId);
    const key = await recordKey("custody", productLocator(this.descriptorId, this.copyId));
    if (this.state.mutateActive(keyFor("custody", key), undefined)) return;
    await this.state.transaction([keyFor("custody", key)], records => { records.delete(keyFor("custody", key)); });
  }
  async has(input: Readonly<{ descriptorId: string; copyId: string }>): Promise<boolean> {
    this.assertTarget(input.descriptorId, input.copyId);
    const key = await recordKey("custody", productLocator(this.descriptorId, this.copyId));
    return this.state.read<unknown>("custody", key).then(value => value !== undefined);
  }
  private assertTarget(descriptorId: string, copyId: string): void { if (descriptorId !== this.descriptorId || copyId !== this.copyId) throw new Error("HyperKey seed custody adapter is scoped to one Copy"); }
}

class PersistentPrivateDeliveryOutbox implements HyperKeyPrivateDeliveryOutboxPort {
  constructor(private readonly state: HyperKeyDeviceState, private readonly descriptorId: string, private readonly copyId: string) {}
  async read(deliveryId: string): Promise<HyperKeyPrivateDeliveryOutboxRecord | undefined> {
    const key = await recordKey("delivery", productLocator(this.descriptorId, this.copyId) + "\u0000" + deliveryId);
    return this.state.read<HyperKeyPrivateDeliveryOutboxRecord>("delivery", key);
  }
  async storeFirst(record: HyperKeyPrivateDeliveryOutboxRecord): Promise<HyperKeyPrivateDeliveryOutboxRecord> {
    if (record.descriptorId !== this.descriptorId || record.senderCopyId !== this.copyId) throw new Error("Private-delivery outbox is scoped to its sender Copy");
    const locator = productLocator(this.descriptorId, this.copyId);
    const [key, productKey] = await Promise.all([recordKey("delivery", locator + "\u0000" + record.deliveryId), recordKey("product", locator)]);
    return this.state.transaction([keyFor("delivery", key), keyFor("product", productKey)], records => {
      const product = records.get(keyFor("product", productKey)) as StoredHyperKeyProduct | undefined;
      if (!product || product.readiness.status !== "ready") throw new HyperKeyCopyUnavailableError(product?.readiness.status === "forgotten" ? "forgotten" : "not-ready");
      const previous = records.get(keyFor("delivery", key)) as HyperKeyPrivateDeliveryOutboxRecord | undefined;
      if (previous && JSON.stringify(previous) !== JSON.stringify(record)) throw new Error("Private delivery ID already contains different bytes");
      if (!previous) records.set(keyFor("delivery", key), structuredClone(record));
      return structuredClone(previous ?? record);
    });
  }
}

class PersistentCopyAdmissionRecords implements HyperKeyCopyAdmissionRecordStore {
  constructor(private readonly state: HyperKeyDeviceState) {}
  async put(record: HyperKeyCopyAdmissionRecord): Promise<void> {
    if (!record || !identifier(record.admissionId) || !identifier(record.groupId) || record.profile !== HYPERKEY_GROUP_PROFILE) throw new Error("HyperKey Copy admission record is invalid");
    const key = await recordKey("admission", record.admissionId);
    await this.state.transaction([keyFor("admission", key)], records => {
      const current = records.get(keyFor("admission", key)) as HyperKeyCopyAdmissionRecord | undefined;
      if (current && JSON.stringify(jsonValue(current)) !== JSON.stringify(jsonValue(record))) throw new Error("HyperKey Copy admission record conflicts");
      records.set(keyFor("admission", key), structuredClone(record));
    });
  }
  async get(admissionId: string): Promise<HyperKeyCopyAdmissionRecord | undefined> {
    if (!identifier(admissionId)) throw new Error("HyperKey Copy admission ID is invalid");
    const key = await recordKey("admission", admissionId);
    return this.state.read<HyperKeyCopyAdmissionRecord>("admission", key);
  }
}

interface ProductIndex { readonly schema: "hyperkey.product-index.v1"; readonly entries: readonly { readonly descriptorId: string; readonly copyId: string }[]; }
function assertIndex(value: ProductIndex): void {
  if (!value || value.schema !== "hyperkey.product-index.v1" || !Array.isArray(value.entries) || value.entries.length > 256 || value.entries.some(entry => !entry || !identifier(entry.descriptorId) || !identifier(entry.copyId))) throw new Error("HyperKey product index is invalid");
  if (new Set(value.entries.map(entry => `${entry.descriptorId}:${entry.copyId}`)).size !== value.entries.length) throw new Error("HyperKey product index has duplicates");
}
function appendIndex(records: Map<string, unknown>, key: string, descriptorId: string, copyId: string): void {
  const index = records.get(keyFor("index", key)) as ProductIndex | undefined ?? { schema: "hyperkey.product-index.v1", entries: [] };
  assertIndex(index);
  if (!index.entries.some(entry => entry.descriptorId === descriptorId && entry.copyId === copyId)) records.set(keyFor("index", key), { schema: "hyperkey.product-index.v1", entries: [...index.entries, { descriptorId, copyId }].sort(compareIndex) });
}
function assertProduct(value: StoredHyperKeyProduct, descriptorId: string, copyId: string): void {
  if (!value || value.schema !== "hyperkey.product-state.v1") throw new Error("HyperKey product record is invalid");
  assertHyperKeyDescriptor(value.descriptor); assertReadiness(value.readiness, descriptorId, copyId);
  if (value.readiness.groupId !== value.descriptor.groupId || value.readiness.receipt && value.readiness.receipt.seedPublicKey !== value.descriptor.publicKey) throw new Error("HyperKey product record binding differs");
}
function assertReadiness(value: HyperKeyCopyReadiness, descriptorId: string, copyId: string): void {
  if (!value || value.descriptorId !== descriptorId || value.copyId !== copyId || !identifier(value.groupId) || (value.status !== "ready" && value.status !== "forgotten")) throw new Error("HyperKey readiness record is invalid");
  if (value.status === "ready" && (!value.receipt || value.receipt.schema !== "hyperkey.installation-receipt.v1" || value.receipt.profile !== HYPERKEY_GROUP_PROFILE || value.receipt.descriptorId !== descriptorId || value.receipt.copyId !== copyId || value.receipt.groupId !== value.groupId)) throw new Error("Ready HyperKey record lacks a valid installation receipt");
  if (value.status === "forgotten" && value.receipt !== undefined) throw new Error("Forgotten HyperKey record retains a receipt");
}
function identifier(value: unknown): value is string { return typeof value === "string" && value.length > 0 && encoder.encode(value).length <= 256; }
function productLocator(descriptorId: string, copyId: string): string { if (!identifier(descriptorId) || !identifier(copyId)) throw new Error("HyperKey record identifier is invalid"); return `${descriptorId}\u0000${copyId}`; }
function compareIndex(left: { readonly descriptorId: string; readonly copyId: string }, right: { readonly descriptorId: string; readonly copyId: string }): number { return left.descriptorId.localeCompare(right.descriptorId) || left.copyId.localeCompare(right.copyId); }
function keyFor(kind: RecordKind, key: string): string { return `hyperkey/${kind}/v1/${key}`; }
function kindFromKey(key: string): RecordKind { const kind = key.split("/")[1]; if (kind === "group" || kind === "product" || kind === "custody" || kind === "index" || kind === "admission" || kind === "delivery" || kind === "candidate" || kind === "progress" || kind === "native" || kind === "native-outbox" || kind === "native-transition") return kind; throw new Error("HyperKey state key is invalid"); }
function rawKey(key: string): string { const prefix = `hyperkey/${kindFromKey(key)}/v1/`; if (!key.startsWith(prefix)) throw new Error("HyperKey state key is invalid"); return key.slice(prefix.length); }
function purpose(kind: RecordKind): string { return kind === "group" || kind === "native" || kind === "native-outbox" ? GROUP_PURPOSE : kind === "custody" || kind === "candidate" ? CUSTODY_PURPOSE : PRODUCT_PURPOSE; }
function associatedData(kind: RecordKind, key: string): Uint8Array { return encoder.encode(JSON.stringify(["hyperkey.device-state.v1", kind, key])); }
async function recordKey(kind: RecordKind, value: string): Promise<string> { const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(`${kind}\u0000${value}`))); return base64url(digest); }
function base64url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}
function jsonValue(value: unknown): unknown {
  if (value instanceof Uint8Array) return { $hyperkeyBytes: base64url(value) };
  if (Array.isArray(value)) return value.map(jsonValue);
  if (!value || typeof value !== "object") return value;
  return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, child]) => [key, jsonValue(child)]));
}
function restoreJsonValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(restoreJsonValue);
  if (!value || typeof value !== "object") return value;
  const record = value as Record<string, unknown>, keys = Object.keys(record);
  if (keys.some(key => key.startsWith("$") && key !== "$hyperkeyBytes")) throw new Error("Unknown byte encoding is rejected");
  if (keys.length === 1 && typeof record.$hyperkeyBytes === "string") return fromBase64url(record.$hyperkeyBytes);
  return Object.fromEntries(keys.map(key => [key, restoreJsonValue(record[key])]));
}
function fromBase64url(value: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/u.test(value) || value.length % 4 === 1) throw new Error("HyperKey state bytes are invalid");
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  const binary = atob(padded), bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

interface PreparedNativeTransition {
  readonly entries: readonly string[];
  readonly nativeKey: string;
  readonly transitionKey: string;
  readonly digest: string;
  readonly outbox: readonly { key: string; value: import("@group-foundation/group-core").NativeGroupOutboxRecord }[];
}

function nativeLocator(groupId: string, member: MemberIdentity): string {
  if (!identifier(groupId) || !identifier(member.signingKeyFingerprint)) throw new Error("Native Group scope is invalid");
  return `${groupId}\u0000${member.signingKeyFingerprint}`;
}

async function prepareNativeTransition(transition: StagedNativeGroupTransition): Promise<PreparedNativeTransition> {
  assertStagedNativeGroupTransition(transition);
  if (transition.next.profile !== HYPERKEY_GROUP_PROFILE) throw new Error("Native Group profile is not the pinned HyperKey profile");
  if (transition.outbox.length > 128) throw new Error("Native Group outbox exceeds its transaction bound");
  const scope = nativeLocator(transition.next.groupId, transition.next.member);
  const [native, receipt, digest] = await Promise.all([
    recordKey("native", scope),
    recordKey("native-transition", scope + "\u0000" + transition.transitionId),
    crypto.subtle.digest("SHA-256", encoder.encode(JSON.stringify(jsonValue(transition)))).then(value => base64url(new Uint8Array(value))),
  ]);
  const outbox = await Promise.all(transition.outbox.map(async value => {
    const digest = base64url(new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(value.bytes))));
    if (digest !== value.digest) throw new Error("Native Group outbox digest differs from its bytes");
    return { key: keyFor("native-outbox", await recordKey("native-outbox", scope + "\u0000" + value.id)), value };
  }));
  const nativeKey = keyFor("native", native), transitionKey = keyFor("native-transition", receipt);
  return { entries: [nativeKey, transitionKey, ...outbox.map(value => value.key)], nativeKey, transitionKey, digest, outbox };
}

function applyNativeTransition(records: Map<string, unknown>, transition: StagedNativeGroupTransition, prepared: PreparedNativeTransition): Readonly<{ state: NativeGroupState; replayed: boolean }> {
  const previousReceipt = records.get(prepared.transitionKey) as { digest: string } | undefined;
  const current = records.get(prepared.nativeKey) as NativeGroupState | undefined;
  if (previousReceipt) {
    if (previousReceipt.digest !== prepared.digest || !current) throw new Error("Native Group transition retry differs from its durable receipt");
    return { state: structuredClone(current), replayed: true };
  }
  if (transition.expectedRevision === null ? current !== undefined : current?.revision !== transition.expectedRevision) throw new Error("Native Group transition lost its predecessor");
  if (current && (current.groupId !== transition.next.groupId || current.profile !== transition.next.profile || current.member.signingKeyFingerprint !== transition.next.member.signingKeyFingerprint)) throw new Error("Native Group transition scope changed");
  for (const outbox of prepared.outbox) {
    const previous = records.get(outbox.key);
    if (previous && JSON.stringify(jsonValue(previous)) !== JSON.stringify(jsonValue(outbox.value))) throw new Error("Native Group outbox ID already contains different bytes");
    records.set(outbox.key, structuredClone(outbox.value));
  }
  records.set(prepared.nativeKey, structuredClone(transition.next));
  records.set(prepared.transitionKey, { schema: "hyperkey.native-transition-receipt.v1", digest: prepared.digest, revision: transition.next.revision });
  return { state: structuredClone(transition.next), replayed: false };
}
