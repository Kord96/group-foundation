/* tslint:disable */
/* eslint-disable */

export interface NativeGroupResult { snapshot: Uint8Array; groupId: Uint8Array; profile: Uint8Array; epoch: string; }
export interface NativeGroupKeyPackageResult { snapshot: Uint8Array; keyPackage: Uint8Array; memberId: Uint8Array; }
export interface NativeGroupAddResult extends NativeGroupResult { priorEpoch: string; commit: Uint8Array; welcome: Uint8Array; ratchetTree: Uint8Array; }
export interface NativeGroupCommitResult extends NativeGroupResult { priorEpoch: string; ratchetTree: Uint8Array; }
export interface NativeGroupRemoveResult extends NativeGroupCommitResult { commit: Uint8Array; }
export interface NativeGroupSealResult extends NativeGroupResult { message: Uint8Array; }
export interface NativeGroupOpenResult extends NativeGroupResult { sender: Uint8Array; plaintext: Uint8Array; }
export interface NativeMemberProofResult { signingKey: Uint8Array; signature: Uint8Array; }



export interface ProductLimits { maxPastEpochs: number; outOfOrderTolerance: number; maxForwardDistance: number; }
/** Exact MLS TLS encodings, interpreted only by OpenMLS. */
export interface ProductProfile extends ProductLimits { capabilities: Uint8Array; contextExtensions: Uint8Array; leafExtensions: Uint8Array; }
export interface ProductMember { leaf: number; signingKey: Uint8Array; credential: Uint8Array; components: Uint8Array; leafNode: Uint8Array; }
export interface ProductProposal { proposal: Uint8Array; origin: 'inline' | 'reference'; reference?: Uint8Array; sender: Uint8Array; }
export interface ProductProjection { groupId: Uint8Array; epoch: string; active: boolean; ownLeaf: number; members: ProductMember[]; components: Uint8Array; context: Uint8Array; ratchetTree: Uint8Array; pendingProposals: ProductProposal[]; }
export interface ProductStage { custody: Uint8Array; projection: ProductProjection; }
export interface ProductKeyPackageStage { custody: Uint8Array; keyPackage: Uint8Array; reference: Uint8Array; leafNode: Uint8Array; }
export interface ProductComponentUpdate { id: number; value: Uint8Array | null; }
export interface ProductCommitRequest { additions: Uint8Array[]; removals: number[]; componentUpdates: ProductComponentUpdate[]; proposalReferences?: Uint8Array[]; }
export interface ProductCommitStage extends ProductStage { commit: Uint8Array; welcome?: Uint8Array; pendingCustody: Uint8Array; }
export interface ProductSignerHandoverCandidate { signingState: Uint8Array; signingKey: Uint8Array; }
export interface ProductSignerHandoverStage extends ProductStage { commit: Uint8Array; predecessorSigningKey: Uint8Array; successorSigningKey: Uint8Array; }
export interface ProductMessageStage extends ProductStage { kind: 'commit' | 'proposal' | 'application'; sender: Uint8Array; credential: Uint8Array; aad: Uint8Array; messageEpoch: string; componentUpdates: ProductComponentUpdate[]; proposals: ProductProposal[]; plaintext?: Uint8Array; resultingContext?: Uint8Array; selfRemoved?: boolean; }
export interface ProductFrameStage extends ProductStage { frame: Uint8Array; }
export interface ProductRecord { key: Uint8Array; value: Uint8Array | null; }
export interface ProductSignerProof { signingKey: Uint8Array; signature: Uint8Array; }



/**
 * Validated product authority facts.  Revisions and expiry are supplied
 * by the product; Group only fences them across MLS transitions.
 */
export class NativeAuthorityFacts {
    free(): void;
    [Symbol.dispose](): void;
    constructor(identity_revision: bigint, identity_valid_until: bigint, governance_revision: bigint, governance_valid_until: bigint);
}

/**
 * One independent local MLS client and its in-memory provider.  It never
 * opens a database. `export_snapshot` is the only persistence boundary.
 */
export class NativeClient {
    free(): void;
    [Symbol.dispose](): void;
    createGroup(group_id: Uint8Array, profile: Uint8Array, authority: NativeAuthorityFacts, now: bigint): NativeGroupResult;
    createKeyPackage(profile: Uint8Array): NativeGroupKeyPackageResult;
    exportSnapshot(): Uint8Array;
    /**
     * Restores only a snapshot previously emitted by this ABI.  The
     * caller is responsible for authenticating and atomically storing it.
     */
    static fromSnapshot(snapshot: Uint8Array): NativeClient;
    memberId(): Uint8Array;
    constructor(evidence: Uint8Array);
    /**
     * Signs a Group-domain transcript with this Copy's existing MLS key.
     * This does not expose the key or change the MLS ratchet.
     */
    signMemberProof(transcript: Uint8Array): NativeMemberProofResult;
    /**
     * Builds an Add on a copied provider. The returned snapshot is the
     * only advanced founder state; this client remains unchanged.
     */
    stageAdd(group_id: Uint8Array, profile: Uint8Array, key_package: Uint8Array, authority: NativeAuthorityFacts, now: bigint): NativeGroupAddResult;
    stageApplyCommit(group_id: Uint8Array, profile: Uint8Array, commit: Uint8Array, authority: NativeAuthorityFacts, now: bigint): NativeGroupCommitResult;
    stageJoin(group_id: Uint8Array, profile: Uint8Array, welcome: Uint8Array, ratchet_tree: Uint8Array, authority: NativeAuthorityFacts, now: bigint): NativeGroupResult;
    stageOpenApplication(group_id: Uint8Array, profile: Uint8Array, message: Uint8Array): NativeGroupOpenResult;
    stageRemove(group_id: Uint8Array, profile: Uint8Array, target: Uint8Array, authority: NativeAuthorityFacts, now: bigint): NativeGroupRemoveResult;
    stageSealApplication(group_id: Uint8Array, profile: Uint8Array, plaintext: Uint8Array, authority: NativeAuthorityFacts, now: bigint): NativeGroupSealResult;
}

/**
 * Independently generated MLS signing custody plus a bounded in-memory provider.
 * Callers seal exported custody and atomically install it with product sidecars.
 */
export class NativeProductClient {
    free(): void;
    [Symbol.dispose](): void;
    exportCustody(): Uint8Array;
    exportProviderState(): Uint8Array;
    exportSecret(group_id: Uint8Array, label: string, context: Uint8Array, length: number): Uint8Array;
    exportSigningState(): Uint8Array;
    static fromCustody(custody: Uint8Array): NativeProductClient;
    static fromParts(provider_state: Uint8Array, signing_state: Uint8Array): NativeProductClient;
    /**
     * Distinguishes a deleted group from an installed inactive group. Invalid
     * IDs, malformed native state, and active signer mismatches still fail.
     */
    hasGroup(group_id: Uint8Array): boolean;
    inspect(group_id: Uint8Array): ProductProjection;
    constructor();
    ownSigner(): Uint8Array;
    /**
     * Generate an independent successor signer without changing this custody.
     * The opaque signing state must be durably retained by the host while the
     * product authorizes the exact public successor key.
     */
    prepareSignerHandover(): ProductSignerHandoverCandidate;
    readRecord(key: Uint8Array): Uint8Array | undefined;
    signProof(transcript: Uint8Array): ProductSignerProof;
    /**
     * Installs only the selected group's native records and exact product keys.
     * Foreign mutations and signing custody substitutions are rejected.
     */
    stageCheckpoint(anchor: Uint8Array, selected: Uint8Array, group_id: Uint8Array, sidecar_keys: Uint8Array[]): Uint8Array;
    /**
     * Returns both the exact pending custody and its merged candidate. Neither is installed.
     */
    stageCommit(group_id: Uint8Array, request: ProductCommitRequest, aad: Uint8Array): ProductCommitStage;
    /**
     * Credential is an exact MLS Credential TLS encoding, never private key material.
     */
    stageCreate(group_id: Uint8Array, credential: Uint8Array, config: ProductProfile): ProductStage;
    /**
     * Returns custody with only the selected group's native state removed.
     * Product sidecar deletion is staged separately with exact record keys.
     */
    stageDelete(group_id: Uint8Array): Uint8Array;
    stageJoin(welcome: Uint8Array, config: ProductLimits): ProductStage;
    stageKeyPackage(credential: Uint8Array, config: ProductProfile): ProductKeyPackageStage;
    stageMergePending(group_id: Uint8Array): ProductStage;
    /**
     * Mode is member, application, or ownCommit. Component updates and proposal
     * facts are returned only after full MLS authentication. ownCommit verifies
     * against the public parent and returns no advanced private ratchet state.
     */
    stageProcess(group_id: Uint8Array, frame: Uint8Array, mode: 'member' | 'application' | 'ownCommit'): ProductMessageStage;
    /**
     * Sidecar changes share the same opaque custody checkpoint as MLS state.
     */
    stageRecords(records: ProductRecord[]): Uint8Array;
    stageSeal(group_id: Uint8Array, plaintext: Uint8Array, aad: Uint8Array): ProductFrameStage;
    stageSelfRemove(group_id: Uint8Array, aad: Uint8Array): ProductFrameStage;
    /**
     * Produce one self-update that replaces this client's active local MLS
     * signer. The source is unchanged. The result contains only successor
     * custody; the predecessor signer is deleted from its provider state.
     */
    stageSignerHandover(group_id: Uint8Array, successor_signing_state: Uint8Array, credential: Uint8Array, aad: Uint8Array): ProductSignerHandoverStage;
}

export function member_fingerprint(signing_key: Uint8Array): Uint8Array;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_nativeauthorityfacts_free: (a: number, b: number) => void;
    readonly __wbg_nativeclient_free: (a: number, b: number) => void;
    readonly member_fingerprint: (a: number, b: number) => [number, number, number, number];
    readonly nativeauthorityfacts_new: (a: bigint, b: bigint, c: bigint, d: bigint) => number;
    readonly nativeclient_createGroup: (a: number, b: number, c: number, d: number, e: number, f: number, g: bigint) => [number, number, number];
    readonly nativeclient_createKeyPackage: (a: number, b: number, c: number) => [number, number, number];
    readonly nativeclient_exportSnapshot: (a: number) => [number, number, number, number];
    readonly nativeclient_fromSnapshot: (a: number, b: number) => [number, number, number];
    readonly nativeclient_memberId: (a: number) => [number, number];
    readonly nativeclient_new: (a: number, b: number) => [number, number, number];
    readonly nativeclient_signMemberProof: (a: number, b: number, c: number) => [number, number, number];
    readonly nativeclient_stageAdd: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint) => [number, number, number];
    readonly nativeclient_stageApplyCommit: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint) => [number, number, number];
    readonly nativeclient_stageJoin: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number, j: number, k: bigint) => [number, number, number];
    readonly nativeclient_stageOpenApplication: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly nativeclient_stageRemove: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint) => [number, number, number];
    readonly nativeclient_stageSealApplication: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: bigint) => [number, number, number];
    readonly __wbg_nativeproductclient_free: (a: number, b: number) => void;
    readonly nativeproductclient_exportCustody: (a: number) => [number, number, number, number];
    readonly nativeproductclient_exportProviderState: (a: number) => [number, number, number, number];
    readonly nativeproductclient_exportSecret: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly nativeproductclient_exportSigningState: (a: number) => [number, number];
    readonly nativeproductclient_fromCustody: (a: number, b: number) => [number, number, number];
    readonly nativeproductclient_fromParts: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly nativeproductclient_hasGroup: (a: number, b: number, c: number) => [number, number, number];
    readonly nativeproductclient_inspect: (a: number, b: number, c: number) => [number, number, number];
    readonly nativeproductclient_new: () => [number, number, number];
    readonly nativeproductclient_ownSigner: (a: number) => [number, number];
    readonly nativeproductclient_prepareSignerHandover: (a: number) => [number, number, number];
    readonly nativeproductclient_readRecord: (a: number, b: number, c: number) => [number, number, number, number];
    readonly nativeproductclient_signProof: (a: number, b: number, c: number) => [number, number, number];
    readonly nativeproductclient_stageCheckpoint: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: any) => [number, number, number, number];
    readonly nativeproductclient_stageCommit: (a: number, b: number, c: number, d: any, e: number, f: number) => [number, number, number];
    readonly nativeproductclient_stageCreate: (a: number, b: number, c: number, d: number, e: number, f: any) => [number, number, number];
    readonly nativeproductclient_stageDelete: (a: number, b: number, c: number) => [number, number, number, number];
    readonly nativeproductclient_stageJoin: (a: number, b: number, c: number, d: any) => [number, number, number];
    readonly nativeproductclient_stageKeyPackage: (a: number, b: number, c: number, d: any) => [number, number, number];
    readonly nativeproductclient_stageMergePending: (a: number, b: number, c: number) => [number, number, number];
    readonly nativeproductclient_stageProcess: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly nativeproductclient_stageRecords: (a: number, b: any) => [number, number, number, number];
    readonly nativeproductclient_stageSeal: (a: number, b: number, c: number, d: number, e: number, f: number, g: number) => [number, number, number];
    readonly nativeproductclient_stageSelfRemove: (a: number, b: number, c: number, d: number, e: number) => [number, number, number];
    readonly nativeproductclient_stageSignerHandover: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number, i: number) => [number, number, number];
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput }): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> }): Promise<InitOutput>;
