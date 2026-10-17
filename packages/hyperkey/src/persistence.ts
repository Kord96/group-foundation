/** Sealed bytes only. The consumer owns encryption keys and durable storage. */
export interface HyperKeyPersistencePort {
  read(keys: readonly string[]): Promise<ReadonlyMap<string, Uint8Array>>;
  /**
   * The consumer runs one physical transaction spanning these records and its
   * own semantic state/outbox. Missing entries are absent from the map. Publish
   * all map changes atomically, with conflict detection and writer fencing.
   * Do not retry the callback after it has run; retry the complete operation.
   * Do not return until the commit outcome is known or reported as uncertain.
   */
  transact<T>(keys: readonly string[], operation: (sealedRecords: Map<string, Uint8Array>) => Promise<T>): Promise<T>;
}

/** Device sealing is independent of the conventional seed and MLS credentials. */
export interface HyperKeySealingPort {
  seal(purpose: string, plaintext: Uint8Array, associatedData: Uint8Array): Promise<Uint8Array>;
  open(purpose: string, sealed: Uint8Array, associatedData: Uint8Array): Promise<Uint8Array>;
}

/** Consumer-specific errors are classified without importing consumer classes. */
export interface HyperKeyCommitOutcomePort {
  isUncertain(cause: unknown): boolean;
}
