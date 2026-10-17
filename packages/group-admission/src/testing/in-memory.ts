import type { AdmissionLedger, AdmissionTransaction, TransactionCompositionPort } from "../admission.js";
import type { AdmissionOutboxRecord, DeliveryPort, StagedSelection } from "../contracts.js";

/** Test-only serializable host writer, including rollback of composed opaque custody. Not production storage. */
export class InMemoryAdmissionTransactions<Custody> implements TransactionCompositionPort<Custody> {
  private ledger: AdmissionLedger;
  private custody: Custody;
  private writer = Promise.resolve();
  loseNextCommitReply = false;
  constructor(ledger: AdmissionLedger, custody: Custody, private readonly compose: (current: Custody, staged: StagedSelection<Custody>) => Promise<Custody>) {
    this.ledger = structuredClone(ledger); this.custody = structuredClone(custody);
  }
  async read(): Promise<AdmissionLedger> { return structuredClone(this.ledger); }
  async readCustody(): Promise<Custody> { return structuredClone(this.custody); }
  async transact<T>(operation: (transaction: AdmissionTransaction<Custody>) => Promise<T>): Promise<T> {
    const previous = this.writer; let release!: () => void;
    this.writer = new Promise<void>(resolve => { release = resolve; }); await previous;
    try {
      const ledger = structuredClone(this.ledger); let custody = structuredClone(this.custody), composed = false;
      const result = await operation({ ledger, stageCustody: async stage => { custody = await this.compose(custody, structuredClone(stage)); composed = true; } });
      this.ledger = structuredClone(ledger); this.custody = structuredClone(custody);
      if (composed && this.loseNextCommitReply) { this.loseNextCommitReply = false; throw new Error("physical commit reply lost"); }
      return structuredClone(result) as T;
    } finally { release(); }
  }
}
export class RecordingDelivery implements DeliveryPort {
  readonly records: AdmissionOutboxRecord[] = [];
  fail = false;
  async publish(record: AdmissionOutboxRecord): Promise<void> { if (this.fail) throw new Error("delivery unavailable"); this.records.push(structuredClone(record)); }
}
