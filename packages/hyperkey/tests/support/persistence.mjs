/** Qualification-only consumer store with atomic, serialized physical writes. */
export class MemoryPhysicalStore {
  records = new Map();
  tail = Promise.resolve();
  failure;
  uncertain;
  semanticRevision = 0;
  async read(keys) {
    await this.tail;
    return new Map(keys.filter(key => this.records.has(key)).map(key => [key, new Uint8Array(this.records.get(key))]));
  }
  async transact(keys, operation) {
    const pending = this.tail.then(async () => {
      const staged = new Map(keys.filter(key => this.records.has(key)).map(key => [key, new Uint8Array(this.records.get(key))]));
      const result = await operation(staged);
      if (this.failure) throw new Error("injected physical failure");
      for (const key of keys) {
        if (staged.has(key)) this.records.set(key, new Uint8Array(staged.get(key)));
        else this.records.delete(key);
      }
      this.semanticRevision++;
      if (this.uncertain) throw this.uncertain;
      return result;
    });
    this.tail = pending.then(() => undefined, () => undefined);
    return pending;
  }
}

/** Separate nonexportable key for every sealing purpose, retained across reopen. */
export class MemorySealing {
  keys = new Map();
  opened = [];
  async key(purpose) {
    if (!this.keys.has(purpose)) this.keys.set(purpose, crypto.subtle.generateKey({name:"AES-GCM",length:256}, false, ["encrypt","decrypt"]));
    return this.keys.get(purpose);
  }
  async seal(purpose, plaintext, aad) {
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name:"AES-GCM",iv:nonce,additionalData:aad},await this.key(purpose),plaintext));
    return new Uint8Array([...nonce,...ciphertext]);
  }
  async open(purpose, sealed, aad) {
    const result = new Uint8Array(await crypto.subtle.decrypt({name:"AES-GCM",iv:sealed.slice(0,12),additionalData:aad},await this.key(purpose),sealed.slice(12)));
    this.opened.push(result);
    return result;
  }
}
export const commitOutcome = { isUncertain: cause => cause?.code === "unknown-physical-commit" };
