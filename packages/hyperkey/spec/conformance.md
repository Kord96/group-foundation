# HyperKey v1 conformance

The ownership contract is [foundation-contract-v1.md](../../../docs/architecture/foundation-contract-v1.md).
[v1-vectors.json](v1-vectors.json) freezes deterministic qualification-only seed,
public descriptor, descriptor ID, canonical descriptor bytes, admission Copy
binding, MLS application binding and conventional signature. Its known seed is a
fixture, and is not generated production custody.

Implementations must pass these behavioral checks:

1. Independent Copies retain distinct MLS fingerprints, KeyPackages and delivery
   keys while signing with the same descriptor's conventional key.
2. Admission and exact recipient installation precede first seed delivery.
   Changed scope, selected commit, recipient key, Copy identity or member fails.
3. Authentication binds direction, exact application frame, Group/profile,
   admitted sender and recipient, and every field in the delivery transcript.
4. Envelope, application, descriptor and admission namespace changes fail. The
   only accepted v1 namespace/profile is the frozen neutral one.
5. Sender retry returns the original durable ciphertext. Changed envelope bytes
   for the same ID fail. Receipt recovery requires no seed reinstall, MLS Add,
   Join, ratchet rewind or temporary delivery private key.
6. Founder, candidate, Group install, seed install and local forget each publish
   their complete staged effects atomically through the consumer transaction.
7. A failed physical commit leaves the entire previous state intact. An uncertain
   commit quiesces the old host. A new coordinator reads only committed state and
   recovers the exact result.
8. Forgotten Copies remain terminal across reload. Stale signing handles fail;
   current seed/candidate/native custody is gone and cannot be revived by delivery.
9. Plaintext record/index/outbox/transaction bounds fail before publication. Sealed
   record substitution across a different purpose or locator fails authentication.
10. Default authority/provider behavior rejects. Test authorities must be explicit.

`hyperkey.test.mjs` exercises authenticated delivery/custody.
`storage.test.mjs` exercises sealed host storage, failed and uncertain physical
commits, independence, candidate/ready state, namespace rejection and exact native
transition receipts. `admission-provider.test.mjs` uses the actual admission
runtime and policy adapters. `native-group-e2e.test.mjs` uses actual native MLS
with an explicitly permissive admission fixture; it does not qualify production
identity/governance policy. `conformance.test.mjs` checks frozen bytes.

The browser artifact independently qualifies native founder creation, IndexedDB
sealed custody, deterministic conventional signing after reload and terminal
local forgetting. It does not supply transport or production Copy authorities.
