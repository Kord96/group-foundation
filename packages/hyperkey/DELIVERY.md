# HyperKey private delivery

The conventional Ed25519 seed is separate from MLS credentials, ratchets,
KeyPackages, candidate evidence, device sealing keys and admission authority.
An admitted Copy receives this one seed through X25519, HKDF-SHA256 and AES-GCM.
The immutable descriptor public key is checked after decryption.

`HyperKeyApplicationDeliveryBoundary.authenticateForSend` requires the sender's
already committed staged MLS sealing result, its local identity and exact frame
in the durable outbox. `authenticateForReceive` requires the recipient's already
committed staged receive result and its local identity. The trusted integration
verifies the exact canonical plaintext and sender, opens the latest durable
ratchet, and commits the advanced state before returning. The boundary checks
Group/profile and the admitted sender/recipient Copy directory and delivery key.
It never authenticates a send by opening a recipient snapshot.

The canonical binding contains descriptor ID, Group ID, pinned profile, sender
Copy, recipient Copy, recipient delivery key, admission ID, selected commit ID and
delivery ID. The MLS application transcript, envelope AAD, sender outbox and
recipient installation receipt retain that binding. Outbox/receipt also retain
the authenticated MLS member fingerprints. A runtime WeakSet rejects invented
objects claiming to be authenticated delivery results.

The concrete admission provider uses the generic runtime's selected Add and
installation authentication. The supplied recipient proof must sign the generic
installation transcript including operation ID, scope, selected wire hash,
successor, recipient fingerprint and exact `installedAtMs`. Actor proofs for
approval and physical Add remain separate operation-bound inputs. The provider
never treats an arbitrary ACK as proof.

`storeFirst` atomically retains the exact first encrypted envelope for a delivery
ID. Changed bytes fail. Exact installation retries read the ready receipt and
custody-presence record before decryption; they require no temporary delivery
private key and perform no second seed installation. A consumed application frame
must recover durable authentication metadata. Never rewind an old recipient MLS
snapshot to authenticate it again.

All HyperKey schemas and transcript domains begin with `hyperkey.`. Persisted
record keys begin with `hyperkey/`; sealing purposes begin with `hyperkey-`.
Native-core schemas remain `group-foundation.group.*`; generic admission schemas
remain `group-foundation.admission.*`. Predecessor descriptors, deliveries,
receipts, Copy progress, product records and encoded byte tags are rejected.
There are no compatibility aliases or old-schema readers.
