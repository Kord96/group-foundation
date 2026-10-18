# Admission bootstrap v2

## Scope and ownership

The bootstrap subpath defines signed presentation bytes, an encrypted duplex session-message contract, and a durable exact-request handoff to `GroupAdmissionRuntime`. A presentation may be rendered as a QR code, copied, or carried by a product-selected channel.

Foundation owns the canonical schemas, protocol roles, message ordering, transcript binding, replay and expiry checks, and the bridge to the admission ledger. It does not render or scan QR codes, open network transports, resolve or display targets, identify devices, choose product policy, authorize an actor, or grant membership. Candidate evidence, actor authentication, governance, invitation capacity, MLS staging, admission decisions, and installation remain owned by `GroupAdmissionRuntime` and its injected ports.

Bootstrap roles are `admission-host` and `candidate`. They describe protocol direction only. They are not group roles or proof of authority.

## Signed presentation

Presentations use `group-foundation.admission.bootstrap.presentation.v2`.

| Mode | Presenter | Signed mode payload | Scanner action |
| --- | --- | --- | --- |
| `offer-target` | `admission-host` | Opaque target material | Candidate elects whether to continue |
| `request-membership` | `candidate` | Opaque candidate rendezvous material | Host selects a target over the encrypted channel |

Candidate-first presentation deliberately contains no `AdmissionRequest` and no target. A request is invalid until the admission host has selected a target, received candidate material, and accepted continuation. The exact canonical request is sent later as the final encrypted channel message.

Both modes bind `channelSuite` and `channelOffer`. The offer is public or encapsulation material for a reviewed product-provided secure-channel implementation. Private channel keys remain behind the crypto port. Foundation does not select or implement a key exchange or encryption algorithm.

The remaining common fields are `schema`, `mode`, `sessionId`, `presenterRole`, `createdAtMs`, `expiresAtMs`, `nonce`, signature `suite`, `verificationKey`, and `proof`. JSON keys are lexicographically sorted. Bytes use unpadded canonical base64url. Alternate whitespace, duplicate or extra fields, malformed UTF-8, alternate encodings, and predecessor schemas are rejected.

Expiry is exclusive. Authenticated inspection applies caller-selected maximum lifetime and future-clock allowance. The presentation signature uses domain `group-foundation.admission.bootstrap.presentation-proof.v2` and covers every presentation field except `proof`. The proof establishes possession of the displayed signing key and detects mutation. The product must still bind that key and opaque payloads to its identity and authorization model.

## Encrypted duplex channel

`BootstrapChannelCryptoPort` is the only encryption boundary. Its stable suite must equal the suite bound by the presentation. `seal` receives the recipient's bounded offer, canonical authenticated data, and canonical plaintext. `open` receives the same authenticated data and ciphertext. Implementations must use a reviewed authenticated-encryption or hybrid-encryption construction and keep private custody behind the opaque `localCustodyId`. Foundation never exposes a decrypt or arbitrary-signing primitive.

`BootstrapChannelTransportPort` sends exact encrypted envelope bytes. It intentionally does not define WebSockets, relays, polling, QR rendering, links, IPNS, or product discovery. Those are interchangeable carriers.

The scanner sends the first `peer-hello`, encrypted to the signed presentation offer. It includes the scanner's channel offer. The presenter decrypts it and returns its own hello. No other message is valid until both hellos have been recorded.

```text
scanner                         presenter
   | -- encrypted peer-hello ----> |
   | <--- encrypted peer-hello ---- |
   | <====== encrypted duplex =====> |
```

Each envelope binds the presentation SHA-256, session ID, sender role, strictly increasing per-sender sequence, send and expiry times, crypto suite, and previous ciphertext-envelope SHA-256. These fields are canonical authenticated data. Each direction has an independent hash chain whose initial value binds the presentation and sender role. A missing, duplicate, skipped, reordered, cross-session, cross-role, predecessor-changing, or post-expiry envelope is rejected. Products must serialize durable revision updates; transport retry re-sends the same retained envelope rather than emitting a new sequence.

The encrypted messages are:

| Message | Sender | Meaning |
| --- | --- | --- |
| `peer-hello` | scanner, then presenter | Establish the peer channel offer |
| `target-selection` | host | Choose the target in candidate-first mode |
| `candidate-payload` | candidate | Provide target-bound candidate material |
| `acceptance` | host | Permit construction of the exact request |
| `rejection` | host | End bootstrap without admission submission |
| `progress` | either | Report bounded product-defined progress |
| `admission-request` | candidate | Transfer one exact canonical `AdmissionRequest` and end channel messaging |

For `offer-target`, the signed target initializes the target binding and later `target-selection` is forbidden. For `request-membership`, the host must select the target after hello exchange. Candidate material requires a target. Acceptance requires target and candidate material. The final request requires acceptance. Rejection and final request handoff are terminal.

Foundation hashes target and candidate bytes in durable state rather than retaining plaintext. It retains the exact final request because the admission host must atomically hand those bytes to the admission ledger.

## Admission handoff

`handoffBootstrapChannelRequest` accepts only an admission-host channel with a completed exact request. The channel and `BootstrapSessionSnapshot` must bind the same session and presentation digest. It advances the admission snapshot from `open` to `request-ready` with those exact bytes.

The host must atomically persist the later `submitted` bootstrap transition with `GroupAdmissionRuntime.commitSubmission(transaction, exactRequest)`. The structural `MembershipSubmissionPort` matches that method while leaving the physical transaction generic. It must not be adapted to convenience `submit`, which would open a second transaction.

Once submitted, cancellation or denial belongs to `GroupAdmissionRuntime`; bootstrap cannot masquerade as the admission ledger. Admission completion may outlive presentation expiry because the exact durable handoff already occurred.

## Bounds and persistence

The protocol caps target and candidate material at 64 KiB each, channel offers at 16 KiB, canonical admission requests at 512 KiB, encrypted ciphertext at 640 KiB, signature keys at 8 KiB, proofs at 16 KiB, and outer wire at 768 KiB. These are parser bounds. A QR product must impose a much smaller renderer-compatible presentation bound.

`BootstrapSessionSnapshot` and `BootstrapChannelSnapshot` are portable persistence contracts, not storage engines. A host must enforce unique session IDs, compare-and-swap revisions, retain exact emitted envelopes for retry, and keep crypto custody independently. Renderability, connectivity, and product acceptance do not imply protocol validity or membership authority.
