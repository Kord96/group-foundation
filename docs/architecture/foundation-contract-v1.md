# Group Foundation v1 ownership contract

## Purpose

Group Foundation provides portable MLS group mechanics, generic group admission,
and logical-key Copy mechanics. It has no runtime dependency on Zagel, Hafez, or
a transport, database, identity service, profile, or UI.

## Packages

- `@group-foundation/group-core` owns MLS custody, staged transitions, member
  credentials, authenticated opaque application frames, canonical primitives,
  the Rust/WASM engine, and conformance vectors.
- `@group-foundation/group-admission` owns generic invitations, candidate
  requests, reservations, approvals, add/remove selection, publication and
  installation receipts, plus signed bootstrap presentation and local handoff
  state. Candidate verification and authorization are injected through ports;
  QR rendering, cameras, transports, and product policy remain consumers.
- `@group-foundation/hyperkey` owns a logical conventional Ed25519 key, its
  immutable descriptor, independently admitted Copies, private seed delivery,
  and Copy workflow. It depends only on the two Foundation packages.

Generic claim policy, evidence requests and verifier orchestration belong to
standalone `@kord96/bouncer@0.1.0`, outside this repository and release closure.
Bouncer checks requirements satisfaction, never membership or session permission.
Registrar enforces configured requirements through Bouncer; IdV supplies evidence,
Authorizer checks operations, and the consumer owner commits effects. Foundation
admission uses its existing injected verification/authorization ports and has no
Bouncer dependency. Bootstrap presentation, QR carrier ownership, and local
handoff behavior are unchanged.

## Ownership exclusions

Foundation does not own Room aliases, roles, policy, Room invitation delivery,
mailboxes, history, calls, forwarding, account authority, devices, recovery,
profiles, databases, physical transaction writers, or application UI.

Each consumer commits its semantic state, Foundation custody, and its outbox in
one physical transaction. Foundation returns validated staged effects and never
opens a persistence writer of its own.

## Stable dependency direction

```text
group-core <- group-admission
group-core <- hyperkey -> group-admission
```

Zagel and future consumers depend downward on these packages. Foundation never
imports a consumer package. HyperKey is not a Zagel runtime dependency.

## Version-one migration rules

- Clean break: no aliases, old-schema readers, workspace links, or fallback
  imports in Zagel.
- New neutral protocol/schema namespaces are `group-foundation.*` and
  `hyperkey.*`; preview data is reset and predecessor values are rejected.
- Consumers pin one immutable, version-aligned Foundation release closure. The
  initial closure was `0.1.0`; the admission-bootstrap v2 clean break is `0.2.0`.
  Historical `0.4.0` closures included `@group-foundation/bouncer`; their
  receipts remain unchanged. The maintained Foundation closure now has three
  npm packages; standalone Bouncer is independently pinned and qualified.
- Standalone Bouncer uses `bouncer.*.v1` domains as an explicit clean break.
  Retained old receipts must not be adopted or relabeled. Consumer/domain
  migration belongs to Root and requires reviewed migration or explicit fresh
  test state; there is no old-owner alias, fork, or fallback source import.
- The current MLS/OpenMLS/toolchain versions are preserved until a separately
  reviewed compatibility migration.
- The current Zagel BFU remains in Zagel.

## Release qualification

`pnpm qualify:release` is the required Foundation release gate. It verifies the
package DAG and production imports, runs the native and browser suites, rebuilds
WASM into isolated output and compares every byte with tracked assets, exercises
packed npm packages from an external consumer, and verifies the packaged Cargo
crate. The command records hashes and tool versions without changing tracked
artifacts. See [release qualification](../release-qualification.md).
