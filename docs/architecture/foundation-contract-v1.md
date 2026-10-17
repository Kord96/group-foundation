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
  installation receipts. Candidate verification and authorization are injected
  through ports.
- `@group-foundation/hyperkey` owns a logical conventional Ed25519 key, its
  immutable descriptor, independently admitted Copies, private seed delivery,
  and Copy workflow. It depends only on the two Foundation packages.

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
- Initial published packages are `0.1.0` and are pinned immutably by consumers.
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
