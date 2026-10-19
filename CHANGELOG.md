# Changelog

## Unreleased

- Add a detached native MLS signer-handover primitive. It prepares an opaque
  successor key, stages the predecessor-authenticated self-update, returns
  successor-only custody, and leaves product policy plus atomic configuration
  installation with the consuming host.

## 0.3.0

- Add the standalone `@group-foundation/admission-guard` package for canonical
  claim policies, request-bound signed evidence, and exact disclosure checks.
  It has no runtime dependencies and is independent of group admission.
- Qualify all four npm packages and the Rust crate as one version-aligned
  `0.3.0` release closure. This preserves the immutable `0.2.0` closure, which
  did not include admission guard.

## 0.2.0

- Add the clean-break `group-foundation.admission.bootstrap.presentation.v2`
  presentation for host-first and candidate-first admission.
- Add a transport-independent encrypted duplex bootstrap state machine through
  injected crypto and carrier ports, with transcript chains, expiry, replay
  rejection, durable retry, and exact canonical request handoff.
- Add `GroupAdmissionRuntime.commitSubmission` so a product can atomically
  commit its bootstrap handoff and the admission submission in one physical
  transaction.
- Publish the three npm packages and the Rust crate as one version-aligned
  `0.2.0` release closure. The v2 bootstrap wire has no v1 compatibility path.

## 0.1.0

- Initial release of portable MLS custody, generic admission, and HyperKey Copy
  protocols.
