# Changelog

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
