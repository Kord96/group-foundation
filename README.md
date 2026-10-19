# Group Foundation

Portable MLS group mechanics, generic group admission, and logical-key Copy
protocols for product applications.

The current release line is `0.3.0`. It adds the standalone
[`@group-foundation/admission-guard`](packages/admission-guard/README.md) policy
and signed-evidence boundary to the admission bootstrap v2 presentation,
encrypted duplex channel contract, and exact atomic handoff into the admission
ledger introduced in `0.2.0`. All four npm packages and the Rust crate share the
same release version. The immutable `0.2.0` closure has three npm packages and
does not include admission guard.

See `docs/architecture/foundation-contract-v1.md` for the ownership boundary.

## Release qualification

Run `pnpm qualify:release` before releasing packages. See
[the qualification guide](docs/release-qualification.md) for prerequisites,
required checks, and artifact evidence.
