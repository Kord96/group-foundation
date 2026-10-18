# Group Foundation

Portable MLS group mechanics, generic group admission, and logical-key Copy
protocols for product applications.

The current release line is `0.2.0`. It introduces the clean-break admission
bootstrap v2 presentation, encrypted duplex channel contract, and exact atomic
handoff into the admission ledger. All npm packages and the Rust crate share the
same release version.

See `docs/architecture/foundation-contract-v1.md` for the ownership boundary.

## Release qualification

Run `pnpm qualify:release` before releasing packages. See
[the qualification guide](docs/release-qualification.md) for prerequisites,
required checks, and artifact evidence.
