# Group Foundation

Portable MLS group mechanics, generic group admission, and logical-key Copy
protocols for product applications.

The Foundation release line is `0.4.0`. The three maintained npm packages
(`group-core`, `group-admission`, and `hyperkey`) and the Rust crate share the
same release version. Historical four-package release receipts remain unchanged.

Generic claim policy and evidence evaluation now belong to the independently
qualified `@kord96/bouncer@0.1.0` package. Foundation contains no Bouncer engine,
wrapper, or dependency. Its existing admission and bootstrap/QR contracts remain
unchanged; consumers separately select any evidence policy and own its effects.

See `docs/architecture/foundation-contract-v1.md` for the ownership boundary.

## Release qualification

Run `pnpm qualify:release` before releasing packages. See
[the qualification guide](docs/release-qualification.md) for prerequisites,
required checks, and artifact evidence.
