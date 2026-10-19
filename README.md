# Group Foundation

Portable MLS group mechanics, generic group admission, and logical-key Copy
protocols for product applications.

The current release line is `0.4.0`. It replaces the standalone evidence
evaluator with [`@group-foundation/bouncer`](packages/bouncer/README.md), which
returns immutable approved or denied decisions and executes no caller action.
All four npm packages and the Rust crate share the same release version.

See `docs/architecture/foundation-contract-v1.md` for the ownership boundary.

## Release qualification

Run `pnpm qualify:release` before releasing packages. See
[the qualification guide](docs/release-qualification.md) for prerequisites,
required checks, and artifact evidence.
