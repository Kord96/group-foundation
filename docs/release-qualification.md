# Release qualification

Run `pnpm qualify:release` from the repository root before releasing Foundation.
Every phase is required; a missing tool, browser, artifact, or failed assertion
exits nonzero. This command does not publish packages or change versions.
The gate also requires all three npm package versions and the Rust crate version
to match so the qualified archives form one immutable release closure.

Prerequisites:

- Node 22 or newer, npm, and the `packageManager` version of pnpm (11.1.2).
- Rust/Cargo 1.95.0, the `wasm32-unknown-unknown` target, and wasm-bindgen 0.2.127.
  The existing WASM build script verifies the exact Rust/Cargo build versions.
- Playwright Chromium and its system dependencies. After installing the workspace,
  run `pnpm --filter @group-foundation/group-core exec playwright install chromium`.
- Access to the locked npm and Cargo dependencies, or populated local caches.

The gate runs a frozen workspace install, release tooling regression tests,
package DAG and production import checks, a clean TypeScript build followed by
checks/tests, locked
Rust tests with all features, core Chromium tests, and the HyperKey browser
example. The dependency check requires core to have no production dependencies,
admission to depend on core, and HyperKey to depend on core and admission. It
parses TypeScript imports, including type imports and dynamic imports, to reject
undeclared dependencies, relative package escapes, and production imports of
testing modules.

The gate then builds WASM into a new temporary output and target directory and
compares every generated file byte for byte with the committed assets, including
the file inventory. It never writes the tracked `generated` directory. A mismatch
must be investigated and the generated assets deliberately regenerated in a
separate change; the qualification command does not repair the mismatch.

Each public npm package is packed with pnpm so workspace dependencies become
release versions. The gate checks the actual archive payload, dependency versions,
exported JavaScript and declarations, and embedded WASM hashes. An external
consumer installs only those tarballs with npm in offline mode and with lifecycle
scripts disabled. Its dependency tree must contain exactly the three Foundation
packages. It imports every JavaScript export, checks the public declarations with
TypeScript (including the disposable types used by wasm-bindgen), runs the core
native MLS lifecycle assertions against the installed
WASM, and runs the HyperKey browser example against the installed packages.
Only the browser test runner imports Playwright from the workspace; application
dependencies resolve from the external consumer.

Finally, `cargo package --locked` performs Cargo's package verification. The gate
unpacks the resulting crate into a separate directory, runs its tests with all
features, and builds its WASM target. `--allow-dirty` permits running the gate while
reviewing tooling changes; qualification always covers the current working tree.

All archives, extracted consumers, Cargo targets, and `report.json` remain under
a unique `foundation-release-*` directory outside the repository, printed at
startup. The report records each required phase and SHA-256 hashes/file inventories
of the qualified artifacts. Keep it with release evidence, then remove the
temporary directory when it is no longer needed. A run can use several gigabytes.

Set `GROUP_FOUNDATION_QUALIFICATION_TMPDIR` to an existing writable directory on a
large volume (for example `/mnt/data/your-user`). Standard `TMPDIR` also applies.
The gate rejects temporary directories inside the repository. Existing WASM
toolchain overrides (`GROUP_FOUNDATION_RUST_TOOLCHAIN_BIN`,
`GROUP_FOUNDATION_WASM_CARGO_HOME`, and `GROUP_FOUNDATION_WASM_BINDGEN_BIN`) remain
available; the gate owns the generated output and Cargo target directories.

Focused checks are available as `pnpm check:packages` and
`pnpm test:release-tooling`. They supplement the consolidated command.
