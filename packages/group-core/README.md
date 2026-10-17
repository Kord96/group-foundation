# Group Core

`@group-foundation/group-core` provides portable MLS custody, detached transitions,
generic member credentials, and authenticated opaque application frames. The
package has no runtime JavaScript dependencies. Consumers supply identity checks,
authorization, transport, and one atomic persistence writer.

The public package exports are `.`, `./contracts`, `./encoding`, `./native`,
`./native-wasm`, and `./testing`. Import the generated web binding from `./native`
and resolve its package-owned WASM asset through `./native-wasm`:

```js
import init, { NativeProductClient } from '@group-foundation/group-core/native';
// Bundlers may resolve this package asset with their URL/asset facility.
const wasmUrl = import.meta.resolve('@group-foundation/group-core/native-wasm');
await init({ module_or_path: wasmUrl });
const client = new NativeProductClient();
```

Node callers can read that asset URL and pass its bytes as `module_or_path`.
Do not reach into a source checkout or depend on the `generated/` layout.

`NativeProductClient` accepts opaque TLS credentials and profile components. Its
`stage*` operations leave live custody unchanged and expose authenticated MLS facts
for consumer validation. `NativeClient` provides a generic pinned-profile facade,
including detached Add and Remove commits, Welcome installation, applications, and
member proofs. They have distinct custody formats and cannot restore one another.
See [the native facade contract](spec/product-browser.md) for profile inputs,
message authentication, proposal origins, terminal deletion, and checkpoints.

Private snapshots must be authenticated and sealed by the host. The host commits
its semantic state, core custody, and exact outbox bytes in one physical
transaction before publishing. `NativeGroupTransitionStoragePort` defines revision
CAS and exact retry behavior. `InMemoryNativeGroupStorage` under `./testing` is a
reference for testing host composition; it does not provide durable storage.

## Build and qualification

The Foundation Cargo workspace owns `Cargo.lock`. Rust 1.95.0, OpenMLS 0.8.1
(with draft-08 extensions), and wasm-bindgen 0.2.127 remain pinned, including the
source dependency lock versions. Install the `wasm32-unknown-unknown` target and
wasm-bindgen 0.2.127, then run from this package:

```sh
npm install
npm run build:wasm
npm test
npm run check
npm run test:rust
npm run test:browser
```

`GROUP_FOUNDATION_WASM_BINDGEN_BIN` selects the wasm-bindgen binary;
`GROUP_FOUNDATION_RUST_TOOLCHAIN_BIN` selects the Rust tools;
`GROUP_FOUNDATION_WASM_CARGO_HOME` selects the Cargo cache;
`GROUP_FOUNDATION_WASM_TARGET_DIR` selects build intermediates; and
`GROUP_FOUNDATION_WASM_OUTPUT_DIR` selects an alternate bindings output directory.
The build fixes source timestamps, disables incremental compilation, remaps local
paths, and normalizes generated initializer signatures.

The clean break uses `group-foundation.*` schemas and transcripts. Provider state
is `GFS01`, product custody `GFC01`, signing custody `GFI01`, and generic snapshots
`GFN01`. Predecessor formats are rejected. Opaque sidecars require the bounded
`group-foundation.sidecar.` namespace. The suffix and value remain consumer-owned;
checkpoint installation selects exact sidecar keys and a single native group.
