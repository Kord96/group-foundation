#!/usr/bin/env bash
set -euo pipefail

# Reproducible browser binding entry point.  This crate uses cargo followed by
# wasm-bindgen directly; it intentionally does not assume wasm-pack is part of
# the repository toolchain.  The generated module is package-owned and is not
# checked into the Rust target directory.
crate_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
repository_root="$(cd "${crate_dir}/../../.." && pwd -P)"
out_dir="${GROUP_FOUNDATION_WASM_OUTPUT_DIR:-${crate_dir}/../generated}"
toolchain_bin="${GROUP_FOUNDATION_RUST_TOOLCHAIN_BIN:-$(dirname "$(command -v rustc)")}"
cargo_home="${GROUP_FOUNDATION_WASM_CARGO_HOME:-${CARGO_HOME:-$HOME/.cargo}}"
wasm_bindgen="${GROUP_FOUNDATION_WASM_BINDGEN_BIN:-$(command -v wasm-bindgen || true)}"
if [[ -z "${wasm_bindgen}" ]]; then
  echo "Set GROUP_FOUNDATION_WASM_BINDGEN_BIN to wasm-bindgen 0.2.127" >&2
  exit 2
fi
test "$("${wasm_bindgen}" --version)" = "wasm-bindgen 0.2.127"
test "$("${toolchain_bin}/rustc" --version)" = "rustc 1.95.0 (59807616e 2026-04-14)"
test "$("${toolchain_bin}/cargo" --version)" = "cargo 1.95.0 (f2d3ce0bd 2026-03-21)"

# Callers can direct Rust's large intermediates to a mounted build volume.
target_root="${GROUP_FOUNDATION_WASM_TARGET_DIR:-${CARGO_TARGET_DIR:-${repository_root}/target}}"
mkdir -p "${target_root}" "${out_dir}"
# Resolve relative paths before Cargo interprets them from its working directory.
target_root="$(cd "${target_root}" && pwd -P)"
out_dir="$(cd "${out_dir}" && pwd -P)"
target_dir="${target_root}/wasm32-unknown-unknown/release"
canonical_rustflags="--remap-path-prefix=${repository_root}=/group-foundation/source --remap-path-prefix=${cargo_home}=/group-foundation/cargo-home"

env \
  -u CARGO_ENCODED_RUSTFLAGS \
  CARGO_HOME="${cargo_home}" \
  CARGO_INCREMENTAL=0 \
  CARGO_TARGET_DIR="${target_root}" \
  PATH="${toolchain_bin}:${PATH:-/usr/bin:/bin}" \
  RUSTC="${toolchain_bin}/rustc" \
  RUSTFLAGS="${canonical_rustflags}" \
  SOURCE_DATE_EPOCH=0 \
  "${toolchain_bin}/cargo" build --locked --manifest-path "${repository_root}/Cargo.toml" --package group-foundation-core --target wasm32-unknown-unknown --release --features wasm
"${wasm_bindgen}" --target web --out-dir "${out_dir}" --out-name foundation_group "${target_dir}/group_foundation_core.wasm"
node "${crate_dir}/../scripts/clean-wasm-bindgen.mjs" "${out_dir}" foundation_group
