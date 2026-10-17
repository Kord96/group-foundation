import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import test from "node:test";

test("native qualification fails when its binding is missing or its WASM is invalid", async () => {
  const qualification = new URL("./native-binding.test.mjs", import.meta.url);
  const source = (await readFile(qualification, "utf8"))
    .replace('new URL("../generated/foundation_group.js", import.meta.url)', `new URL(${JSON.stringify(new URL("../generated/foundation_group.js", qualification).href)})`)
    .replace('new URL("../generated/foundation_group_bg.wasm", import.meta.url)', `new URL(${JSON.stringify(new URL("../generated/foundation_group_bg.wasm", qualification).href)})`);
  for (const [condition, changed, cause] of [
    ["missing binding", source.replace("foundation_group.js", "missing_group_binding.js"), /ENOENT/u],
    ["invalid WASM", source.replace("await readFile(generatedWasm)", "new Uint8Array([0])"), /CompileError/u],
  ]) {
    const result = spawnSync(process.execPath, ["--input-type=module"], { input: changed, encoding: "utf8" });
    assert.ifError(result.error);
    assert.notEqual(result.status, 0, `${condition} must fail qualification`);
    assert.match(result.stderr, /native WebAssembly binding is required for qualification/u);
    assert.match(result.stderr, cause);
  }
});
