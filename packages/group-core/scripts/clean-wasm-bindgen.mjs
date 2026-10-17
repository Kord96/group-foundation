import { readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

if (process.argv.length !== 4) throw new Error("Usage: clean-wasm-bindgen.mjs OUTPUT_DIRECTORY BINDING_NAME");
const directory = pathToFileURL(resolve(process.argv[2]) + "/");
const bindingName = process.argv[3];
if (!/^[a-z][a-z0-9_]*$/u.test(bindingName)) throw new Error("wasm-bindgen binding name is invalid");
const javascriptPath = new URL(`${bindingName}.js`, directory);
const declarationsPath = new URL(`${bindingName}.d.ts`, directory);

let javascript = readFileSync(javascriptPath, "utf8");
javascript = replaceOnce(
  javascript,
  "function initSync(module) {",
  "function initSync({ module }) {",
  "synchronous initializer signature",
);
javascript = replaceOnce(
  javascript,
  "async function __wbg_init(module_or_path) {",
  "async function __wbg_init({ module_or_path } = {}) {",
  "asynchronous initializer signature",
);
javascript = removeGeneratedBranch(javascript, "module");
javascript = removeGeneratedBranch(javascript, "module_or_path");
writeFileSync(javascriptPath, javascript);

const declarations = readFileSync(declarationsPath, "utf8")
  .split("\n")
  .filter(line => !line.includes("Passing `"))
  .map(line => {
    if (line.startsWith("export function initSync(")) {
      return "export function initSync(module: { module: SyncInitInput }): InitOutput;";
    }
    if (line.startsWith("export default function __wbg_init")) {
      return "export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> }): Promise<InitOutput>;";
    }
    return line;
  })
  .join("\n");
writeFileSync(declarationsPath, declarations);

function removeGeneratedBranch(source, parameter) {
  const marker = `    if (${parameter} !== undefined) {`;
  const start = source.indexOf(marker);
  if (start < 0) throw new Error(`wasm-bindgen ${parameter} branch was not found`);
  const end = source.indexOf("\n    }\n", start);
  if (end < 0) throw new Error(`wasm-bindgen ${parameter} branch is unterminated`);
  return source.slice(0, start) + source.slice(end + 7);
}

function replaceOnce(source, before, after, label) {
  const start = source.indexOf(before);
  if (start < 0 || source.indexOf(before, start + before.length) >= 0) {
    throw new Error(`wasm-bindgen ${label} did not occur exactly once`);
  }
  return source.slice(0, start) + after + source.slice(start + before.length);
}
