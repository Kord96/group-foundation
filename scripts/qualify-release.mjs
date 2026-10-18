import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { cp, mkdir, mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { compareGenerated, json, packageNames, readArchive, scope, sha256, validatePacked, validateReleaseVersions } from './release-utils.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const pnpm = process.platform === 'win32' ? 'pnpm.cmd' : 'pnpm';
const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const base = await realpath(process.env.GROUP_FOUNDATION_QUALIFICATION_TMPDIR ?? tmpdir());
const fromRoot = relative(await realpath(root), base);
assert(fromRoot === '..' || fromRoot.startsWith(`..${sep}`) || isAbsolute(fromRoot), 'Qualification temp directory must be outside the repository');
const output = await mkdtemp(resolve(base, 'foundation-release-'));
const report = { status: 'running', node: process.version, steps: [], archives: {}, output };
const env = { ...process.env, CARGO_TARGET_DIR: resolve(output, 'cargo-target') };
console.log(`Release qualification artifacts: ${output}`);

async function run(command, args, options = {}) {
  console.log(`\n> ${command} ${args.join(' ')}`);
  await new Promise((done, reject) => {
    const child = spawn(command, args, { cwd: root, env, stdio: 'inherit', ...options });
    child.on('error', reject);
    child.on('exit', (code, signal) => code === 0 ? done() : reject(new Error(`${command} ${args.join(' ')} failed (${signal ?? code})`)));
  });
}
async function step(name, action) {
  const entry = { name, status: 'running' };
  report.steps.push(entry);
  try { await action(); entry.status = 'passed'; }
  catch (error) { entry.status = 'failed'; throw error; }
}
const node = (args, options) => run(process.execPath, args, options);
const manifests = Object.fromEntries(await Promise.all(packageNames.map(async name => [name, await json(resolve(root, 'packages', name, 'package.json'))])));
const cargoManifest = await readFile(resolve(root, 'packages/group-core/rust/Cargo.toml'), 'utf8');
report.version = validateReleaseVersions(manifests, cargoManifest);

try {
  assert(Number(process.versions.node.split('.')[0]) >= 22, 'Node 22 or newer is required');
  await step('frozen workspace install', () => run(pnpm, ['install', '--frozen-lockfile']));
  await step('release tooling regression tests', () => node(['--test', 'scripts/release-utils.test.mjs']));
  await step('package DAG and production dependencies', () => node(['scripts/check-package-boundaries.mjs']));
  await step('clean TypeScript build', async () => {
    for (const name of packageNames) await rm(resolve(root, 'packages', name, 'dist'), { recursive: true, force: true });
    await run(pnpm, ['build']);
  });
  await step('TypeScript checks', () => run(pnpm, ['check']));
  // Select packages explicitly: the example browser suite is a separate required step.
  await step('TypeScript and native WASM tests', () => run(pnpm, ['--filter', './packages/**', '--recursive', 'test']));
  await step('locked Rust tests', () => run('cargo', ['test', '--locked', '--workspace', '--all-features']));
  await step('core Chromium qualification', () => run(pnpm, ['--filter', scope + 'group-core', 'test:browser']));
  await step('HyperKey browser example', () => run(pnpm, ['--filter', 'hyperkey-browser-qualification', 'test']));
  await step('deterministic generated WASM comparison', async () => {
    const generated = resolve(output, 'generated');
    await run(pnpm, ['--filter', scope + 'group-core', 'build:wasm'], { env: {
      ...env, GROUP_FOUNDATION_WASM_OUTPUT_DIR: generated,
      GROUP_FOUNDATION_WASM_TARGET_DIR: resolve(output, 'wasm-target'),
    } });
    report.generated = await compareGenerated(resolve(root, 'packages/group-core/generated'), generated);
  });
  await step('packed npm archives and external consumer', async () => {
    const archives = resolve(output, 'npm'), consumer = resolve(output, 'consumer');
    await mkdir(archives); await mkdir(consumer);
    const paths = [], imports = [];
    for (const name of packageNames) {
      await run(pnpm, ['--filter', scope + name, 'pack', '--pack-destination', archives]);
      const archive = resolve(archives, `group-foundation-${name}-${manifests[name].version}.tgz`);
      const bytes = await readFile(archive), files = readArchive(bytes, 'package');
      const packed = validatePacked(files, name, manifests);
      if (name === 'group-core') {
        for (const [filename, hash] of Object.entries(report.generated)) {
          assert.equal(sha256(files.get(`generated/${filename}`)), hash, `Packed WASM differs: ${filename}`);
        }
      }
      report.archives[packed.name] = { filename: archive, sha256: sha256(bytes), files: [...files.keys()].sort() };
      paths.push(archive);
      for (const [subpath, target] of Object.entries(packed.exports)) {
        if (typeof target === 'object' && target.import?.endsWith('.js')) imports.push(packed.name + (subpath === '.' ? '' : subpath.slice(1)));
      }
    }
    await writeFile(resolve(consumer, 'package.json'), JSON.stringify({ name: 'foundation-external-qualification', private: true, type: 'module' }));
    // All production dependencies must be satisfied by these tarballs, even offline.
    await run(npm, ['install', '--offline', '--ignore-scripts', '--no-audit', '--no-fund', '--save-exact', ...paths], { cwd: consumer });
    await run(npm, ['ls', '--omit=dev', '--all'], { cwd: consumer });
    const lock = await json(resolve(consumer, 'package-lock.json'));
    assert.deepEqual(Object.keys(lock.packages).filter(path => path).sort(), packageNames.map(name => `node_modules/${scope}${name}`).sort(), 'External install includes unexpected production dependencies');
    const smoke = imports.map(specifier => `await import(${JSON.stringify(specifier)});`).join('\n');
    await writeFile(resolve(consumer, 'exports.mjs'), smoke);
    await node(['exports.mjs'], { cwd: consumer });
    await writeFile(resolve(consumer, 'exports.mts'), imports.map((specifier, i) => `import * as entry${i} from ${JSON.stringify(specifier)}; void entry${i};`).join('\n'));
    await node([resolve(root, 'packages/group-core/node_modules/typescript/bin/tsc'), '--noEmit', '--strict', '--module', 'NodeNext', '--target', 'ES2022', '--lib', 'ES2022,DOM,ESNext.Disposable', 'exports.mts'], { cwd: consumer });
    // Exercise the same real MLS lifecycle against installed archives. Only the
    // binding locator changes; all qualification assertions remain intact.
    const nativeTest = (await readFile(resolve(root, 'packages/group-core/tests/native-binding.test.mjs'), 'utf8'))
      .replace('new URL("../generated/foundation_group.js", import.meta.url)', 'new URL(import.meta.resolve("@group-foundation/group-core/native"))')
      .replace('new URL("../generated/foundation_group_bg.wasm", import.meta.url)', 'new URL(import.meta.resolve("@group-foundation/group-core/native-wasm"))');
    await writeFile(resolve(consumer, 'native.test.mjs'), nativeTest);
    await node(['--test', 'native.test.mjs'], { cwd: consumer });
    // The browser example runs a second time from the external install, with no
    // workspace packages available through its package resolution ancestry.
    const example = resolve(consumer, 'browser');
    await cp(resolve(root, 'examples/hyperkey-browser'), example, { recursive: true, filter: path => !path.split(/[\\/]/u).includes('node_modules') });
    const browserTest = (await readFile(resolve(example, 'qualification.test.mjs'), 'utf8'))
      .replace('from "playwright"', `from ${JSON.stringify(new URL('./packages/group-core/node_modules/playwright/index.mjs', new URL('../', import.meta.url)).href)}`);
    await writeFile(resolve(example, 'qualification.test.mjs'), browserTest);
    await node(['browser/qualification.test.mjs'], { cwd: consumer });
  });
  await step('packaged Cargo crate qualification', async () => {
    await run('cargo', ['package', '--locked', '--allow-dirty', '--package', 'group-foundation-core']);
    const version = /^version\s*=\s*"([^"]+)"/mu.exec(cargoManifest)?.[1];
    assert(version, 'Cargo crate version missing');
    const prefix = `group-foundation-core-${version}`;
    const archive = resolve(env.CARGO_TARGET_DIR, 'package', `${prefix}.crate`);
    const bytes = await readFile(archive), files = readArchive(bytes, prefix);
    assert(files.has('Cargo.lock') && files.has('Cargo.toml') && files.has('src/lib.rs'), 'Incomplete Cargo archive');
    const extracted = resolve(output, 'crate');
    for (const [name, content] of files) {
      const path = resolve(extracted, name); await mkdir(dirname(path), { recursive: true }); await writeFile(path, content);
    }
    report.archives['group-foundation-core'] = { filename: archive, sha256: sha256(bytes), files: [...files.keys()].sort() };
    const manifest = resolve(extracted, 'Cargo.toml');
    await run('cargo', ['test', '--locked', '--manifest-path', manifest, '--all-features']);
    await run('cargo', ['build', '--locked', '--manifest-path', manifest, '--target', 'wasm32-unknown-unknown', '--release', '--features', 'wasm']);
  });
  report.status = 'passed';
} catch (error) {
  report.status = 'failed'; report.error = error.stack;
  console.error(error); process.exitCode = 1;
} finally {
  await writeFile(resolve(output, 'report.json'), JSON.stringify(report, null, 2) + '\n');
  console.log(`\nRelease qualification ${report.status}: ${resolve(output, 'report.json')}`);
}
