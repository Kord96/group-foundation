import assert from 'node:assert/strict';
import { gunzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import { posix, resolve, relative, sep } from 'node:path';

export const packageNames = ['group-core', 'group-admission', 'bouncer', 'hyperkey'];
export const scope = '@group-foundation/';
const expectedDependencies = {
  'group-core': [], 'group-admission': ['group-core'], 'bouncer': [], hyperkey: ['group-admission', 'group-core'],
};
export const sha256 = bytes => createHash('sha256').update(bytes).digest('hex');
export const json = async path => JSON.parse(await readFile(path, 'utf8'));

export function validateReleaseVersions(manifests, cargoManifest) {
  const versions = packageNames.map(name => manifests[name]?.version);
  for (const version of versions) assert.match(version ?? '', /^\d+\.\d+\.\d+$/u, 'npm package release version must be exact semver');
  assert.equal(new Set(versions).size, 1, 'Foundation npm package versions must match');
  const crateVersion = /^version\s*=\s*"([^"]+)"/mu.exec(cargoManifest)?.[1];
  assert.equal(crateVersion, versions[0], 'Foundation Rust crate and npm package versions must match');
  return versions[0];
}

export function validateManifest(manifest, name, packed = false) {
  assert.equal(manifest.name, scope + name);
  assert.equal(manifest.private, undefined, `${name} must be publishable`);
  assert.deepEqual(Object.keys(manifest.dependencies ?? {}).sort(), expectedDependencies[name].map(dep => scope + dep));
  for (const field of ['optionalDependencies', 'peerDependencies', 'bundledDependencies', 'bundleDependencies']) {
    assert.equal(Object.keys(manifest[field] ?? {}).length, 0, `${name}: unexpected ${field}`);
  }
  for (const version of Object.values(manifest.dependencies ?? {})) {
    assert.match(version, packed ? /^\d+\.\d+\.\d+$/u : /^workspace:\*$/u, `${name}: dependency must be ${packed ? 'a release version' : 'workspace:*'}`);
  }
}

export async function filesBelow(directory, prefix = '') {
  const result = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const name = posix.join(prefix, entry.name);
    assert(!entry.isSymbolicLink(), `Unexpected symlink: ${name}`);
    if (entry.isDirectory()) result.push(...await filesBelow(resolve(directory, entry.name), name));
    else if (entry.isFile()) result.push(name);
    else assert.fail(`Unexpected file type: ${name}`);
  }
  return result.sort();
}

export async function compareGenerated(expected, actual) {
  const names = await filesBelow(expected);
  assert.deepEqual(await filesBelow(actual), names, 'Generated WASM file inventory differs');
  const hashes = {};
  for (const name of names) {
    const wanted = await readFile(resolve(expected, name));
    const found = await readFile(resolve(actual, name));
    assert(wanted.equals(found), `Generated WASM differs: ${name} (expected ${sha256(wanted)}, got ${sha256(found)})`);
    hashes[name] = sha256(found);
  }
  return hashes;
}

// npm and Cargo produce regular ustar archives. Fail closed on unsupported
// entries rather than extracting links, metadata extensions, or unsafe paths.
export function readArchive(compressed, prefix) {
  const tar = gunzipSync(compressed), files = new Map();
  let offset = 0, ended = false;
  const string = (start, length) => tar.subarray(start, start + length).toString('utf8').replace(/\0.*$/su, '');
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every(byte => byte === 0)) { ended = true; break; }
    const checksum = Number.parseInt(string(offset + 148, 8).trim(), 8);
    const actual = header.reduce((sum, byte, index) => sum + (index >= 148 && index < 156 ? 32 : byte), 0);
    assert.equal(actual, checksum, 'Invalid tar checksum');
    const base = string(offset, 100), directory = string(offset + 345, 155);
    const name = directory ? `${directory}/${base}` : base;
    assert(name.startsWith(`${prefix}/`) && !name.includes('\\') && !name.split('/').includes('..'), `Unsafe archive path: ${name}`);
    const sizeField = string(offset + 124, 12).trim();
    assert.match(sizeField, /^[0-7]+$/u, 'Unsupported tar size');
    const size = Number.parseInt(sizeField, 8), type = string(offset + 156, 1);
    assert(type === '0' || type === '' || type === '5', `Unsupported archive entry: ${name} (${type})`);
    offset += 512;
    assert(offset + size <= tar.length, `Truncated archive entry: ${name}`);
    if (type !== '5') {
      const path = name.slice(prefix.length + 1);
      assert(path && posix.normalize(path) === path, `Noncanonical archive path: ${name}`);
      assert(!files.has(path), `Duplicate archive entry: ${name}`);
      files.set(path, tar.subarray(offset, offset + size));
    }
    offset += Math.ceil(size / 512) * 512;
  }
  assert(ended && tar.subarray(offset).every(byte => byte === 0), 'Missing tar terminator or trailing archive data');
  return files;
}

export function exportTargets(value) {
  if (typeof value === 'string') return [value];
  assert(value && typeof value === 'object', 'Invalid package export');
  return Object.values(value).flatMap(exportTargets);
}

export function validatePacked(files, name, manifests) {
  assert(files.has('package.json'), 'Archive lacks package.json');
  const manifest = JSON.parse(files.get('package.json').toString());
  validateManifest(manifest, name, true);
  assert.equal(manifest.version, manifests[name].version, `${name}: packed version changed`);
  assert.deepEqual(manifest.exports, manifests[name].exports, `${name}: packed exports changed`);
  for (const [dependency, version] of Object.entries(manifest.dependencies ?? {})) {
    assert.equal(version, manifests[dependency.slice(scope.length)].version, `${name}: dependency version mismatch`);
  }
  for (const path of files.keys()) {
    assert(/^(?:package\.json|README\.md|DELIVERY\.md|(?:dist|spec|generated)\/)/u.test(path), `Unexpected npm archive file: ${path}`);
    assert(!/(?:^|\/)(?:node_modules|tests?|target|src)(?:\/|$)/u.test(path), `Development file in npm archive: ${path}`);
  }
  for (const target of exportTargets(manifest.exports)) {
    assert(target.startsWith('./'), `Nonlocal export: ${target}`);
    assert(files.has(target.slice(2)), `Missing packed export: ${target}`);
  }
  return manifest;
}

export function validateImport(specifier, source, packageRoot, manifest, production) {
  if (specifier.startsWith('.')) {
    const target = relative(packageRoot, resolve(source, '..', specifier));
    assert(target !== '..' && !target.startsWith(`..${sep}`), `Cross-package relative import: ${specifier}`);
    if (production) assert(!/(?:^|[/\\])testing(?:\.|[/\\]|$)/u.test(target), `Production imports testing: ${specifier}`);
    return;
  }
  const dependency = specifier.startsWith('@') ? specifier.split('/').slice(0, 2).join('/') : specifier.split('/')[0];
  assert(Object.hasOwn(manifest.dependencies ?? {}, dependency), `Undeclared production dependency in ${manifest.name}: ${specifier}`);
  if (production) assert(!specifier.endsWith('/testing'), `Production imports testing: ${specifier}`);
}
