import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import test from 'node:test';
import { gunzipSync, gzipSync } from 'node:zlib';
import { compareGenerated, readArchive, validateImport, validateManifest, validatePacked, validateReleaseVersions } from './release-utils.mjs';

function archive(name = 'package/package.json', type = '0', body = '{}') {
  const header = Buffer.alloc(512), content = Buffer.from(body);
  header.write(name, 0); header.write('0000644\0', 100);
  header.write(content.length.toString(8).padStart(11, '0') + '\0', 124);
  header.fill(32, 148, 156); header.write(type, 156); header.write('ustar\0', 257);
  header.write(header.reduce((sum, byte) => sum + byte, 0).toString(8).padStart(6, '0') + '\0 ', 148);
  return gzipSync(Buffer.concat([header, content, Buffer.alloc((512 - content.length % 512) % 512 + 1024)]));
}
const core = { name: '@group-foundation/group-core', version: '0.1.0', exports: { '.': { import: './dist/index.js', types: './dist/index.d.ts' } } };

test('release closure requires one exact npm and Rust crate version', () => {
  const manifests = {
    'group-core': core,
    'group-admission': { version: '0.1.0' },
    'admission-guard': { version: '0.1.0' },
    hyperkey: { version: '0.1.0' },
  };
  assert.equal(validateReleaseVersions(manifests, '[package]\nversion = "0.1.0"\n'), '0.1.0');
  assert.throws(() => validateReleaseVersions({ ...manifests, hyperkey: { version: '0.2.0' } }, '[package]\nversion = "0.1.0"\n'), /versions must match/u);
  assert.throws(() => validateReleaseVersions(manifests, '[package]\nversion = "0.2.0"\n'), /Rust crate/u);
  assert.throws(() => validateReleaseVersions({ ...manifests, hyperkey: { version: 'latest' } }, '[package]\nversion = "0.1.0"\n'), /exact semver/u);
});

test('archive parser rejects traversal, links, duplicate files, truncation, and corrupt checksums', () => {
  assert.equal(readArchive(archive(), 'package').get('package.json').toString(), '{}');
  assert.throws(() => readArchive(archive('package/../outside'), 'package'), /Unsafe/u);
  assert.throws(() => readArchive(archive('package/link', '2'), 'package'), /Unsupported/u);
  const valid = archive();
  const raw = gunzipSync(valid);
  assert.throws(() => readArchive(gzipSync(Buffer.concat([raw.subarray(0, 1024), raw])), 'package'), /Duplicate/u);
  assert.throws(() => readArchive(gzipSync(raw.subarray(0, 513)), 'package'), /Truncated/u);
  raw[0] ^= 1;
  assert.throws(() => readArchive(gzipSync(raw), 'package'), /checksum/u);
});

test('package graph rejects reverse edges, extra runtime dependencies, and unresolved packed workspaces', () => {
  validateManifest(core, 'group-core');
  assert.throws(() => validateManifest({ ...core, dependencies: { '@group-foundation/hyperkey': 'workspace:*' } }, 'group-core'));
  assert.throws(() => validateManifest({ ...core, optionalDependencies: { vendor: '1.0.0' } }, 'group-core'));
  assert.throws(() => validateManifest({ name: '@group-foundation/group-admission', dependencies: { '@group-foundation/group-core': 'workspace:*' } }, 'group-admission', true));
});

test('packed validation rejects missing declarations, mismatched dependency versions, and development payloads', () => {
  const files = new Map([['package.json', Buffer.from(JSON.stringify(core))], ['dist/index.js', Buffer.from('')], ['dist/index.d.ts', Buffer.from('')]]);
  validatePacked(files, 'group-core', { 'group-core': core });
  files.delete('dist/index.d.ts');
  assert.throws(() => validatePacked(files, 'group-core', { 'group-core': core }), /Missing packed export/u);
  files.set('dist/index.d.ts', Buffer.from('')); files.set('src/index.ts', Buffer.from(''));
  assert.throws(() => validatePacked(files, 'group-core', { 'group-core': core }), /Unexpected npm/u);
  const admission = { name: '@group-foundation/group-admission', version: '0.1.0', exports: {}, dependencies: { '@group-foundation/group-core': '0.2.0' } };
  assert.throws(() => validatePacked(new Map([['package.json', Buffer.from(JSON.stringify(admission))]]), 'group-admission', { 'group-core': core, 'group-admission': admission }), /dependency version/u);
});

test('production imports reject fixture reachability, undeclared packages, and relative package escapes', () => {
  const root = resolve(tmpdir(), 'core'), source = resolve(root, 'src/index.ts');
  validateImport('./contracts.js', source, root, core, true);
  assert.throws(() => validateImport('./testing/in-memory.js', source, root, core, true), /testing/u);
  assert.throws(() => validateImport('../../other/src/index.js', source, root, core, true), /Cross-package/u);
  assert.throws(() => validateImport('node:fs', source, root, core, true), /Undeclared/u);
  const dependent = { dependencies: { '@group-foundation/group-core': 'workspace:*' } };
  assert.throws(() => validateImport('@group-foundation/group-core/testing', source, root, dependent, true), /testing/u);
  validateImport('./testing/in-memory.js', source, root, core, false);
});

test('generated comparison rejects byte drift and changed inventory without overwriting originals', async () => {
  const directory = await mkdtemp(resolve(tmpdir(), 'foundation-compare-test-'));
  try {
    const expected = resolve(directory, 'expected'), actual = resolve(directory, 'actual');
    await mkdir(expected); await mkdir(actual);
    await writeFile(resolve(expected, 'binding.wasm'), 'original');
    await writeFile(resolve(actual, 'binding.wasm'), 'original');
    assert.equal(Object.keys(await compareGenerated(expected, actual)).length, 1);
    await writeFile(resolve(actual, 'binding.wasm'), 'changed');
    await assert.rejects(compareGenerated(expected, actual), /differs/u);
    await writeFile(resolve(actual, 'extra.js'), '');
    await assert.rejects(compareGenerated(expected, actual), /inventory/u);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
