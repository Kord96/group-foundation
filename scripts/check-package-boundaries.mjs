import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readdir, readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { filesBelow, json, packageNames, validateImport, validateManifest } from './release-utils.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
assert.deepEqual((await readdir(resolve(root, 'packages'))).sort(), [...packageNames].sort(), 'Update the release package inventory when adding packages');
const ts = createRequire(resolve(root, 'packages/group-core/package.json'))('typescript');
for (const name of packageNames) {
  const directory = resolve(root, 'packages', name), manifest = await json(resolve(directory, 'package.json'));
  validateManifest(manifest, name);
  for (const path of (await filesBelow(resolve(directory, 'src'))).filter(path => path.endsWith('.ts'))) {
    const filename = resolve(directory, 'src', path);
    const source = ts.createSourceFile(filename, await readFile(filename, 'utf8'), ts.ScriptTarget.Latest, true);
    const production = !/^testing(?:\.|\/)/u.test(path);
    const check = value => validateImport(value, filename, directory, manifest, production);
    function visit(node) {
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) check(node.moduleSpecifier.text);
      if (ts.isImportTypeNode(node) && ts.isLiteralTypeNode(node.argument)) check(node.argument.literal.text);
      if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === 'require'))) {
        assert(node.arguments.length === 1 && ts.isStringLiteralLike(node.arguments[0]), `Nonliteral dependency in ${filename}`);
        check(node.arguments[0].text);
      }
      ts.forEachChild(node, visit);
    }
    visit(source);
  }
}
console.log('Package DAG and production imports passed: core → admission → HyperKey; testing remains separate.');
