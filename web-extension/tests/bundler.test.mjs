/**
 * Bundler tests.
 *
 * Every byte the extension ships goes through scripts/bundler.mjs, so its
 * failure modes matter: a wrong module order, a dropped export or a silently
 * mis-rewritten import would break the content script in ways that are hard to
 * see (content scripts cannot be ES modules, which is why any of this exists).
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';

import { bundleSources } from '../scripts/bundler.mjs';

const ROOT = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..');

/** Writes a fixture tree and returns its root. */
async function fixture(files) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'kb-bundler-'));
  for (const [relative, contents] of Object.entries(files)) {
    await fs.mkdir(path.dirname(path.join(dir, relative)), { recursive: true });
    await fs.writeFile(path.join(dir, relative), contents, 'utf8');
  }
  return dir;
}

/**
 * Runs a bundle the way a browser would: as a classic script.
 *
 * Module exports live on per-module `__exports` objects (deliberately not on
 * globals), so fixtures publish what they want observed as `globalThis.__result`.
 */
function runBundle(code) {
  const sandbox = { console, TextEncoder, TextDecoder };
  vm.createContext(sandbox);
  vm.runInContext(code, sandbox);
  return sandbox;
}

/* ------------------------------------------------------------------ */

test('dependencies are emitted before the modules that import them', async () => {
  const root = await fixture({
    'entry.js': "import { deep } from './a.js';\nexport const value = deep + 1;\n",
    'a.js': "import { base } from './b.js';\nexport const deep = base + 1;\n",
    'b.js': 'export const base = 1;\n'
  });
  const { modules, code } = await bundleSources({ root, entry: 'entry.js' });
  assert.deepEqual(modules, ['b.js', 'a.js', 'entry.js']);
  for (const name of modules) {
    assert.equal(code.includes(`__kbDefine(${JSON.stringify(name)}`), true, `${name} should be defined`);
  }
  assert.ok(
    code.indexOf('__kbDefine("b.js"') < code.indexOf('__kbDefine("a.js"'),
    'b must be defined before a'
  );
});

test('a module keeps its own scope and exports are wired to the right bindings', async () => {
  const root = await fixture({
    'entry.js': "import { inner, shadowed } from './dep.js';\nglobalThis.__result = inner() + shadowed;\n",
    // `helper` exists in both modules with different meanings and different
    // arities: a bundler that concatenated instead of wrapping would collide.
    'dep.js': "const helper = () => 41;\nexport const inner = () => helper() + 0;\nexport const shadowed = 1;\n",
    'other.js': 'const helper = () => "not a number";\nexport const unused = helper;\n'
  });
  const { code } = await bundleSources({ root, entry: 'entry.js' });
  const sandbox = runBundle(code);
  assert.equal(sandbox.__result, 42, 'exported bindings must resolve across module scopes');
});

test('async functions, classes and destructured imports survive the rewrite', async () => {
  const root = await fixture({
    'entry.js': [
      "import { makeThing, CLASSY, later } from './dep.js';",
      'globalThis.__made = makeThing(2);',
      'globalThis.__kind = new CLASSY().kind;',
      'globalThis.__promise = later();'
    ].join('\n'),
    'dep.js': [
      'export class CLASSY {',
      "  constructor() { this.kind = 'class'; }",
      '}',
      'export const makeThing = (n) => ({ doubled: n * 2 });',
      'export async function later() { return 7; }'
    ].join('\n')
  });
  const { code } = await bundleSources({ root, entry: 'entry.js' });
  assert.equal(/^\s*(import|export)\s/m.test(code), false, 'no module syntax may survive');
  const sandbox = runBundle(code);
  // compare fields: the object was created in another realm, so deepEqual's
  // prototype check would fail for reasons unrelated to the bundler
  assert.equal(sandbox.__made.doubled, 4);
  assert.equal(sandbox.__kind, 'class');
  assert.equal(await sandbox.__promise, 7);
});

test('the output is deterministic, so the staleness check means something', async () => {
  const root = await fixture({
    'entry.js': "import { a } from './a.js';\nexport const value = a;\n",
    'a.js': 'export const a = () => 1;\n'
  });
  const first = await bundleSources({ root, entry: 'entry.js' });
  const second = await bundleSources({ root, entry: 'entry.js' });
  assert.equal(first.code, second.code);
  assert.equal(first.hash, second.hash);
  assert.match(first.hash, /^[0-9a-f]{64}$/);
  assert.match(first.code, /source-sha256: [0-9a-f]{64}/);
});

test('a diamond dependency is defined once and required once', async () => {
  const root = await fixture({
    'entry.js': "import { l } from './left.js';\nimport { r } from './right.js';\nglobalThis.__result = l + r;\n",
    'left.js': "import { shared } from './shared.js';\nexport const l = shared + 1;\n",
    'right.js': "import { shared } from './shared.js';\nexport const r = shared + 2;\n",
    'shared.js': 'export const shared = 10;\n'
  });
  const { modules, code } = await bundleSources({ root, entry: 'entry.js' });
  assert.equal(modules.length, 4);
  assert.equal(code.split('__kbDefine("shared.js"').length - 1, 1, 'defined exactly once');
  assert.equal(code.split('__kbRequire("shared.js")').length - 1, 2, 'required by both importers');
  assert.equal(runBundle(code).__result, 23);
});

test('a cyclic import does not hang and still produces a runnable bundle', async () => {
  const root = await fixture({
    'entry.js': "import { fromA } from './a.js';\nglobalThis.__result = fromA();\n",
    'a.js': "import { fromB } from './b.js';\nexport const fromA = () => 'a' + fromB();\n",
    'b.js': "import { fromA } from './a.js';\nexport const fromB = () => (fromA ? 'b' : 'b');\n"
  });
  const { modules, code } = await bundleSources({ root, entry: 'entry.js' });
  assert.equal(modules.length, 3);
  assert.equal(runBundle(code).__result, 'ab', 'calls made after initialisation resolve fine');
});

test('unsupported module syntax fails the build instead of shipping broken code', async () => {
  const cases = [
    ["import thing from './dep.js';\nexport const x = 1;\n", /unhandled import/i],
    ["import * as ns from './dep.js';\nexport const x = 1;\n", /unhandled import/i],
    ["import { a } from 'left-pad';\nexport const x = a;\n", /bare import/i],
    ["const late = async () => { await import('./dep.js'); };\nexport const x = late;\n", /unhandled import/i],
    ['export default 42;\n', /default exports/i],
    ['const a = 1;\nexport { a as b };\n', /unhandled export/i],
    ["export * from './dep.js';\n", /default exports|unhandled export/i]
  ];
  for (const [source, pattern] of cases) {
    const root = await fixture({ 'entry.js': source, 'dep.js': 'export const a = 1;\n' });
    await assert.rejects(() => bundleSources({ root, entry: 'entry.js' }), pattern, source);
  }
});

test('the bundle runs as a classic script with no globals leaked', async () => {
  const root = await fixture({
    'entry.js': "import { helper } from './dep.js';\nconst secret = helper();\nglobalThis.__result = secret;\n",
    'dep.js': 'export const helper = () => 5;\n'
  });
  const { code } = await bundleSources({ root, entry: 'entry.js' });
  const sandbox = runBundle(code);
  for (const leak of ['__kbModules', '__kbCache', '__kbDefine', '__kbRequire', 'secret', 'helper']) {
    assert.equal(leak in sandbox, false, `${leak} leaked into the global scope`);
  }
  assert.equal(sandbox.__result, 5);
});

test('the real content bundle is in sync with the real sources', async () => {
  const { hash, modules } = await bundleSources({ root: ROOT, entry: 'src/content.js' });
  const written = await fs.readFile(path.join(ROOT, 'bundle/content.js'), 'utf8');
  assert.match(written, new RegExp(hash), 'bundle/content.js is stale — run npm run build');
  // dependency order: settings.js now imports crypto.js, so crypto is emitted
  // first and every module is defined before its importer
  assert.deepEqual(modules, [
    'src/crypto.js',
    'src/settings.js',
    'src/keyboard.js',
    'src/wiring.js',
    'src/content.js'
  ]);
});
