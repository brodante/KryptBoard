/**
 * Build + packaging tests.
 *
 * The bundle is the only artifact Chrome actually runs, so the release gate is
 * worth testing as thoroughly as the code it wraps: staleness detection, the
 * manifest cross-check, and the exact contents of the store zip.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';

import { bundleSources, readBundleHash } from '../scripts/bundler.mjs';
import { assertManifestPaths, packageZip, PACKAGE_EXCLUDES } from '../scripts/build.mjs';

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

async function tempDir(prefix) {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

test('the checked-in bundle matches the current sources', async () => {
  const { code, hash, modules } = await bundleSources({ root: ROOT, entry: 'src/content.js' });
  const onDisk = await readBundleHash(path.join(ROOT, 'bundle/content.js'));
  const file = await fs.readFile(path.join(ROOT, 'bundle/content.js'), 'utf8');

  assert.equal(onDisk, hash, 'run `npm run build` — the bundle is stale');
  assert.equal(file, code, 'the bundle bytes differ from a fresh build');
  assert.ok(modules.length >= 5);
  assert.match(file, /source-sha256:/);
});

test('--check passes on a fresh clone and fails on a stale bundle', async () => {
  const fresh = await execFileAsync(process.execPath, ['scripts/build.mjs', '--check'], { cwd: ROOT });
  assert.match(fresh.stdout, /is up to date/);

  // mutate the bundle in a scratch copy of the tree and re-check
  const scratch = await tempDir('kb-build-');
  await fs.cp(ROOT, path.join(scratch, 'ext'), {
    recursive: true,
    filter: (src) => !/(node_modules|\.git)$/.test(path.basename(src))
  });
  const ext = path.join(scratch, 'ext');
  await fs.writeFile(path.join(ext, 'bundle/content.js'), '// tampered\n', 'utf8');

  await assert.rejects(
    () => execFileAsync(process.execPath, ['scripts/build.mjs', '--check'], { cwd: ext }),
    (error) => {
      assert.equal(error.code, 1);
      assert.match(error.stderr, /is stale/);
      return true;
    }
  );
  await fs.rm(scratch, { recursive: true, force: true });
});

test('manifest validation accepts the real manifest and catches broken references', async () => {
  const manifest = JSON.parse(await fs.readFile(path.join(ROOT, 'manifest.json'), 'utf8'));
  assert.deepEqual(await assertManifestPaths(manifest, ROOT), []);

  const broken = structuredClone(manifest);
  broken.action.default_popup = 'src/does-not-exist.html';
  broken.content_scripts[0].js = ['bundle/missing.js'];
  broken.icons['128'] = 'assets/icons/absent.png';
  const problems = await assertManifestPaths(broken, ROOT);
  assert.equal(problems.length, 3, problems.join(' | '));
  assert.ok(problems.every((p) => /missing file/.test(p)));
});

test('the packaged zip contains the extension and nothing else', async () => {
  const manifest = JSON.parse(await fs.readFile(path.join(ROOT, 'manifest.json'), 'utf8'));
  const out = await tempDir('kb-zip-');
  const packaged = await packageZip(manifest, { root: ROOT, outDir: out });

  if (!packaged) {
    console.warn('zip binary unavailable — packaging test skipped');
    return;
  }
  assert.equal(packaged.name, `kryptboard-${manifest.version}.zip`);
  assert.ok(packaged.size > 20 * 1024, 'the package should contain the real sources');

  const { stdout } = await execFileAsync('unzip', ['-Z1', packaged.path]);
  const entries = stdout.trim().split('\n').map((line) => line.trim()).filter(Boolean);

  // required runtime files
  for (const required of ['manifest.json', 'bundle/content.js', 'src/crypto.js', 'src/keyboard.css', 'src/popup.html']) {
    assert.ok(entries.includes(required), `${required} is missing from the package`);
  }
  assert.ok(entries.some((e) => /^assets\/icons\/icon-128\.png$/.test(e)), 'icons are missing');

  // development-only files must never ship
  for (const forbidden of ['index.html', 'package.json', 'package-lock.json', 'README.md', 'tests/dom.test.mjs', 'scripts/build.mjs', 'demo/demo.js', 'bundle/content.js.map']) {
    assert.equal(entries.includes(forbidden), false, `${forbidden} must not be packaged`);
  }
  assert.equal(entries.some((e) => e.startsWith('node_modules/')), false);
  assert.equal(entries.some((e) => /\.zip$/.test(e)), false);

  // and the exclusion list covers every category we rely on
  for (const pattern of ['node_modules/*', 'tests/*', 'scripts/*', 'demo/*', 'index.html', 'package.json', 'package-lock.json']) {
    assert.ok(PACKAGE_EXCLUDES.includes(pattern), `${pattern} must be excluded`);
  }

  await fs.rm(out, { recursive: true, force: true });
});
