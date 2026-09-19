#!/usr/bin/env node
/**
 * Build + package.
 *
 *   node scripts/build.mjs            build bundle/content.js
 *   node scripts/build.mjs --check    fail if the checked-in bundle is stale
 *   node scripts/build.mjs --zip      also write kryptboard-<version>.zip
 *
 * The extension has no runtime dependencies, so this is all the "toolchain"
 * there is: bundle the content script, verify the manifest, optionally zip.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { bundleSources, readBundleHash } from './bundler.mjs';

const execFileAsync = promisify(execFile);
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = 'src/content.js';
const OUT = 'bundle/content.js';

const args = new Set(process.argv.slice(2));
const checkOnly = args.has('--check');
const makeZip = args.has('--zip');

async function readJson(relative) {
  return JSON.parse(await fs.readFile(path.join(ROOT, relative), 'utf8'));
}

/**
 * Verifies that every file the manifest points at actually exists. Exported so
 * the test suite can exercise the check itself, not just its happy path.
 */
export async function assertManifestPaths(manifest, root = ROOT) {
  const problems = [];
  const mustExist = [
    manifest.action && manifest.action.default_popup,
    manifest.background && manifest.background.service_worker,
    ...((manifest.content_scripts || []).flatMap((cs) => [...(cs.js || []), ...(cs.css || [])])),
    ...Object.values(manifest.icons || {}),
    ...Object.values((manifest.action && manifest.action.default_icon) || {})
  ].filter(Boolean);

  for (const relative of mustExist) {
    try {
      await fs.access(path.join(root, relative));
    } catch (error) {
      problems.push(`manifest references a missing file: ${relative}`);
    }
  }

  for (const entry of manifest.web_accessible_resources || []) {
    for (const relative of entry.resources || []) {
      if (relative.includes('*')) continue;
      try {
        await fs.access(path.join(root, relative));
      } catch (error) {
        problems.push(`web_accessible_resources references a missing file: ${relative}`);
      }
    }
  }
  return problems;
}

/** Files that exist in the repo but must never be shipped to the store. */
export const PACKAGE_EXCLUDES = [
  'node_modules/*',
  'tests/*',
  'scripts/*',
  'demo/*',
  'index.html',
  'package.json',
  'package-lock.json',
  '*.zip',
  '*.md',
  '.gitignore'
];

/** Writes kryptboard-<version>.zip into `outDir`. Returns null if zip is absent. */
export async function packageZip(manifest, { root = ROOT, outDir = root } = {}) {
  const name = `kryptboard-${manifest.version}.zip`;
  const target = path.join(outDir, name);
  try {
    await execFileAsync('zip', ['-qr', target, '.', '-x', ...PACKAGE_EXCLUDES], { cwd: root });
  } catch (error) {
    console.warn(`! zip step skipped: ${error && error.message ? error.message : error}`);
    return null;
  }
  const stats = await fs.stat(target);
  return { name, path: target, size: stats.size };
}

async function main() {
  const manifest = await readJson('manifest.json');
  const { code, hash, modules } = await bundleSources({ root: ROOT, entry: ENTRY });

  if (checkOnly) {
    const onDisk = await readBundleHash(path.join(ROOT, OUT)).catch(() => null);
    if (onDisk !== hash) {
      console.error(`✗ ${OUT} is stale (bundle ${onDisk || 'missing'} ≠ sources ${hash}). Run: npm run build`);
      process.exitCode = 1;
      return;
    }
    console.log(`✓ ${OUT} is up to date (${hash.slice(0, 12)}…)`);
  } else {
    await fs.mkdir(path.join(ROOT, 'bundle'), { recursive: true });
    await fs.writeFile(path.join(ROOT, OUT), code, 'utf8');
    console.log(`✓ bundled ${modules.length} modules → ${OUT}`);
    console.log(`  modules: ${modules.join(', ')}`);
    console.log(`  source-sha256: ${hash}`);
  }

  const problems = await assertManifestPaths(manifest, ROOT);
  if (problems.length) {
    console.error(`✗ manifest check failed:\n  - ${problems.join('\n  - ')}`);
    process.exitCode = 1;
    return;
  }
  console.log('✓ manifest references resolve');

  if (makeZip) {
    const packaged = await packageZip(manifest, { root: ROOT });
    if (packaged) console.log(`✓ packaged ${packaged.name} (${(packaged.size / 1024).toFixed(1)} KiB)`);
  }
}

// Only run when invoked as a script — importing this module (for tests) must
// not rebuild the extension as a side effect.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
  });
}
