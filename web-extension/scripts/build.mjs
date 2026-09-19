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
import { fileURLToPath } from 'node:url';
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

async function assertManifestPaths(manifest) {
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
      await fs.access(path.join(ROOT, relative));
    } catch (error) {
      problems.push(`manifest references a missing file: ${relative}`);
    }
  }

  for (const entry of manifest.web_accessible_resources || []) {
    for (const relative of entry.resources || []) {
      if (relative.includes('*')) continue;
      try {
        await fs.access(path.join(ROOT, relative));
      } catch (error) {
        problems.push(`web_accessible_resources references a missing file: ${relative}`);
      }
    }
  }
  return problems;
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

  const problems = await assertManifestPaths(manifest);
  if (problems.length) {
    console.error(`✗ manifest check failed:\n  - ${problems.join('\n  - ')}`);
    process.exitCode = 1;
    return;
  }
  console.log('✓ manifest references resolve');

  if (makeZip) {
    const name = `kryptboard-${manifest.version}.zip`;
    // index.html is a preview convenience; it is not part of the extension.
    const exclude = ['-x', 'node_modules/*', 'tests/*', 'scripts/*', 'demo/*', 'index.html', '*.zip', '*.md', '.gitignore'];
    try {
      await execFileAsync('zip', ['-qr', name, '.', '-x', ...exclude.slice(1)], { cwd: ROOT });
      const stats = await fs.stat(path.join(ROOT, name));
      console.log(`✓ packaged ${name} (${(stats.size / 1024).toFixed(1)} KiB)`);
    } catch (error) {
      console.warn(`! zip step skipped: ${error && error.message ? error.message : error}`);
    }
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
