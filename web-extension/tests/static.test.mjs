/**
 * Static guarantees.
 *
 * These tests read the shipped files the way a reviewer (or the paper's
 * artefact evaluator) would, and fail if the extension ever grows a network
 * call, a permission it does not need, an external dependency, a dangling DOM
 * reference, or a mismatched version.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (relative) => fs.readFile(path.join(ROOT, relative), 'utf8');
const exists = async (relative) => {
  try {
    await fs.access(path.join(ROOT, relative));
    return true;
  } catch (error) {
    return false;
  }
};

async function sourceFiles() {
  const dir = path.join(ROOT, 'src');
  const entries = await fs.readdir(dir);
  return entries.filter((name) => name.endsWith('.js')).map((name) => `src/${name}`);
}

/* ------------------------------------------------------------------ */
/* manifest                                                            */
/* ------------------------------------------------------------------ */

test('manifest asks for the storage permission and nothing else', async () => {
  const manifest = JSON.parse(await read('manifest.json'));
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual(manifest.permissions, ['storage']);
  assert.deepEqual(manifest.host_permissions, []);
  assert.equal(manifest.externally_connectable, undefined);
  assert.equal(manifest.optional_permissions, undefined);
  assert.equal(manifest.devtools_page, undefined);
  assert.match(manifest.content_security_policy.extension_pages, /script-src 'self'/);
  assert.equal(manifest.background, undefined, 'no service worker: nothing needs to run outside a page');
  assert.equal(manifest.web_accessible_resources.length, 1);
  assert.deepEqual(manifest.web_accessible_resources[0].resources, ['src/keyboard.css']);
});

test('content script covers http(s) and file pages, in all frames', async () => {
  const manifest = JSON.parse(await read('manifest.json'));
  const [script] = manifest.content_scripts;
  assert.deepEqual(script.matches, ['http://*/*', 'https://*/*', 'file:///*']);
  assert.deepEqual(script.js, ['bundle/content.js']);
  assert.equal(script.all_frames, true);
  assert.equal(script.run_at, 'document_idle');
});

test('manifest version matches package.json and the icons exist at the claimed sizes', async () => {
  const manifest = JSON.parse(await read('manifest.json'));
  const pkg = JSON.parse(await read('package.json'));
  assert.equal(manifest.version, pkg.version);
  for (const size of [16, 32, 48, 128]) {
    const file = `assets/icons/icon-${size}.png`;
    assert.ok(await exists(file), `${file} is missing`);
    const png = await fs.readFile(path.join(ROOT, file));
    assert.equal(png.subarray(1, 4).toString('ascii'), 'PNG', `${file} is not a PNG`);
    // IHDR width/height are big-endian uint32 at offsets 16 and 20
    assert.equal(png.readUInt32BE(16), size, `${file} width`);
    assert.equal(png.readUInt32BE(20), size, `${file} height`);
  }
});

/* ------------------------------------------------------------------ */
/* no network, no eval, no third-party code                            */
/* ------------------------------------------------------------------ */

test('no source file can reach the network', async () => {
  const banned = [
    /\bfetch\s*\(/,
    /XMLHttpRequest/,
    /WebSocket/,
    /EventSource/,
    /sendBeacon/,
    /importScripts/,
    /\bnavigator\.connection\b/,
    /https?:\/\/(?!example\.test)/
  ];
  for (const file of await sourceFiles()) {
    const code = await read(file);
    for (const pattern of banned) {
      assert.equal(pattern.test(code), false, `${file} matches ${pattern} — the extension must stay offline`);
    }
  }
});

test('no eval, no new Function, no runtime code generation', async () => {
  for (const file of [...(await sourceFiles()), 'scripts/bundler.mjs', 'scripts/build.mjs']) {
    const code = await read(file);
    assert.equal(/\beval\s*\(/.test(code), false, `${file} uses eval`);
    assert.equal(/new\s+Function\s*\(/.test(code), false, `${file} uses new Function`);
    assert.equal(/document\.write\s*\(/.test(code), false, `${file} uses document.write`);
  }
});

test('the overlay has no external dependencies and no remote assets', async () => {
  for (const file of ['src/keyboard.js', 'src/keyboard.css', 'src/popup.html']) {
    const code = await read(file);
    // Author links in the footer are navigational (<a href>), not assets: they
    // are stripped before the check, so a stray <img>/<script>/@import is still
    // caught.
    const withoutAnchors = code.replace(/<a\b[^>]*>[\s\S]*?<\/a>/gi, '');
    assert.equal(/https?:\/\//.test(withoutAnchors), false, `${file} references a remote URL`);
    assert.equal(/@import|url\(\s*['"]?http/i.test(code), false, `${file} loads a remote asset`);
  }
  const pkg = JSON.parse(await read('package.json'));
  assert.deepEqual(Object.keys(pkg.dependencies || {}), [], 'the extension must ship with zero runtime dependencies');
});

test('elements toggled with the hidden attribute are really hidden, and the host resists page CSS', async () => {
  const css = await read('src/keyboard.css');
  const js = await read('src/keyboard.js');

  // The JS toggles visibility by setting `.hidden`; author `display:` rules beat
  // the UA stylesheet regardless of specificity, so the sheet must cover it.
  const toggled = new Set([...js.matchAll(/refs\.([A-Za-z]+)\.hidden\s*=/g)].map((m) => m[1]));
  assert.ok(toggled.size >= 4, `expected several elements to be toggled via .hidden, found ${[...toggled].join(', ')}`);
  assert.match(css, /\[hidden\][^{}]*\{[^}]*display:\s*none\s*!important/, 'the sheet must hide [hidden] elements explicitly');

  // A page must not be able to collapse or bury the overlay with its own CSS.
  assert.match(css, /:host\s*\{[^}]*position:\s*fixed\s*!important/);
  assert.match(css, /:host\s*\{[^}]*z-index:\s*\d+\s*!important/);
  assert.match(css, /:host\s*\{[^}]*display:\s*flex\s*!important/);
});

test('the plaintext buffer lives in a closed shadow root', async () => {
  const code = await read('src/keyboard.js');
  assert.match(code, /attachShadow\(\s*\{\s*mode:\s*'closed'\s*\}\s*\)/);
  assert.equal(/mode:\s*'open'/.test(code), false);
});

/* ------------------------------------------------------------------ */
/* markup ↔ script consistency                                         */
/* ------------------------------------------------------------------ */

test('every element id referenced by the popup script exists in its markup', async () => {
  const html = await read('src/popup.html');
  const js = await read('src/popup.js');
  const declared = new Set([...html.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));
  const referenced = [...js.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]);
  assert.ok(referenced.length > 10, 'expected the popup script to reference its controls');
  const missing = referenced.filter((id) => !declared.has(id));
  assert.deepEqual(missing, [], `popup.js references ids that do not exist: ${missing.join(', ')}`);
});

test('every element id referenced by the demo script exists in its markup', async () => {
  const html = await read('demo/demo.html');
  const js = await read('demo/demo.js');
  const declared = new Set([...html.matchAll(/id="([^"]+)"/g)].map((m) => m[1]));
  const referenced = [...js.matchAll(/\$\('([^']+)'\)/g)].map((m) => m[1]);
  const missing = referenced.filter((id) => !declared.has(id));
  assert.deepEqual(missing, [], `demo.js references ids that do not exist: ${missing.join(', ')}`);
});

test('every local file referenced by the demo page exists', async () => {
  const html = await read('demo/demo.html');
  const refs = [...html.matchAll(/(?:src|href)="([^"]+)"/g)].map((m) => m[1]).filter((r) => !/^https?:|^#|^data:/.test(r));
  for (const ref of refs) {
    const resolved = path.posix.normalize(path.posix.join('demo', ref));
    assert.ok(await exists(resolved), `demo.html references missing file ${ref}`);
  }
});

test('the demo page uses the real extension modules, not a copy', async () => {
  const js = await read('demo/demo.js');
  assert.match(js, /from '\.\.\/src\/wiring\.js'/);
  assert.match(js, /from '\.\.\/src\/crypto\.js'/);
  assert.match(js, /from '\.\.\/src\/settings\.js'/);
  assert.ok(await exists('src/wiring.js'));
});

/* ------------------------------------------------------------------ */
/* documentation promises                                              */
/* ------------------------------------------------------------------ */

test('the README documents the threat model and the honest limits', async () => {
  const readme = await read('README.md');
  for (const phrase of ['Threat model', 'Limitations', 'KryptBoard']) {
    assert.match(readme, new RegExp(phrase, 'i'), `README should discuss ${phrase}`);
  }
});

test('every surface carries the author watermark', async () => {
  const surfaces = ['src/popup.html', '../README.md', 'README.md'];
  for (const file of surfaces) {
    const text = await read(file);
    assert.match(text, /Made with love by/, `${file} is missing the watermark`);
    assert.match(text, /愛をこめて/, `${file} is missing the Japanese watermark line`);
    assert.match(text, /https:\/\/github\.com\/brodante\//, `${file} is missing the author link`);
  }
  // the demo page and the preview landing page carry it too
  for (const file of ['demo/demo.html', 'index.html']) {
    const text = await read(file);
    assert.match(text, /が作りました/, `${file} is missing the watermark`);
    assert.match(text, /href="https:\/\/github\.com\/brodante\/"/, `${file} is missing the author link`);
  }
});

test("the paper's DOI is linked wherever the watermark is, and in both READMEs", async () => {
  const doi = 'https://doi.org/10.1109/ICEI65890.2026.11447792';
  for (const file of ['src/popup.html', 'demo/demo.html', 'index.html', '../README.md', 'README.md']) {
    const text = await read(file);
    assert.ok(text.includes(doi), `${file} does not link the paper DOI`);
    assert.match(text, /ICEI65890\.2026\.11447792/, `${file} does not name the DOI`);
  }
  // the extension README cites the paper properly: authors, venue, pages
  const readme = await read('README.md');
  assert.match(readme, /## The paper/);
  assert.match(readme, /Surya Pratap Singh Chauhan/);
  assert.match(readme, /NIT Agartala/);
  assert.match(readme, /International Conference on Emerging Trends and Innovations in ICT/);
  assert.match(readme, /pp\. 1–6/);
  assert.match(readme, /https:\/\/ieeexplore\.ieee\.org\/document\/11447792\//);

  // and the repository is machine-citable
  const cff = await read('../CITATION.cff');
  assert.match(cff, /^cff-version: 1\.2\.0$/m);
  assert.match(cff, /doi: 10\.1109\/ICEI65890\.2026\.11447792/);
  assert.match(cff, /Secure Your Words Before You Send/);
  for (const author of ['Chauhan', 'Saha', 'Biswas', 'Kar']) {
    assert.match(cff, new RegExp(`family-names: ${author}`), `CITATION.cff is missing ${author}`);
  }
  assert.match(cff, /https:\/\/github\.com\/brodante\/KryptBoard/);
});

test('the GitHub Pages workflow publishes the preview, the demo and the zip', async () => {
  const workflow = await read('../.github/workflows/pages.yml');

  // it runs on the default branch, and can be started by hand
  assert.match(workflow, /branches: \[main\]/);
  assert.match(workflow, /workflow_dispatch:/);

  // the permissions the Pages deployment needs, and nothing broader
  assert.match(workflow, /pages: write/);
  assert.match(workflow, /id-token: write/);
  assert.match(workflow, /contents: read/);
  assert.equal(/contents: write/.test(workflow), false, 'the workflow must not ask to write to the repo');

  // the action pins and the deployment environment
  for (const action of [
    'actions/checkout@v4',
    'actions/setup-node@v4',
    'actions/configure-pages@v5',
    'actions/upload-pages-artifact@v3',
    'actions/deploy-pages@v4'
  ]) {
    assert.ok(workflow.includes(action), `the workflow is missing ${action}`);
  }
  assert.match(workflow, /name: github-pages/);

  // it stages exactly what the site needs, from web-extension/, and no Jekyll
  for (const item of ['index.html', 'demo', 'src', 'bundle', 'assets', 'manifest.json']) {
    assert.ok(workflow.includes(`web-extension/${item}`), `the site is missing ${item}`);
  }
  assert.match(workflow, /touch _site\/\.nojekyll/);
  assert.equal(/web-extension\/tests|web-extension\/scripts|node_modules/.test(workflow), false,
    'the site must not publish tests, tooling or dependencies');

  // the stale-bundle gate keeps Pages from ever publishing an out-of-date build
  assert.match(workflow, /scripts\/build\.mjs --check/);

  // the download button on the landing page points at the published zip
  const landing = await read('index.html');
  assert.match(landing, /href="kryptboard-latest\.zip"/);
  assert.match(workflow, /kryptboard-latest\.zip/);
});
