/**
 * The Pages deploy's preflight step, executed for real.
 *
 * `.github/workflows/pages.yml` has one step whose whole job is to explain what
 * is wrong when the deploy cannot proceed, so "it fails with a clear message"
 * is a behaviour worth testing rather than trusting. This suite extracts that
 * step's shell script from the YAML, substitutes the `${{ }}` expressions the
 * way the runner does, and runs it against a fake Pages API.
 *
 * Four states are covered, which are the four a repository can be in:
 *
 *   404      Pages has never been enabled      → fail, with the settings link
 *   legacy   Pages deploys from a branch       → fail, naming `build_type`
 *   workflow Pages deploys from Actions        → continue
 *   403      the token cannot read Pages       → warn and continue
 *
 * The `403` case is why the script must not use `set -e` carelessly: under
 * `pipefail` a `grep` that finds no match aborts the script *before* it can
 * explain itself, so every case is asserted on its output, not just its exit
 * code.
 */
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WORKFLOW = path.join(ROOT, '..', '.github/workflows/pages.yml');
const STEP_NAME = 'Check the Pages setup';

const hasBash = spawnSync('bash', ['-c', 'exit 0']).status === 0;
const skip = hasBash ? false : 'bash is not available on this platform';

/** Pulls one `run: |` block out of the workflow, dedented like YAML would. */
function extractRunScript(yaml, stepName) {
  const lines = fs.readFileSync(yaml, 'utf8').split('\n');
  const start = lines.findIndex((line) => line.trim() === `- name: ${stepName}`);
  assert.notEqual(start, -1, `step "${stepName}" is missing from the workflow`);

  const collected = [];
  let indent = null;
  for (let i = start + 1; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*- name:/.test(line)) break; // next step
    const marker = /^(\s+)run: \|\s*$/.exec(line);
    if (marker) {
      indent = marker[1].length;
      continue;
    }
    if (indent === null) continue;
    if (line.trim() === '') {
      collected.push('');
      continue;
    }
    if (line.search(/\S/) < indent) break;
    collected.push(line.slice(indent));
  }
  assert.ok(collected.length, `step "${stepName}" has no run script`);

  // GitHub substitutes expressions before the shell sees the script.
  const substitutions = {
    'steps.pages.outcome': 'failure',
    'github.server_url': 'https://github.com',
    'github.repository': 'brodante/KryptBoard',
    'github.repository_owner': 'brodante',
    'github.event.repository.name': 'KryptBoard'
  };
  return collected.join('\n').replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (whole, expr) => {
    assert.ok(expr in substitutions, `the test does not model the expression ${whole}`);
    return substitutions[expr];
  });
}

/** Serves GET /repos/{owner}/{repo}/pages with the requested state. */
function startFakePagesApi(mode) {
  const bodies = {
    legacy: { url: 'https://brodante.github.io/KryptBoard/', status: 'built', build_type: 'legacy', source: { branch: 'main', path: '/' } },
    workflow: { url: 'https://brodante.github.io/KryptBoard/', status: 'built', build_type: 'workflow' },
    '403': { message: 'Resource not accessible by integration', status: '403' }
  };
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      const body = mode === '404' ? { message: 'Not Found' } : bodies[mode];
      const status = mode === '404' ? 404 : mode === '403' ? 403 : 200;
      res.writeHead(status, { 'content-type': 'application/json' });
      res.end(JSON.stringify(body));
    });
    server.listen(0, '127.0.0.1', () => resolve({ server, port: server.address().port }));
  });
}

/**
 * Runs the step against the fake API.
 *
 * `spawn` and not `spawnSync`: the fake server lives in *this* process, so
 * blocking the event loop would deadlock the curl call the step makes.
 */
function runStep(mode) {
  return new Promise(async (resolve, reject) => {
    const { server, port } = await startFakePagesApi(mode);
    const summary = path.join(fs.mkdtempSync('/tmp/kb-pages-test-'), 'summary.md');
    const child = spawn('bash', ['-c', extractRunScript(WORKFLOW, STEP_NAME)], {
      env: {
        ...process.env,
        GH_TOKEN: 'fake-token',
        GITHUB_API_URL: `http://127.0.0.1:${port}`,
        GITHUB_REPOSITORY: 'brodante/KryptBoard',
        GITHUB_SERVER_URL: 'https://github.com',
        GITHUB_STEP_SUMMARY: summary,
        GITHUB_ACTIONS: 'true'
      }
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.stderr.on('data', (chunk) => { stderr += chunk; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 30000);

    child.on('error', (error) => { clearTimeout(timer); server.close(); reject(error); });
    child.on('close', (status) => {
      clearTimeout(timer);
      server.close();
      const summaryText = fs.existsSync(summary) ? fs.readFileSync(summary, 'utf8') : '';
      resolve({ status, stdout, stderr, summary: summaryText });
    });
  });
}

test('a repository without Pages gets an instruction, not a stack trace', { skip }, async () => {
  const { status, stdout } = await runStep('404');
  assert.equal(status, 1, 'the step must fail: the deploy cannot proceed');
  assert.match(stdout, /GET \/pages → HTTP 404/);
  assert.match(stdout, /::error title=GitHub Pages is not enabled::/);
  assert.match(stdout, /https:\/\/github\.com\/brodante\/KryptBoard\/settings\/pages/);
  assert.match(stdout, /re-run this workflow/i);
});

test('Pages set to "deploy from a branch" is named as the problem', { skip }, async () => {
  const { status, stdout, summary } = await runStep('legacy');
  assert.equal(status, 1);
  assert.match(stdout, /build_type=legacy/);
  assert.match(stdout, /::error title=Pages is set to "legacy", not "GitHub Actions"::/);
  assert.match(stdout, /Source to "GitHub Actions"/);
  // the job summary spells out the whole fix, so it is readable from the run page
  assert.match(summary, /### Pages is deploying from a branch, not from Actions/);
  assert.match(summary, /Source → GitHub Actions/);
});

test('Pages already set to GitHub Actions lets the deploy continue', { skip }, async () => {
  const { status, stdout } = await runStep('workflow');
  assert.equal(status, 0, 'nothing to complain about');
  assert.match(stdout, /build_type=workflow/);
  assert.match(stdout, /configured for GitHub Actions deployments/);
  assert.equal(/::error/.test(stdout), false, 'no error annotation on the happy path');
});

test('a token that cannot read the Pages settings is a warning, not a failure', { skip }, async () => {
  const { status, stdout } = await runStep('403');
  assert.equal(status, 0, 'an unreadable setting is not proof of a misconfiguration');
  assert.match(stdout, /::warning title=Could not read the Pages settings::HTTP 403/);
  assert.match(stdout, /deploy step will report the real problem/);
});