/**
 * A ~120-line ES-module bundler, just enough for this extension.
 *
 * Content scripts cannot be ES modules, so the sources are wrapped in a
 * module registry and concatenated into one classic script. Each module keeps
 * its own function scope (so private helpers cannot collide), imports become
 * __kbRequire() calls, and exports are copied onto a per-module exports
 * object. No dependencies, no transpiling, no eval at runtime.
 */

import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const IMPORT_RE = /^[ \t]*import\s*\{([\s\S]*?)\}\s*from\s*['"]([^'"]+)['"];?[ \t]*$/gm;
const EXPORT_DECL_RE = /^export[ \t]+(?:(async)[ \t]+)?(function|class|const|let|var)[ \t]+([A-Za-z0-9_$]+)/gm;

// `import`/`export` that survived the rewrite: statements (any position), the
// dynamic form, and namespace/default imports. `obj.import` must not match.
const RESIDUAL_IMPORT_RE = /(?:^|[^\w.$])import\s*[({*'"]|(?:^|[^\w.$])import\s+[\w$*{]/m;
const RESIDUAL_EXPORT_RE = /(?:^|[^\w.$])export\s+[\w$*{]/m;

/**
 * Blanks out comments *and* string/template literals, keeping newlines and
 * length so the residual-syntax scan only ever looks at real code. Prose can
 * legitimately contain the words "import" or "export" (a UI string here does),
 * and this is what keeps the detector from crying wolf. Regex literals are not
 * modelled: at worst a quote inside one produces a false positive, which fails
 * the build loudly rather than shipping broken code.
 */
function stripNonCode(source) {
  let out = '';
  let i = 0;
  const n = source.length;
  const blank = (ch) => (ch === '\n' ? '\n' : ' ');
  while (i < n) {
    const ch = source[i];
    const next = source[i + 1];
    if (ch === '/' && next === '/') {
      while (i < n && source[i] !== '\n') {
        out += ' ';
        i++;
      }
      continue;
    }
    if (ch === '/' && next === '*') {
      out += '  ';
      i += 2;
      while (i < n && !(source[i] === '*' && source[i + 1] === '/')) {
        out += blank(source[i]);
        i++;
      }
      out += '  ';
      i += 2;
      continue;
    }
    if (ch === "'" || ch === '"' || ch === '`') {
      const quote = ch;
      out += ' ';
      i++;
      while (i < n) {
        if (source[i] === '\\') {
          out += '  ';
          i += 2;
          continue;
        }
        if (source[i] === quote) {
          out += ' ';
          i++;
          break;
        }
        out += blank(source[i]);
        i++;
      }
      continue;
    }
    out += ch;
    i++;
  }
  return out;
}

export async function bundleSources({ root, entry }) {
  const modules = new Map(); // canonical id -> { id, code, deps: Set<string> }
  const order = [];

  async function load(id) {
    if (modules.has(id)) return modules.get(id);
    const absolute = path.join(root, id);
    let code = await fs.readFile(absolute, 'utf8');
    const deps = new Set();

    code = code.replace(IMPORT_RE, (match, names, spec) => {
      if (!spec.startsWith('.')) {
        throw new Error(`Bundler: bare import "${spec}" in ${id} cannot be bundled.`);
      }
      const depId = path.posix.normalize(path.posix.join(path.posix.dirname(id), spec));
      deps.add(depId);
      const bindings = names
        .split(',')
        .map((n) => n.trim())
        .filter(Boolean)
        .join(', ');
      return `const { ${bindings} } = __kbRequire(${JSON.stringify(depId)});`;
    });

    if (/^\s*export\s+default/m.test(code)) {
      throw new Error(`Bundler: default exports are not supported (${id}).`);
    }

    const exported = [];
    code = code.replace(EXPORT_DECL_RE, (match, isAsync, kind, name) => {
      exported.push(name);
      return `${isAsync ? 'async ' : ''}${kind} ${name}`;
    });

    // Anything the rewrite above did not consume — default imports, namespace
    // imports, dynamic import(), export lists, export * — would survive into
    // the output as real module syntax, which is a syntax error in the classic
    // script a content script has to be. Refuse instead of shipping it.
    // Comments are stripped first so prose cannot trip these checks, and the
    // lookbehind-ish prefix avoids matching properties such as `obj.import`.
    const residue = stripNonCode(code);
    if (RESIDUAL_IMPORT_RE.test(residue)) {
      throw new Error(`Bundler: unhandled import syntax in ${id} (only named imports from relative paths are supported).`);
    }
    if (RESIDUAL_EXPORT_RE.test(residue)) {
      throw new Error(`Bundler: unhandled export syntax in ${id}.`);
    }

    const tail = exported.map((name) => `__exports.${name} = ${name};`).join('\n');
    modules.set(id, { id, code, deps });
    // depth-first so dependencies are defined before their importers
    for (const dep of deps) await load(dep);
    if (!order.includes(id)) order.push(id);
    modules.get(id).tail = tail;
    return modules.get(id);
  }

  const entryMod = await load(entry);
  void entryMod;

  const hasher = crypto.createHash('sha256');
  const chunks = [];
  for (const id of order) {
    const mod = modules.get(id);
    hasher.update(`${id}\n`);
    hasher.update(mod.code);
    chunks.push(
      `__kbDefine(${JSON.stringify(id)}, function (__exports, __require) {\n${mod.code}\n${mod.tail}\n});`
    );
  }
  const hash = hasher.digest('hex');

  const body = [
    `/*! KryptBoard content bundle — generated by scripts/build.mjs. Do not edit. */`,
    `/* source-sha256: ${hash} */`,
    `(function () {`,
    `'use strict';`,
    `var __kbModules = Object.create(null);`,
    `var __kbCache = Object.create(null);`,
    `function __kbDefine(id, factory) { __kbModules[id] = factory; }`,
    `function __kbRequire(id) {`,
    `  if (__kbCache[id]) return __kbCache[id].exports;`,
    `  var factory = __kbModules[id];`,
    `  if (!factory) throw new Error('KryptBoard: unknown module ' + id);`,
    `  var module = { exports: {} };`,
    `  __kbCache[id] = module;`,
    `  factory(module.exports, __kbRequire);`,
    `  return module.exports;`,
    `}`,
    chunks.join('\n'),
    `__kbRequire(${JSON.stringify(entry)});`,
    `})();`,
    ''
  ].join('\n');

  return { code: body, hash, modules: order };
}

export async function readBundleHash(file) {
  const code = await fs.readFile(file, 'utf8');
  const match = code.match(/source-sha256:\s*([0-9a-f]{64})/);
  return match ? match[1] : null;
}
