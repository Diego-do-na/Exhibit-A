#!/usr/bin/env node
"use strict";

// This program is deliberately executed inside the pinned Node sandbox.  It parses source
// with the TypeScript compiler API and emits data only; it never loads repository modules.
const fs = require("fs");
const path = require("path");
const ts = require("typescript");

const MAX_FILES = 5000;
const MAX_FILE_BYTES = 1000000;
const MAX_TOTAL_BYTES = 50000000;
const EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts"]);
const SKIP = new Set(["node_modules", ".git", ".venv", "venv", "dist", "build", "__pycache__"]);

function text(node, source, limit = 120) {
  if (!node) return "";
  const value = node.getText(source).replace(/\s+/g, " ").trim();
  return value.length <= limit ? value : value.slice(0, limit - 3) + "...";
}
function isConst(node) {
  if (!node) return false;
  if (ts.isStringLiteral(node) || ts.isNumericLiteral(node) || node.kind === ts.SyntaxKind.TrueKeyword ||
      node.kind === ts.SyntaxKind.FalseKeyword || node.kind === ts.SyntaxKind.NullKeyword ||
      ts.isNoSubstitutionTemplateLiteral(node)) return true;
  return ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken &&
    isConst(node.left) && isConst(node.right);
}
function dotted(node) {
  const parts = [];
  let current = node;
  while (ts.isPropertyAccessExpression(current)) {
    parts.unshift(current.name.text);
    current = current.expression;
  }
  if (ts.isIdentifier(current)) {
    parts.unshift(current.text);
    return parts;
  }
  return null;
}
function walkFiles(root) {
  const files = [], skipped = [];
  let total = 0;
  function visit(dir) {
    if (files.length >= MAX_FILES || total >= MAX_TOTAL_BYTES) return;
    let names;
    try { names = fs.readdirSync(dir, {withFileTypes: true}); }
    catch (e) { skipped.push({file: path.relative(root, dir), reason: "cannot read directory"}); return; }
    for (const entry of names.sort((a, b) => a.name.localeCompare(b.name))) {
      if (files.length >= MAX_FILES || total >= MAX_TOTAL_BYTES) break;
      if (entry.name.startsWith(".") || SKIP.has(entry.name) || entry.isSymbolicLink()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { visit(full); continue; }
      if (!entry.isFile() || !EXTENSIONS.has(path.extname(entry.name))) continue;
      const rel = path.relative(root, full).split(path.sep).join("/");
      let stat;
      try { stat = fs.statSync(full); } catch { skipped.push({file: rel, reason: "cannot stat"}); continue; }
      if (stat.size > MAX_FILE_BYTES || total + stat.size > MAX_TOTAL_BYTES) {
        skipped.push({file: rel, reason: "file too large"}); continue;
      }
      try {
        const source = fs.readFileSync(full, "utf8");
        files.push({rel, source});
        total += Buffer.byteLength(source);
      } catch { skipped.push({file: rel, reason: "cannot read"}); }
    }
  }
  visit(root);
  return {files, skipped, truncated: files.length >= MAX_FILES || total >= MAX_TOTAL_BYTES};
}
function moduleName(rel) {
  return rel.replace(/\.(mjs|cjs|js|ts)$/, "").replace(/\/index$/, "").replace(/\//g, ".") || "index";
}
function resolveModule(from, spec, modules) {
  if (!spec.startsWith(".")) return spec;
  const base = path.posix.normalize(path.posix.join(path.posix.dirname(from), spec));
  for (const candidate of [base, `${base}.ts`, `${base}.js`, `${base}.mjs`, `${base}.cjs`,
    `${base}/index.ts`, `${base}/index.js`]) {
    if (modules.has(candidate)) return moduleName(candidate);
  }
  return spec;
}

function build(root) {
  const discovered = walkFiles(root);
  const modules = new Map(discovered.files.map(f => [f.rel, f]));
  const nodes = [], edges = [], nodeByName = new Map(), exports = new Map(), importsByFile = new Map();
  const sourceFiles = new Map();
  for (const file of discovered.files) {
    const scriptKind = file.rel.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.JS;
    const sf = ts.createSourceFile(file.rel, file.source, ts.ScriptTarget.Latest, true, scriptKind);
    sourceFiles.set(file.rel, sf);
    importsByFile.set(file.rel, new Map());
    exports.set(file.rel, new Map());
  }
  function addNode(file, kind, name, decl, params = [], decorators = []) {
    const id = `${moduleName(file)}:${name}`;
    if (nodeByName.has(id)) return nodeByName.get(id);
    const node = {id, kind, module: moduleName(file), name, file, line: sfLine(file, decl),
      start: sfLine(file, decl), end: sfEndLine(file, decl), is_async: !!(decl.modifiers || []).some(m => m.kind === ts.SyntaxKind.AsyncKeyword),
      params, decorators, bases: []};
    nodes.push(node); nodeByName.set(id, node); return node;
  }
  function sfLine(file, n) { return sourceFiles.get(file).getLineAndCharacterOfPosition(n.getStart(sourceFiles.get(file))).line + 1; }
  function sfEndLine(file, n) { return sourceFiles.get(file).getLineAndCharacterOfPosition(n.end).line + 1; }
  function decoratorInfo(file, decl) {
    const result = [];
    // TS 5.x decorators are exposed through modifiers; compatibility with older API is retained.
    for (const mod of (decl.modifiers || [])) if (mod.kind === ts.SyntaxKind.Decorator) {
      const expr = mod.expression;
      result.push({callee: ts.isCallExpression(expr) ? text(expr.expression, sourceFiles.get(file)) : text(expr, sourceFiles.get(file)),
        call: ts.isCallExpression(expr), path: ts.isCallExpression(expr) && expr.arguments.length && ts.isStringLiteral(expr.arguments[0]) ? expr.arguments[0].text : null});
    }
    return result;
  }
  function paramsOf(decl) { return decl.parameters ? decl.parameters.map(p => p.name.getText(sourceFiles.get(currentFile))) : []; }
  let currentFile = "";
  for (const file of discovered.files) {
    currentFile = file.rel;
    nodes.push({id: `${moduleName(file.rel)}:<module>`, kind: "module", module: moduleName(file.rel), name: "<module>",
      file: file.rel, line: 1, start: 1, end: sourceFiles.get(file.rel).getLineStarts().length, is_async: false, params: [], decorators: [], bases: []});
    function scan(node, prefix = "") {
      if (ts.isFunctionDeclaration(node) && node.name) {
        const n = addNode(file.rel, "function", `${prefix}${node.name.text}`, node,
          node.parameters.map(p => p.name.getText(sourceFiles.get(file.rel))), decoratorInfo(file.rel, node));
        if (node.modifiers && node.modifiers.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) exports.get(file.rel).set(node.name.text, n.id);
        scanChildren(node, `${prefix}${node.name.text}.<locals>`);
      } else if (ts.isClassDeclaration(node) && node.name) {
        const n = addNode(file.rel, "class", `${prefix}${node.name.text}`, node, [], decoratorInfo(file.rel, node));
        for (const member of node.members) {
          if (ts.isMethodDeclaration(member) && member.name) {
            const name = member.name.getText(sourceFiles.get(file.rel));
            const method = addNode(file.rel, "method", `${prefix}${node.name.text}.${name}`, member,
              member.parameters.map(p => p.name.getText(sourceFiles.get(file.rel))), decoratorInfo(file.rel, member));
            if (member.modifiers && member.modifiers.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) exports.get(file.rel).set(name, method.id);
            scanChildren(member, `${prefix}${node.name.text}.${name}.<locals>`);
          }
        }
        if (node.modifiers && node.modifiers.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) exports.get(file.rel).set(node.name.text, n.id);
      } else if (ts.isVariableStatement(node)) {
        for (const decl of node.declarationList.declarations) {
          if (ts.isIdentifier(decl.name) && decl.initializer && (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))) {
            const n = addNode(file.rel, "function", `${prefix}${decl.name.text}`, decl.initializer,
              decl.initializer.parameters.map(p => p.name.getText(sourceFiles.get(file.rel))), []);
            if (node.modifiers && node.modifiers.some(m => m.kind === ts.SyntaxKind.ExportKeyword)) exports.get(file.rel).set(decl.name.text, n.id);
          }
        }
      }
      scanChildren(node, prefix);
    }
    function scanChildren(node, prefix) { node.forEachChild(child => { if (!ts.isFunctionLike(child) || ts.isFunctionDeclaration(child) || ts.isMethodDeclaration(child)) scan(child, prefix); }); }
    sourceFiles.get(file.rel).forEachChild(n => scan(n));
  }
  // Imports and require aliases are collected after all module symbols exist.
  for (const file of discovered.files) {
    currentFile = file.rel; const sf = sourceFiles.get(file.rel), aliases = importsByFile.get(file.rel);
    function imports(node) {
      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        const mod = resolveModule(file.rel, node.moduleSpecifier.text, modules);
        const clause = node.importClause;
        if (clause) {
          if (clause.name) aliases.set(clause.name.text, `${mod}.*`);
          if (clause.namedBindings && ts.isNamespaceImport(clause.namedBindings)) aliases.set(clause.namedBindings.name.text, `${mod}.*`);
          if (clause.namedBindings && ts.isNamedImports(clause.namedBindings))
            for (const el of clause.namedBindings.elements) aliases.set(el.name.text, `${mod}:${el.propertyName ? el.propertyName.text : el.name.text}`);
        }
      }
      if (ts.isVariableStatement(node)) for (const d of node.declarationList.declarations) {
        if (ts.isIdentifier(d.name) && d.initializer && ts.isCallExpression(d.initializer) &&
            ts.isIdentifier(d.initializer.expression) && d.initializer.expression.text === "require" &&
            d.initializer.arguments.length && ts.isStringLiteral(d.initializer.arguments[0])) {
          aliases.set(d.name.text, `${resolveModule(file.rel, d.initializer.arguments[0].text, modules)}.*`);
        }
      }
      node.forEachChild(imports);
    }
    imports(sf);
  }
  const functionFor = (file, pos) => {
    const line = sourceFiles.get(file).getLineAndCharacterOfPosition(pos).line + 1;
    return nodes.filter(n => n.file === file && (n.kind === "function" || n.kind === "method") && n.start <= line && line <= n.end)
    .sort((a, b) => (b.end - b.start) - (a.end - a.start))[0] || nodes.find(n => n.file === file && n.kind === "module");
  };
  const addEdge = (e) => { if (!edges.some(x => JSON.stringify(x) === JSON.stringify(e))) edges.push(e); };
  for (const file of discovered.files) {
    currentFile = file.rel; const sf = sourceFiles.get(file.rel), aliases = importsByFile.get(file.rel);
    function calls(node) {
      if (ts.isCallExpression(node)) {
        const owner = functionFor(file.rel, node.getStart(sf)); const chain = dotted(node.expression);
        if (owner && chain) {
          let target = chain.join("."), ref = aliases.get(chain[0]);
          if (ref) target = ref.endsWith(".*") ? `${ref.slice(0, -2)}.${chain.slice(1).join(".")}` : `${ref.split(":")[0]}.${ref.split(":")[1]}${chain.length > 1 ? "." + chain.slice(1).join(".") : ""}`;
          const targetParts = target.split(".");
          const importedId = targetParts.length > 1
            ? nodeByName.get(`${targetParts.slice(0, -1).join(".")}:${targetParts[targetParts.length - 1]}`)
            : null;
          const local = nodeByName.get(`${moduleName(file.rel)}:${target}`) || importedId ||
            (ref && ref.includes(":") ? nodeByName.get(`${ref.split(":")[0]}:${ref.split(":")[1]}`) : null);
          const args = node.arguments.slice(0, 3).map(a => text(a, sf, 600));
          const kwargs = {};
          const line = sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1;
          if (local) addEdge({src: owner.id, dst: local.id, kind: "call", line, text: chain.join("."), via: "", args: [], kwargs: {}, ref: false});
          else {
            const imported = target.match(/^([^.]+)\.(.+)$/) && ref ? target : (target.includes(".") ? target : "");
            const dst = imported || target;
            addEdge({src: owner.id, dst, kind: "external", line, text: chain.join("."), via: "", args, kwargs, ref: false});
          }
          for (const arg of node.arguments) {
            const ad = dotted(arg);
            if (!ad) continue;
            const a = nodeByName.get(`${moduleName(file.rel)}:${ad.join(".")}`) || (aliases.has(ad[0]) && nodeByName.get(`${aliases.get(ad[0]).split(":")[0]}:${aliases.get(ad[0]).split(":")[1]}`));
            if (a) addEdge({src: owner.id, dst: a.id, kind: "ref", line, text: ad.join("."), via: chain.join("."), args: [], kwargs: {}, ref: true});
          }
        }
      }
      node.forEachChild(calls);
    }
    calls(sf);
  }
  // Express/Koa/Fastify route registrations and exported functions become entry metadata.
  const entries = [];
  for (const edge of edges) {
    if (edge.kind !== "external" || !/^(?:app|router|server|fastify)\.(get|post|put|patch|delete|use|all|route)$/.test(edge.text)) continue;
    const owner = nodes.find(n => n.id === edge.src); if (!owner) continue;
    const sf = sourceFiles.get(owner.file), call = findCallAt(sf, owner, edge.line);
    if (call) for (const arg of call.arguments.slice(1)) {
      const d = dotted(arg), target = d && nodeByName.get(`${moduleName(owner.file)}:${d.join(".")}`);
      if (target) { addEdge({src: owner.id, dst: target.id, kind: "ref", line: edge.line, text: d.join("."), via: edge.text, args: [], kwargs: {}, ref: true}); entries.push({node: target.id, kind: "route_table", oracle_name: target.name, detail: `${edge.text}(..., ${target.name})`}); }
    }
  }
  for (const [file, names] of exports) for (const id of names.values()) {
    const n = nodeByName.get(id); if (n && !entries.some(e => e.node === id)) entries.push({node: id, kind: "exported_handler", oracle_name: n.name, detail: "exported function"});
  }
  const stats = {files: discovered.files.length, nodes: nodes.length, edges: edges.length,
    resolved: edges.filter(e => !["external", "unresolved"].includes(e.kind)).length,
    external: edges.filter(e => e.kind === "external").length, unresolved: edges.filter(e => e.kind === "unresolved").length};
  return {schema_version: "1", files: discovered.files.map(f => f.rel).sort(), nodes: nodes.sort((a,b) => a.id.localeCompare(b.id)),
    edges: edges.sort((a,b) => a.src.localeCompare(b.src) || a.line - b.line || a.text.localeCompare(b.text)),
    skipped: discovered.skipped, truncated: discovered.truncated, stats, entry_points: entries};
}
function findCallAt(sf, owner, line) {
  let found = null;
  function visit(n) { if (ts.isCallExpression(n) && sf.getLineAndCharacterOfPosition(n.getStart(sf)).line + 1 === line) found = n; n.forEachChild(visit); }
  visit(sf); return found;
}
const root = process.argv[2];
if (!root || !path.isAbsolute(root)) { console.error("usage: graph_builder.js ABSOLUTE_REPOSITORY"); process.exit(2); }
try { process.stdout.write(JSON.stringify(build(root))); }
catch (e) { console.error(`builder failure: ${e && e.message ? e.message : e}`); process.exit(1); }
