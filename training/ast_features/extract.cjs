"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const parser = require("@solidity-parser/parser");

const LOW_LEVEL = new Set(["call", "callcode", "delegatecall", "staticcall", "send", "transfer"]);
const ARITHMETIC = new Set(["+", "-", "*", "/", "%", "**", "+=", "-=", "*=", "/=", "%="]);
const ASSIGNMENT = new Set(["=", "+=", "-=", "*=", "/=", "%=", "|=", "&=", "^=", "<<=", ">>="]);
const SAFE_METHODS = new Set(["add", "sub", "mul", "div", "mod"]);

function increment(features, key, value = 1) {
  features[key] = (features[key] || 0) + value;
}

function children(node) {
  const result = [];
  for (const [key, value] of Object.entries(node)) {
    if (["range", "loc", "comments", "errors", "tokens"].includes(key)) continue;
    for (const child of Array.isArray(value) ? value : [value]) {
      if (child && typeof child === "object" && typeof child.type === "string") result.push(child);
    }
  }
  return result;
}

function* walk(root) {
  if (!root) return;
  const stack = [{ node: root, parents: [] }];
  while (stack.length) {
    const current = stack.pop();
    yield current;
    const next = children(current.node);
    for (let i = next.length - 1; i >= 0; i--) {
      stack.push({ node: next[i], parents: [...current.parents, current.node] });
    }
  }
}

function member(node, base, name) {
  return node?.type === "MemberAccess" && node.memberName === name &&
    node.expression?.type === "Identifier" && node.expression.name === base;
}

function callKind(expression) {
  if (!expression) return null;
  if (expression.type === "MemberAccess") {
    if (LOW_LEVEL.has(expression.memberName)) return expression.memberName;
    if (["value", "gas"].includes(expression.memberName)) return callKind(expression.expression);
  }
  if (["FunctionCall", "NameValueExpression"].includes(expression.type)) return callKind(expression.expression);
  return null;
}

function rootIdentifier(node) {
  if (node?.type === "Identifier") return node.name;
  if (node?.type === "IndexAccess") return rootIdentifier(node.base);
  if (node?.type === "MemberAccess") return rootIdentifier(node.expression);
  return null;
}

function functionFeatures(fn, states) {
  const features = Object.create(null);
  const nodes = [...walk(fn)];
  const shadowed = new Set(nodes.filter(({ node }) => node.type === "VariableDeclaration")
    .map(({ node }) => node.name).filter(Boolean));
  const calls = [];
  const writes = [];
  for (const { node, parents } of nodes) {
    increment(features, `node.${node.type}`);
    const parent = parents.at(-1);
    if (parent) increment(features, `edge.${parent.type}.${node.type}`);
    if (node.type === "BinaryOperation" || node.type === "UnaryOperation") {
      increment(features, `operator.${node.operator}`);
      if (ARITHMETIC.has(node.operator) || ["++", "--"].includes(node.operator)) {
        increment(features, "arithmetic");
        if (parents.some(p => p.type === "UncheckedStatement")) increment(features, "arithmetic_unchecked_block");
      }
      const lhs = node.type === "BinaryOperation" && ASSIGNMENT.has(node.operator) ? node.left :
        node.type === "UnaryOperation" && ["++", "--", "delete"].includes(node.operator) ? node.subExpression : null;
      const name = rootIdentifier(lhs);
      if (name && states.has(name) && !shadowed.has(name)) {
        increment(features, "syntactic_state_write");
        writes.push(node.range);
      }
    }
    if (member(node, "tx", "origin")) {
      increment(features, "tx_origin");
      if (parents.some(p => p.type === "FunctionCall" && ["require", "assert"].includes(p.expression?.name))) {
        increment(features, "tx_origin_in_guard");
      }
      if (parents.some(p => p.type === "BinaryOperation" && ["==", "!="].includes(p.operator))) {
        increment(features, "tx_origin_comparison");
      }
    }
    if (member(node, "msg", "sender")) increment(features, "msg_sender");
    if (member(node, "msg", "value")) increment(features, "msg_value");
    if (node.type !== "FunctionCall") continue;
    if (node.expression?.type === "Identifier" && ["require", "assert", "revert", "selfdestruct", "suicide"].includes(node.expression.name)) {
      increment(features, `builtin.${node.expression.name}`);
    }
    if (node.expression?.type === "MemberAccess" && SAFE_METHODS.has(node.expression.memberName)) {
      increment(features, `math_named_method.${node.expression.memberName}`);
    }
    const kind = callKind(node.expression);
    // .value(x) and .gas(x) configure legacy calls; count only their terminal invocation.
    if (!kind || (node.expression?.type === "MemberAccess" && ["value", "gas"].includes(node.expression.memberName))) continue;
    if (parent?.type === "FunctionCall" && parent.expression === node) continue;
    if (parent?.type === "MemberAccess" && ["value", "gas"].includes(parent.memberName)) continue;
    increment(features, `call.${kind}`);
    calls.push(node.range);
    if (parent?.type === "ExpressionStatement") increment(features, `discarded.${kind}`);
    if (parent?.type === "ReturnStatement") increment(features, `returned.${kind}`);
    if (parents.some(p => p.type === "VariableDeclarationStatement" ||
        p.type === "BinaryOperation" && ASSIGNMENT.has(p.operator))) increment(features, `stored.${kind}`);
    if (parents.some(p => p.type === "IfStatement" && p.condition?.range &&
        p.condition.range[0] <= node.range[0] && p.condition.range[1] >= node.range[1])) increment(features, `condition.${kind}`);
    if (parents.some(p => p.type === "FunctionCall" && ["require", "assert"].includes(p.expression?.name))) {
      increment(features, `guarded_expression.${kind}`);
    }
    if ([...walk(node.expression)].some(({ node: n }) => n.type === "MemberAccess" && n.memberName === "value" ||
        n.type === "NameValueList" && n.names?.includes("value"))) increment(features, `value_option.${kind}`);
  }
  for (const call of calls) {
    if (writes.some(write => write[0] > call[1])) increment(features, "syntactic_write_after_call");
    if (writes.some(write => write[1] < call[0])) increment(features, "syntactic_write_before_call");
  }
  increment(features, "has_call_and_arithmetic", Number(calls.length > 0 && Boolean(features.arithmetic)));
  increment(features, "has_call_and_state_write", Number(calls.length > 0 && writes.length > 0));
  return features;
}

function failure(entry, status, diagnostic) {
  return { key: entry.key, source_sha256: entry.source_sha256, contract: entry.contract, status,
    features: { [`extraction.${status}`]: 1 }, scoped_source: entry.source,
    target_spans: [], unresolved_bases: [], diagnostic };
}

function extract(entry, ast) {
  const contracts = ast.children.filter(node => node.type === "ContractDefinition");
  const targets = contracts.filter(node => node.name === entry.contract);
  if (targets.length !== 1) return failure(entry, targets.length ? "target_ambiguous" : "target_missing", "Named target does not resolve uniquely");
  const features = { "extraction.parsed": 1 };
  const target = targets[0];
  const scope = [];
  const visited = new Set();
  const unresolved = new Set();
  const active = new Set();
  function add(contract) {
    if (active.has(contract)) {
      increment(features, "context.inheritance_cycle");
      return;
    }
    if (visited.has(contract)) return;
    visited.add(contract);
    active.add(contract);
    scope.push(contract);
    for (const base of contract.baseContracts) {
      const matches = contracts.filter(candidate => candidate.name === base.baseName.namePath);
      if (matches.length === 1) add(matches[0]);
      else unresolved.add(base.baseName.namePath);
    }
    active.delete(contract);
  }
  add(target);
  features["context.unresolved_base_count"] = unresolved.size;
  features["context.in_file_base_count"] = scope.length - 1;
  features["context.import_count"] = ast.children.filter(n => n.type === "ImportDirective").length;
  const pragmas = ast.children.filter(n => n.type === "PragmaDirective" && n.name === "solidity");
  features["context.solidity_pragma_count"] = pragmas.length;
  const version = pragmas[0]?.value.match(/(\d+)\.(\d+)(?:\.(\d+))?/);
  if (version) {
    features["context.pragma_first_major"] = Number(version[1]);
    features["context.pragma_first_minor"] = Number(version[2]);
    features["context.pragma_first_patch"] = Number(version[3] || 0);
  }
  const states = new Set(scope.flatMap(c => c.subNodes.filter(n => n.type === "StateVariableDeclaration")
    .flatMap(n => n.variables.map(v => v.name).filter(Boolean))));
  const modifiers = new Map();
  for (const contract of scope) {
    for (const node of contract.subNodes.filter(n => n.type === "ModifierDefinition")) {
      if (!modifiers.has(node.name)) modifiers.set(node.name, node);
      else increment(features, "context.modifier_name_ambiguity");
    }
  }
  for (const contract of scope) {
    const prefix = contract === target ? "target" : "base";
    increment(features, `${prefix}.kind.${contract.kind}`);
    for (const { node } of walk(contract)) {
      if (node.type === "ElementaryTypeName" && /^(u?int\d*|address|bool|bytes\d*)$/.test(node.name)) {
        increment(features, `${prefix}.type.${node.name}`);
      }
      if (node.type === "UsingForDeclaration") {
        increment(features, `${prefix}.using_for`);
        if (node.libraryName === "SafeMath") increment(features, `${prefix}.using_safemath_named`);
      }
    }
    for (const fn of contract.subNodes.filter(n => n.type === "FunctionDefinition")) {
      const role = fn.isConstructor || fn.name === contract.name ? "constructor" :
        ["public", "external", "default"].includes(fn.visibility) ? "entry" : "internal";
      increment(features, `${prefix}.functions.${role}`);
      increment(features, `${prefix}.mutability.${fn.stateMutability || "unspecified"}`);
      const statistics = functionFeatures(fn, states);
      for (const [name, value] of Object.entries(statistics)) {
        increment(features, `${prefix}.${role}.sum.${name}`, value);
        const maxKey = `${prefix}.${role}.max.${name}`;
        features[maxKey] = Math.max(features[maxKey] || 0, value);
      }
      for (const invocation of fn.modifiers) {
        increment(features, `${prefix}.${role}.modifiers`);
        const definition = modifiers.get(invocation.name);
        if (!definition) increment(features, `${prefix}.${role}.unresolved_modifier`);
        else for (const [name, value] of Object.entries(functionFeatures(definition, states))) {
          increment(features, `${prefix}.${role}.modifier.${name}`, value);
        }
      }
    }
  }
  return { key: entry.key, source_sha256: entry.source_sha256, contract: entry.contract,
    status: "parsed", features, scoped_source: scope.map(n => entry.source.slice(n.range[0], n.range[1] + 1)).join("\n"),
    target_spans: scope.map(n => ({ name: n.name, kind: n === target ? "target" : "in_file_base", range: n.range })),
    unresolved_bases: [...unresolved].sort(), diagnostic: null };
}

function batch(entries) {
  let previousHash = null;
  let ast = null;
  let diagnostic = null;
  let failureStatus = "parse_error";
  return entries.map((entry, index) => {
    if (index && index % 100 === 0) process.stderr.write(`Parsed source/target inputs: ${index}/${entries.length}\n`);
    if (Object.keys(entry).sort().join(",") !== "contract,key,source,source_sha256" ||
        typeof entry.key !== "string" || typeof entry.contract !== "string" || typeof entry.source !== "string" ||
        crypto.createHash("sha256").update(entry.source).digest("hex") !== entry.source_sha256) {
      throw new Error("Worker accepts source-only, hash-pinned named-target inputs");
    }
    if (entry.source_sha256 !== previousHash) {
      previousHash = entry.source_sha256;
      try {
        ast = parser.parse(entry.source, { range: true, tolerant: false });
        diagnostic = null;
      } catch (error) {
        ast = null;
        if (error instanceof parser.ParserError) {
          failureStatus = "parse_error";
          diagnostic = error.errors.map(e => ({ line: e.line, column: e.column, message: e.message.slice(0, 200) }));
        } else if (error instanceof Error && !(error instanceof RangeError)) {
          failureStatus = "parser_internal_error";
          diagnostic = { kind: error.name, message: error.message.slice(0, 200) };
        } else throw error;
      }
    }
    return ast ? extract(entry, ast) : failure(entry, failureStatus, diagnostic);
  });
}

if (require.main === module) {
  const input = JSON.parse(fs.readFileSync(0, "utf8"));
  if (!Array.isArray(input)) throw new Error("Expected an array of source-only entries");
  process.stdout.write(JSON.stringify(batch(input)) + "\n");
}

module.exports = { batch, functionFeatures };
