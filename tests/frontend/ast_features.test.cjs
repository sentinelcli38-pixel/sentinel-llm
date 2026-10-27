"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const fs = require("node:fs");
const vm = require("node:vm");
const { batch } = require("../../training/ast_features/extract.cjs");

function entry(source, contract = "C") {
  return { key: "synthetic-fixture", contract, source,
    source_sha256: crypto.createHash("sha256").update(source).digest("hex") };
}
function parse(source, contract = "C") {
  return batch([entry(source, contract)])[0];
}
const count = (result, name) => result.features[`target.entry.sum.${name}`] || 0;

test("named target excludes unrelated contracts and string/comment security words", () => {
  const result = parse('contract Other { function bad() public { tx.origin.call(""); } } contract C { string note = "tx.origin.call"; function f() public { /* tx.origin */ } }');
  assert.equal(result.status, "parsed");
  assert.equal(count(result, "tx_origin"), 0);
  assert.equal(count(result, "call.call"), 0);
  assert.ok(!result.scoped_source.includes("contract Other"));
});

test("legacy value/gas call counted once with discarded result and lexical write ordering", () => {
  const result = parse('contract C { uint balance; function f() public { msg.sender.call.gas(9000).value(balance)(""); balance=0; } }');
  assert.equal(count(result, "call.call"), 1);
  assert.equal(count(result, "discarded.call"), 1);
  assert.equal(count(result, "value_option.call"), 1);
  assert.equal(count(result, "syntactic_write_after_call"), 1);
  assert.equal(count(result, "syntactic_write_before_call"), 0);
});

test("stored, returned, condition-tested and required call results remain distinct syntax", () => {
  const result = parse('contract C { function f(address a) public returns(bool) { bool ok=a.send(1); require(a.send(2)); if(a.send(3)) {} return a.send(4); } }');
  assert.equal(count(result, "call.send"), 4);
  assert.equal(count(result, "stored.send"), 1);
  assert.equal(count(result, "guarded_expression.send"), 1);
  assert.equal(count(result, "condition.send"), 1);
  assert.equal(count(result, "returned.send"), 1);
  assert.equal(count(result, "discarded.send"), 0);
});

test("modern call options and unchecked arithmetic parse without compiler execution", () => {
  const result = parse('pragma solidity ^0.8.20; contract C { uint balance; function f(address a) public { (bool ok,)=a.call{value: 1}(""); unchecked { balance++; } } }');
  assert.equal(result.status, "parsed");
  assert.equal(count(result, "call.call"), 1);
  assert.equal(count(result, "stored.call"), 1);
  assert.equal(count(result, "value_option.call"), 1);
  assert.equal(count(result, "arithmetic_unchecked_block"), 1);
  assert.equal(result.features["context.pragma_first_minor"], 8);
});

test("in-file bases and applied modifier syntax are retained without including unrelated siblings", () => {
  const result = parse('contract B { modifier auth() { require(tx.origin==msg.sender); _; } function inherited() public {} } contract C is B, Missing { function f() public auth {} } contract Sibling { function bad() public { msg.sender.send(1); } }');
  assert.equal(result.status, "parsed");
  assert.equal(result.features["context.in_file_base_count"], 1);
  assert.deepEqual(result.unresolved_bases, ["Missing"]);
  assert.equal(result.features["target.entry.modifier.tx_origin_in_guard"], 1);
  assert.equal(result.features["base.functions.entry"], 1);
  assert.ok(!result.scoped_source.includes("contract Sibling"));
});

test("local or parameter shadowing does not become a state-write feature", () => {
  for (const source of ['contract C { uint balance; function f(uint balance) public { msg.sender.send(1); balance=0; } }',
    'contract C { uint balance; function f() public { uint balance; msg.sender.send(1); balance=0; } }']) {
    const result = parse(source);
    assert.equal(count(result, "syntactic_state_write"), 0);
    assert.equal(count(result, "syntactic_write_after_call"), 0);
  }
});

test("internal functions and old-style constructors have separate feature roles", () => {
  const result = parse('contract C { function C() public { msg.sender.send(1); } function secret() internal { msg.sender.send(2); } function f() public {} }');
  assert.equal(count(result, "call.send"), 0);
  assert.equal(result.features["target.constructor.sum.call.send"], 1);
  assert.equal(result.features["target.internal.sum.call.send"], 1);
});

test("parse errors, missing and ambiguous targets retain whole-source fallback with explicit status", () => {
  for (const [source, status] of [["contract C { function broken(", "parse_error"],
    ["contract Other {}", "target_missing"], ["contract C {} contract C {}", "target_ambiguous"]]) {
    const result = parse(source);
    assert.equal(result.status, status);
    assert.equal(result.scoped_source, source);
    assert.equal(result.features[`extraction.${status}`], 1);
  }
});

test("legacy modifier placeholder without semicolon retains a parser-internal-error fallback", () => {
  const source = "contract C { modifier auth { if (msg.sender == owner) _ } address owner; function f() auth {} }";
  const result = parse(source);
  assert.equal(result.status, "parser_internal_error");
  assert.equal(result.scoped_source, source);
  assert.equal(result.features["extraction.parser_internal_error"], 1);
  assert.equal(result.diagnostic.kind, "TypeError");
});

test("parser AST-builder generic errors remain explicit rather than dropping malformed input", () => {
  const source = "contract C { modifier x { if() _; } }";
  const result = parse(source);
  assert.equal(result.status, "parser_internal_error");
  assert.equal(result.scoped_source, source);
  assert.equal(result.diagnostic.kind, "Error");
});

test("worker never accepts labels or a mismatched source hash", () => {
  assert.throws(() => batch([{ ...entry("contract C {}"), vulnerable: true }]), /source-only/);
  assert.throws(() => batch([{ ...entry("contract C {}"), source_sha256: "0".repeat(64) }]), /source-only/);
});

test("identifier renaming leaves numeric features unchanged and produces finite counts", () => {
  const a = parse('contract C { uint balance; function f(address receiver) public { receiver.send(balance); balance=0; } }');
  const b = parse('contract D { uint deposit; function withdraw(address target) public { target.send(deposit); deposit=0; } }', "D");
  assert.deepEqual(a.features, b.features);
  assert.ok(Object.values(a.features).every(value => Number.isFinite(value) && value >= 0));
});

test("same source can be assessed for two different targets without cache contamination", () => {
  const source = 'contract C { function f() public { msg.sender.send(1); } } contract D { function f() public {} }';
  const result = batch([entry(source, "C"), entry(source, "D")]);
  assert.equal(count(result[0], "call.send"), 1);
  assert.equal(count(result[1], "call.send"), 0);
});

test("resource and feature-extractor errors abort instead of being disguised as source fallbacks", () => {
  function isolated(parse) {
    const fakeParser = { parse, ParserError: class extends Error {} };
    const sandbox = { module: { exports: {} }, Error, RangeError, TypeError,
      require: name => name === "@solidity-parser/parser" ? fakeParser : require(name) };
    vm.runInNewContext(fs.readFileSync(require.resolve("../../training/ast_features/extract.cjs"), "utf8"), sandbox);
    return sandbox.module.exports;
  }
  assert.throws(() => isolated(() => { throw new RangeError("synthetic depth limit"); }).batch([entry("contract C {}")]), RangeError);
  assert.throws(() => isolated(() => ({ children: null })).batch([entry("contract C {}")]), /filter/);
});
