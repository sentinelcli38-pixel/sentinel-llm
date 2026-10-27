"""Experimental call-result and direct authorization checks over Slither objects."""

import argparse
import hashlib
import json
from collections import defaultdict, deque
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path
from typing import Literal


@dataclass(frozen=True)
class ResultStep:
    kind: Literal["call", "copy", "use"]
    reads: tuple[str, ...] = ()
    write: str | None = None


def unused_results(steps: list[ResultStep]) -> list[int]:
    """Follow SSA copies; any non-copy use conservatively suppresses a warning."""
    readers = defaultdict(list)
    for step in steps:
        for value in step.reads:
            readers[value].append(step)
    unused = []
    for index, origin in enumerate(steps):
        if origin.kind != "call":
            continue
        pending, seen, consumed = deque([origin.write] if origin.write else []), set(), False
        while pending and not consumed:
            value = pending.popleft()
            if value in seen:
                continue
            seen.add(value)
            for reader in readers[value]:
                if reader.kind == "copy" and reader.write:
                    pending.append(reader.write)
                else:
                    consumed = True
                    break
        if not consumed:
            unused.append(index)
    return unused


def origin_authorization_paths(expression, depth: int = 0) -> set[frozenset[str]] | None:
    """Summarize direct equality guards; unknown syntax is deliberately unsupported.

    Each alternative records origin/sender requirements, not runtime feasibility.
    There are at most four summaries regardless of the Boolean tree's size.
    """
    from slither.core.declarations import SolidityVariableComposed
    from slither.core.expressions import (
        BinaryOperation,
        BinaryOperationType,
        Identifier,
    )
    from slither.core.variables.state_variable import StateVariable

    if depth >= 64 or not isinstance(expression, BinaryOperation):
        return None
    left, right = expression.expression_left, expression.expression_right
    if expression.type in (BinaryOperationType.ANDAND, BinaryOperationType.OROR):
        a = origin_authorization_paths(left, depth + 1)
        b = origin_authorization_paths(right, depth + 1)
        if a is None or b is None:
            return None
        if expression.type == BinaryOperationType.OROR:
            return a | b
        return {x | y for x in a for y in b}
    if expression.type != BinaryOperationType.EQUAL:
        return None

    def builtin(value):
        if isinstance(value, Identifier) and isinstance(value.value, SolidityVariableComposed):
            return value.value.name
        return None

    def authority(value):
        return (isinstance(value, Identifier) and isinstance(value.value, StateVariable)
                and str(value.value.type) in {"address", "address payable"})

    names = {builtin(left), builtin(right)}
    if names == {"msg.sender", "tx.origin"}:
        return {frozenset({"sender"})}
    for identity, other in ((left, right), (right, left)):
        name = builtin(identity)
        if authority(other) and name in {"tx.origin", "msg.sender"}:
            return {frozenset({"origin" if name == "tx.origin" else "sender"})}
    return None


def origin_guard_findings(function) -> list[dict]:
    from slither.core.declarations import SolidityFunction
    from slither.core.expressions import CallExpression, Identifier
    from slither.utils.output import Output

    findings = []
    for node in function.nodes:
        expression = node.expression
        if not (isinstance(expression, CallExpression) and isinstance(expression.called, Identifier)
                and isinstance(expression.called.value, SolidityFunction)
                and expression.called.value.name in {"require(bool)", "require(bool,string)", "assert(bool)"}
                and expression.arguments):
            continue
        paths = origin_authorization_paths(expression.arguments[0])
        if paths is None or frozenset({"origin"}) not in paths:
            continue
        output = Output([node, " in ", function,
                         " has a direct authorization alternative relying on tx.origin without a sender equality guard\n"])
        item = output.data
        item.update(check="origin-auth-alternative", impact="Medium", confidence="Medium")
        item["additional_fields"] = {
            "experimental": True, "engine": "slither-ast",
            "scope": "Direct require/assert equality guards against address state variables only. "
                     "No aliases, helper calls, path feasibility, preceding guards, or exploitability proof.",
        }
        findings.append(item)
    return findings


def execution_context(item: dict, function) -> dict:
    """Keep declaration locations while identifying the compiled execution contract."""
    from slither.utils.output import Output

    if function.contract != function.contract_declarer:
        fields = item.setdefault("additional_fields", {})
        fields.update(execution_contract=function.contract.name,
                      declaring_contract=function.contract_declarer.name,
                      function_signature=function.full_name,
                      attribution="compiled-inherited-entry-point")
        context = Output(["Execution contract: ", function.contract, "\n"])
        item["elements"].extend(context.data["elements"])
        item["description"] += context.data["description"]
        item["markdown"] = item.get("markdown", "") + context.data["markdown"]
        item["id"] = hashlib.sha256(f"{item.get('id', '')}:{function.contract.name}".encode()).hexdigest()
    return item


def inherited_reentrancy_findings(analysis) -> list[dict]:
    from slither.core.declarations import FunctionContract
    from slither.detectors.reentrancy.reentrancy_benign import ReentrancyBenign
    from slither.detectors.reentrancy.reentrancy_eth import ReentrancyEth
    from slither.detectors.reentrancy.reentrancy_events import ReentrancyEvent
    from slither.detectors.reentrancy.reentrancy_read_before_write import (
        ReentrancyReadBeforeWritten,
    )

    class ContractEntries:
        def __init__(self, contract):
            self.contract = contract

        @property
        def functions_and_modifiers_declared(self):
            inherited = [function for function in self.contract.functions_entry_points
                         if function.contract_declarer != self.contract and not function.is_shadowed]
            return [*self.contract.functions_and_modifiers_declared, *inherited]

        def __getattr__(self, name):
            return getattr(self.contract, name)

    class InheritedContext:
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.contracts = [ContractEntries(contract) for contract in self.contracts]

        def generate_result(self, info, additional_fields=None):
            result = super().generate_result(info, additional_fields)
            function = next((value for value in info if isinstance(value, FunctionContract)), None)
            if (function is not None and function.contract != function.contract_declarer
                    and function in function.contract.functions_entry_points and not function.is_shadowed):
                result.data.setdefault("additional_fields", {}).update(
                    experimental=True, engine="slither-inherited-context",
                    underlying_detector=self.ARGUMENT.removeprefix("inherited-"),
                    scope="Slither rule on context-expanded inherited public/external entry points. "
                          "Not a new vulnerability rule, exploit proof, or arbitrary internal-call reachability analysis.")
                execution_context(result.data, function)
            return result

        def _detect(self):
            results = []
            for result in super()._detect():
                fields = result.data.get("additional_fields", {})
                if not fields.get("execution_contract"):
                    continue
                # The built-in rules add their primary function after generating
                # the output. Keep it first, not our appended context contract.
                elements = result.data["elements"]
                index = next((i for i, element in enumerate(elements)
                              if element.get("type") == "function"
                              and element.get("type_specific_fields", {}).get("signature") == fields["function_signature"]
                              and element.get("type_specific_fields", {}).get("parent", {}).get("name") == fields["declaring_contract"]), None)
                if index is None:
                    raise ValueError("Inherited reentrancy result lacks a primary declaration")
                elements.insert(0, elements.pop(index))
                results.append(result)
            return results

    # Pinned Slither detector hooks retain the actual FunctionContract objects;
    # inferring inheritance from rendered JSON names would lose override context.
    for detector in (ReentrancyEth, ReentrancyReadBeforeWritten, ReentrancyBenign, ReentrancyEvent):
        contextual = type(f"Inherited{detector.__name__}", (InheritedContext, detector),
                          {"ARGUMENT": f"inherited-{detector.ARGUMENT}"})
        analysis.register_detector(contextual)
    return [item for results in analysis.run_detectors() for item in results]


def analyze_project(project: Path) -> list[dict]:
    # Optional dependency: ordinary Sentinel commands must work without Slither's
    # Python package installed in their own interpreter.
    from slither import Slither
    from slither.slithir.operations import Assignment, LowLevelCall, Phi, Send, Unpack
    from slither.slithir.variables import (
        LocalIRVariable,
        TemporaryVariableSSA,
        TupleVariableSSA,
    )
    from slither.utils.output import Output

    analysis = Slither(str(project.resolve()))
    findings = []

    def token(variable, index=None):
        suffix = f":{index}" if index is not None else ""
        return f"{id(variable)}{suffix}"

    def reads(variable):
        if isinstance(variable, TupleVariableSSA):
            return [token(variable, i) for i in range(len(variable.type))]
        return [token(variable)]

    for contract in analysis.contracts:
        inherited_entries = [function for function in contract.functions_entry_points
                             if function.contract_declarer != contract and not function.is_shadowed]
        for function in [*contract.functions_and_modifiers_declared, *inherited_entries]:
            findings.extend(execution_context(item, function) for item in origin_guard_findings(function))
            operations = [ir for node in function.nodes for ir in node.irs_ssa]
            steps = []
            for ir in operations:
                write = getattr(ir, "lvalue", None)
                values = tuple(value for variable in ir.read for value in reads(variable))
                if isinstance(ir, (Send, LowLevelCall)):
                    # Modern low-level calls return (success, data). Reading data
                    # alone does not consume the success result.
                    target = token(write, 0) if isinstance(write, TupleVariableSSA) else token(write) if write is not None else None
                    step = ResultStep("call", values, target)
                elif isinstance(ir, (Assignment, Phi, Unpack)) and isinstance(write, (LocalIRVariable, TemporaryVariableSSA)):
                    if isinstance(ir, Unpack):
                        values = (token(ir.tuple, ir.index),)
                    # Storage writes and unknown uses are not treated as dead
                    # locals: another function may consume the stored result.
                    step = ResultStep("copy", values, token(write))
                else:
                    step = ResultStep("use", values)
                steps.append(step)
            for index in unused_results(steps):
                ir = operations[index]
                output = Output([ir.node, " in ", function, " has a call success result with no non-copy SSA use\n"])
                item = output.data
                item.update(check="unused-call-result", impact="Medium", confidence="Medium")
                item["additional_fields"] = {
                    "experimental": True, "engine": "slither-ssa",
                    "scope": "Dead success result only; any non-copy use suppresses this check. Not proof of exploitability.",
                }
                findings.append(execution_context(item, function))
    findings.extend(inherited_reentrancy_findings(analysis))
    return findings


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", type=Path)
    args = parser.parse_args()
    try:
        findings = analyze_project(args.project)
        document = {"success": True, "results": {"detectors": findings},
                    "engine": {"name": "sentinel-static", "slither_version": version("slither-analyzer"),
                               "implementation_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(), "experimental": True}}
    except Exception as exc:
        print(json.dumps({"success": False, "error": f"{type(exc).__name__}: {exc}", "results": {"detectors": []}}))
        raise SystemExit(2) from exc
    print(json.dumps(document))


if __name__ == "__main__":
    main()
