import pytest

from sentinel.analyzers.call_results import origin_authorization_paths


@pytest.fixture
def guards():
    pytest.importorskip("slither")
    from slither.core.declarations import SolidityVariableComposed
    from slither.core.expressions import (
        BinaryOperation,
        BinaryOperationType,
        Identifier,
    )
    from slither.core.solidity_types import ElementaryType
    from slither.core.variables.state_variable import StateVariable

    owner = StateVariable()
    owner.name = "owner"
    owner.type = ElementaryType("address")

    def eq(a, b):
        return BinaryOperation(a, b, BinaryOperationType.EQUAL)

    sender = Identifier(SolidityVariableComposed("msg.sender"))
    origin = Identifier(SolidityVariableComposed("tx.origin"))
    return {
        "sender": eq(sender, Identifier(owner)),
        "origin": eq(origin, Identifier(owner)),
        "reversed": eq(Identifier(owner), origin),
        "eoa": eq(origin, sender),
        "and": lambda a, b: BinaryOperation(a, b, BinaryOperationType.ANDAND),
        "or": lambda a, b: BinaryOperation(a, b, BinaryOperationType.OROR),
        "unsupported": origin,
    }


def test_or_retains_origin_only_alternative(guards):
    paths = origin_authorization_paths(guards["or"](guards["sender"], guards["origin"]))
    assert paths == {frozenset({"sender"}), frozenset({"origin"})}


def test_and_requires_sender_and_origin(guards):
    paths = origin_authorization_paths(guards["and"](guards["sender"], guards["origin"]))
    assert paths == {frozenset({"sender", "origin"})}


def test_nested_sender_guard_cannot_be_bypassed_by_inner_or(guards):
    tree = guards["and"](guards["or"](guards["sender"], guards["origin"]), guards["eoa"])
    assert frozenset({"origin"}) not in origin_authorization_paths(tree)


def test_eoa_comparison_is_not_origin_authorization(guards):
    assert origin_authorization_paths(guards["eoa"]) == {frozenset({"sender"})}
    assert origin_authorization_paths(guards["reversed"]) == {frozenset({"origin"})}


def test_unknown_operand_does_not_manufacture_authorization_path(guards):
    for kind in ("and", "or"):
        assert origin_authorization_paths(guards[kind](guards["origin"], guards["unsupported"])) is None


def test_deep_expression_is_bounded(guards):
    tree = guards["origin"]
    for _ in range(70):
        tree = guards["or"](tree, guards["sender"])
    assert origin_authorization_paths(tree) is None
