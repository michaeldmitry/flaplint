"""Interprocedural summary computation.

Each function's summary -- which parameters reach a sink, and how taint flows to
the return value -- depends on the summaries of the functions it calls. We reach
a consistent set of summaries by iterating the whole function table to a fixed
point: keep re-analyzing until no summary changes. Termination is guaranteed
because every field only ever grows (booleans flip once, sets only gain members)
within a finite domain.
"""

from __future__ import annotations

import ast
from typing import List

from . import astutils
from .handlers import SummaryHandler
from .model import FuncInfo, Registry
from .traversal import FunctionAnalyzer


def compute_summaries(functions: List[FuncInfo], analyzer: FunctionAnalyzer) -> None:
    """Populate ``dangerous`` / ``returns_*`` on every function in place."""
    changed = True
    while changed:
        changed = False
        for fi in functions:
            handler = SummaryHandler(fi)
            analyzer.analyze(fi, handler)
            changed = changed or handler.changed


def _own_returns(node: ast.AST) -> List[ast.expr]:
    """Return values of ``node``'s own ``return`` statements (not nested defs)."""
    out: List[ast.expr] = []

    def walk(n: ast.AST) -> None:
        for child in ast.iter_child_nodes(n):
            if isinstance(
                child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)
            ):
                continue  # a nested scope owns its own returns
            if isinstance(child, ast.Return) and child.value is not None:
                out.append(child.value)
            walk(child)

    walk(node)
    return out


def _returns_a_databag(fi: FuncInfo, registry: Registry) -> bool:
    """True if ``fi`` returns a relation databag (directly or via another accessor)."""
    for value in _own_returns(fi.node):
        # direct: relation.data[entity] / relation.data.get(entity)
        if astutils.databag_expr(value) or astutils.databag_get_call(value):
            return True
        # chain: ``return self.<accessor>`` / ``return self.<accessor>(...)`` where
        # the named property/method is itself a databag accessor of this class.
        target = value.func if isinstance(value, ast.Call) else value
        if (
            isinstance(target, ast.Attribute)
            and isinstance(target.value, ast.Name)
            and target.value.id in ("self", "cls")
        ):
            for other in registry.get(target.attr, []):
                if other.class_name == fi.class_name and other.returns_databag:
                    return True
    return False


def mark_databag_accessors(functions: List[FuncInfo], registry: Registry) -> None:
    """Set ``returns_databag`` on every property/method that returns a databag.

    A small fixed point so a chain of accessors (``unit_data`` -> ``_peer_data`` ->
    ``relation.data[entity]``) all resolve. Runs before the taint summaries so the
    traversal can treat ``self.<accessor>.update(...)`` as a databag write.
    """
    changed = True
    while changed:
        changed = False
        for fi in functions:
            if not fi.returns_databag and _returns_a_databag(fi, registry):
                fi.returns_databag = True
                changed = True
