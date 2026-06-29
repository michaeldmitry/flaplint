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
from typing import List, Optional

from . import databag as dbg
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


def _returns_databag_kind(fi: FuncInfo, registry: Registry) -> Optional[str]:
    """Strongest databag-provenance kind ``fi`` returns (``None`` if not databag-y).

    Resolves ``self.<accessor>`` references against the (still-converging) kinds of
    same-class accessors, so a chain ``unit_data`` -> ``all_data`` -> ``_peers`` ->
    ``get_relation`` falls out over the fixed point.
    """

    def accessor_kind(attr: str) -> Optional[str]:
        for other in registry.get(attr, []):
            if other.class_name == fi.class_name and other.returns_databag_kind:
                return other.returns_databag_kind
        return None

    best: Optional[str] = None
    for value in _own_returns(fi.node):
        best = dbg.stronger(best, dbg.databag_kind(value, {}, accessor_kind))
    return best


def mark_databag_accessors(functions: List[FuncInfo], registry: Registry) -> None:
    """Set ``returns_databag_kind`` on every property/method that returns a databag
    object (a Relation, its RelationData, or a single databag).

    A small fixed point so a chain of accessors resolves: each pass can only
    *strengthen* a kind (``None`` -> ``relation`` -> ``relation_data`` -> ``databag``)
    as the accessors it depends on become known, so it terminates. Runs before the
    taint summaries, so the traversal can treat ``self.<accessor>.update(...)`` as a
    databag write.
    """
    changed = True
    while changed:
        changed = False
        for fi in functions:
            kind = _returns_databag_kind(fi, registry)
            if dbg.stronger(fi.returns_databag_kind, kind) != fi.returns_databag_kind:
                fi.returns_databag_kind = kind
                changed = True
