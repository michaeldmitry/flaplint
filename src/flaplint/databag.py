"""Databag-object provenance: tracking ops Relation / RelationData / databag objects.

Recognising the *object* a write lands on -- not one fixed write-shape -- lets a
databag be followed through property layers and ``.get(entity)`` access. Databag-ness
enters only through ops's public API, never a type name (which could collide with an
unrelated ``Relation`` class):

* a Relation comes from ``<model>.get_relation(...)``;
* ``<relation>.data`` is its RelationData mapping (recognised **only** on a value
  already known to be a Relation -- a bare ``.data`` is far too generic);
* indexing that mapping by an ``.app`` / ``.unit`` entity yields a single databag.

A write (``.update`` / ``.setdefault`` / ``[k] = ...``) on a databag is a sink, no
matter how many property/alias hops wrap it. The receiver-agnostic
``<x>.data[entity]`` / ``.data.get(entity)`` shapes are also databags (anchored on
``.data`` *plus* an entity index), which keeps the common inline write covered.
"""

from __future__ import annotations

import ast
from typing import Callable, Dict, Optional

from . import astutils

RELATION = "relation"
RELATION_DATA = "relation_data"
DATABAG = "databag"

#: increasing specificity, so a fixed point only ever strengthens a kind.
_ORDER = {None: 0, RELATION: 1, RELATION_DATA: 2, DATABAG: 3}


def stronger(a: Optional[str], b: Optional[str]) -> Optional[str]:
    """The more specific of two kinds (``databag`` > ``relation_data`` > …)."""
    return a if _ORDER[a] >= _ORDER[b] else b


def _entity_slice(node: ast.Subscript) -> ast.AST:
    sl = node.slice
    # py<3.9 wrapped the index in an ``ast.Index``; ``.value`` unwraps it. (``getattr``
    # rather than ``sl.value`` because ``ast.Index`` is a deprecated stub with no typed
    # ``value`` attribute -- the access is real at runtime.)
    return getattr(sl, "value") if isinstance(sl, ast.Index) else sl


def databag_kind(
    node: Optional[ast.AST],
    local_kinds: Dict[str, str],
    accessor_kind: Callable[[str], Optional[str]],
    _depth: int = 0,
) -> Optional[str]:
    """The databag-provenance kind of ``node``, or ``None`` if it isn't databag-related.

    ``local_kinds`` maps a local variable name to its kind; ``accessor_kind`` maps a
    ``self.<name>`` property/method to its return kind for the current class.
    """
    if node is None or _depth > 12:
        return None

    def rec(n: ast.AST) -> Optional[str]:
        return databag_kind(n, local_kinds, accessor_kind, _depth + 1)

    # Receiver-agnostic shapes, anchored on ``.data`` + an entity index.
    if astutils.databag_expr(node) or astutils.databag_get_call(node):
        return DATABAG

    # A local we've already classified.
    if isinstance(node, ast.Name):
        return local_kinds.get(node.id)

    # ops producer: ``<model>.get_relation(...)`` -> a Relation.
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get_relation"
    ):
        return RELATION

    # ``self.<accessor>`` / ``self.<accessor>(...)`` -> the accessor's return kind.
    target = node.func if isinstance(node, ast.Call) else node
    if (
        isinstance(target, ast.Attribute)
        and isinstance(target.value, ast.Name)
        and target.value.id in ("self", "cls")
    ):
        k = accessor_kind(target.attr)
        if k is not None:
            return k

    # ``<relation>.data`` -> the RelationData mapping (only on a known Relation).
    if (
        isinstance(node, ast.Attribute)
        and node.attr == "data"
        and rec(node.value) == RELATION
    ):
        return RELATION_DATA

    # ``<relation_data>[entity]`` -> a databag.
    if (
        isinstance(node, ast.Subscript)
        and astutils.is_entity(_entity_slice(node))
        and rec(node.value) == RELATION_DATA
    ):
        return DATABAG

    # ``<relation_data>.get(entity)`` -> a databag.
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
        and astutils.is_entity(node.args[0])
        and rec(node.func.value) == RELATION_DATA
    ):
        return DATABAG

    return None
