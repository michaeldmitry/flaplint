"""Guard against silent drift in the ops/pebble API surface flaplint anchors on.

flaplint reads charm source as text and never imports ops, so it cannot notice when
an ops rename quietly invalidates one of its sink/source anchors -- coverage would
just drop silently, with no error. These asserts turn that into a loud failure: if
ops removes or renames something flaplint matches on, the matching assert breaks on
the next dependency bump and points at the anchor that needs updating.

Each test names where flaplint relies on the anchor, so a failure is actionable.

Skipped when ops isn't installed (flaplint itself is stdlib-only). Install the dev
extra (``pip install -e .[dev]``) or run inside a charm venv to exercise it.
"""

from __future__ import annotations

import pytest

ops = pytest.importorskip("ops")


def _has_member(cls, name: str) -> bool:
    """True if ``cls`` exposes ``name`` as a method/attribute *or* an annotated
    instance attribute (``units: set[Unit]`` is set in ``__init__``, so it lives in
    ``__annotations__`` rather than on the class)."""
    return hasattr(cls, name) or name in getattr(cls, "__annotations__", {})


def test_relation_databag_and_units_anchors():
    # The databag sink is recognised by the shape ``<expr>.data[entity]``
    # (astutils.databag_expr); ``relation.units`` is the unordered-source anchor
    # (constants.UNORDERED_ATTRS = {"units"}).
    assert _has_member(ops.Relation, "data"), "databag sink shape `.data[...]`"
    assert _has_member(ops.Relation, "units"), "unordered source `relation.units`"


def test_typed_databag_save_anchor():
    # ``relation.save(obj, entity)`` is recognised as a databag write
    # (astutils, the `save` call shape). Added with ops typed relation data, so
    # this also flags if it's run against an ops too old to have it.
    assert hasattr(ops.Relation, "save"), "typed-databag write `relation.save(...)`"


def test_databag_entity_anchors():
    # ``relation.data[app | unit]`` is keyed by these two entity types
    # (astutils.databag_entity recognises `.app` / `.unit`).
    assert hasattr(ops, "Application"), "databag entity `relation.app`"
    assert hasattr(ops, "Unit"), "databag entity `relation.unit`"


def test_file_sink_anchors():
    # constants.FILE_WRITE_METHODS: the workload-container file sink.
    assert hasattr(ops.Container, "push"), "file sink `container.push`"


def test_plan_sink_anchors():
    # constants.PLAN_WRITE_METHODS: `container.add_layer` feeds the pebble plan,
    # and `container.replan` is what compares the plan and restarts services -- the
    # churn the plan sink guards against. (replan carries no content, so it is not
    # itself a sink, but the anchor documents the mechanism.)
    assert hasattr(ops.Container, "add_layer"), "plan sink `container.add_layer`"
    assert hasattr(ops.Container, "replan"), "plan-compare trigger `container.replan`"


def test_unordered_source_anchors():
    # constants.UNORDERED_CALLS: `container.list_files` is a directory listing
    # (unspecified order), recognised like os.listdir.
    assert hasattr(ops.Container, "list_files"), "unordered source `container.list_files`"


def test_relation_producer_anchors():
    # databag.py seeds Relation-ness from the ops Model API: `model.get_relation(...)`
    # produces a Relation, and `model.relations` is the RelationMapping. These are
    # what let a databag be followed through property layers.
    assert hasattr(ops.Model, "get_relation"), "Relation producer `model.get_relation`"
    assert _has_member(ops.Model, "relations"), "Relation mapping `model.relations`"
