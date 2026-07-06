"""A labelled flap/clean corpus and the ops-semantic anchors it depends on.

This is the data behind two guards (see ``test_corpus.py``):

* a **regression net** -- each case has a known verdict (`flap` / `clean`), so any
  edit to the engine that changes a verdict is caught; and
* an **ops-drift oracle** -- every case names the ops semantics its verdict assumes
  (``anchors``), and the oracle checks those assumptions still hold against the
  *installed* ops. flaplint reads source as text and never imports ops, so its verdict
  can't move when ops moves; the only way to notice ops drift is to assert the
  assumptions separately and tie them back to the cases they'd invalidate.

Why a *matrix*, and which ops we anchor on: see ``docs/ops-version-anchoring.md``. The
floor is the oldest ops a *supported Juju LTS* can run (Juju 2.9 LTS, Focal, Python
3.8 -> ops 2.x); the ceiling is the latest 3.x. The semantics below are invariant
across that whole window, so flaplint's single (version-free) assumption is correct for
any charm a person could deploy -- which is the property the oracle exists to verify.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional, Tuple

#: Oldest ops a *supported* Juju LTS can still run: Juju 2.9 LTS / Ubuntu Focal 20.04 /
#: Python 3.8 -> ops 2.x (ops 1.5 is EOL since 2024-04). The CI matrix should validate
#: the oracle against {this floor, latest 3.x}; locally it validates against whatever
#: ops is installed. Bump only when a Juju LTS leaves support.
OPS_FLOOR = "2.23"  # the supported ops 2.x LTS line


@dataclass(frozen=True)
class Anchor:
    """An assumption a case's verdict rests on, plus how to check it still holds.

    ``check`` is a predicate over the imported ``ops`` module returning True while the
    assumption holds; ``None`` marks a *frozen* assumption (the Python stdlib / language
    -- `set` is unordered, `sorted()` sanitises) that needs no runtime check.
    """

    id: str
    desc: str
    holds_for: str  # e.g. "ops>=2.0" or "stdlib"
    check: Optional[Callable[[object], bool]] = None


def _units_is_unordered(ops_mod: object) -> bool:
    """ops ``Relation.units`` is still an unordered ``set`` (not a sorted sequence).

    ops uses ``from __future__ import annotations``, so the annotation is the *string*
    ``"set[Unit]"``; fall back to resolved-type origin if it's ever a real type.
    """
    annot = getattr(getattr(ops_mod, "Relation"), "__annotations__", {}).get("units")
    if isinstance(annot, str):
        a = annot.lower().replace(" ", "")
        return (a.startswith("set[") or a in ("set", "frozenset") or "abstractset" in a) and (
            "sequence" not in a and "list[" not in a and "tuple[" not in a
        )
    try:
        import typing

        return typing.get_origin(annot) in (set, frozenset)
    except Exception:  # pragma: no cover - defensive
        return annot in (set, frozenset)


def _has(cls_name: str, member: str) -> Callable[[object], bool]:
    # An ops member may be a method/attribute *or* an annotated instance attribute
    # (``data: RelationData`` is set in ``__init__``, so it lives in ``__annotations__``
    # rather than on the class) -- mirror test_api_anchors._has_member.
    def check(ops_mod: object) -> bool:
        cls = getattr(ops_mod, cls_name, object)
        return hasattr(cls, member) or member in getattr(cls, "__annotations__", {})

    return check


#: Every assumption any case may reference. The oracle requires each case's anchors to
#: appear here (so an undocumented assumption is a test failure), and checks the ops-
#: typed ones against the installed ops.
ANCHORS: Tuple[Anchor, ...] = (
    # --- ops semantics (can drift on an ops bump) ---
    Anchor("ops:units-unordered", "Relation.units is an unordered set[Unit]",
           "ops>=2.0", _units_is_unordered),
    Anchor("ops:data-sink", "Relation.data is the databag mapping (.data[entity])",
           "ops>=2.0", _has("Relation", "data")),
    Anchor("ops:save-sink", "Relation.save(obj, entity) typed-databag write",
           "ops>=2.0", _has("Relation", "save")),
    Anchor("ops:push-file", "Container.push file write",
           "ops>=2.0", _has("Container", "push")),
    Anchor("ops:add_layer-plan", "Container.add_layer feeds the pebble plan",
           "ops>=2.0", _has("Container", "add_layer")),
    Anchor("ops:list_files-ordered", "Container.list_files lists via pebble's "
           "os.ReadDir -> sorted by filename (stable, not an unordered source)",
           "ops>=2.0", _has("Container", "list_files")),
    Anchor("ops:get_relation-producer", "Model.get_relation yields a Relation",
           "ops>=2.0", _has("Model", "get_relation")),
    # --- frozen stdlib / language semantics (no runtime check) ---
    Anchor("std:set-unordered", "a set has no stable iteration order", "stdlib"),
    Anchor("std:sorted-sanitises", "sorted() fixes order", "stdlib"),
    Anchor("std:json-sort_keys", "json.dumps(sort_keys=True) sorts mapping keys", "stdlib"),
    Anchor("std:yaml-sorts-keys", "yaml.safe_dump sorts mapping keys by default", "stdlib"),
    Anchor("std:glob-unordered", "glob returns paths in unspecified order", "stdlib"),
    Anchor("std:uuid4-volatile", "uuid4() is fresh every call", "stdlib"),
    Anchor("std:time-volatile", "time()/now() is fresh every call", "stdlib"),
)

ANCHOR_IDS = frozenset(a.id for a in ANCHORS)


@dataclass(frozen=True)
class Case:
    """One labelled snippet: its expected verdict and the assumptions it rests on."""

    id: str
    code: str
    expect: str  # "flap" | "clean"
    anchors: Tuple[str, ...]
    rule: str = ""  # optional expected finding rule when expect == "flap"


def _c(id, code, expect, anchors, rule=""):
    return Case(id, code, expect, tuple(anchors), rule)


CORPUS: Tuple[Case, ...] = (
    # -- relation.units (ops unordered source) x databag sink --
    _c("units-join-databag", """
        class Charm:
            def h(self):
                self.relation.data[self.app]["u"] = " ".join(self.relation.units)
    """, "flap", ["ops:units-unordered", "ops:data-sink"], "unordered-iteration"),
    _c("units-sorted-databag", """
        class Charm:
            def h(self):
                self.relation.data[self.app]["u"] = " ".join(sorted(self.relation.units))
    """, "clean", ["ops:units-unordered", "ops:data-sink", "std:sorted-sanitises"]),
    _c("units-list-databag", """
        class Charm:
            def h(self):
                self.relation.data[self.app]["u"] = list(self.relation.units)
    """, "flap", ["ops:units-unordered", "ops:data-sink"], "unordered-iteration"),
    _c("units-pick-first", """
        class Charm:
            def h(self):
                self.relation.data[self.app]["f"] = list(self.relation.units)[0]
    """, "flap", ["ops:units-unordered", "ops:data-sink"], "unordered-pick"),

    # -- stdlib set source x databag sink --
    _c("set-join-databag", """
        class Charm:
            def h(self):
                self.relation.data[self.app]["u"] = " ".join(set(self.items))
    """, "flap", ["std:set-unordered", "ops:data-sink"], "unordered-iteration"),
    _c("set-sorted-databag", """
        class Charm:
            def h(self):
                self.relation.data[self.app]["u"] = " ".join(sorted(set(self.items)))
    """, "clean", ["std:set-unordered", "std:sorted-sanitises", "ops:data-sink"]),

    # -- serializer key-sort semantics --
    _c("dict-from-set-sortkeys", """
        import json
        class Charm:
            def h(self):
                d = {k: 1 for k in set(self.items)}
                self.relation.data[self.app]["u"] = json.dumps(d, sort_keys=True)
    """, "clean", ["std:set-unordered", "std:json-sort_keys", "ops:data-sink"]),
    _c("dict-from-set-nosort", """
        import json
        class Charm:
            def h(self):
                d = {k: 1 for k in set(self.items)}
                self.relation.data[self.app]["u"] = json.dumps(d)
    """, "flap", ["std:set-unordered", "ops:data-sink"], "unordered-collection"),
    _c("bare-set-yaml-return", """
        import yaml
        class Charm:
            def render(self):
                d = {k: 1 for k in set(self.items)}
                return yaml.safe_dump(d)
    """, "clean", ["std:set-unordered", "std:yaml-sorts-keys"]),

    # -- relation.save (ops typed-databag sink) --
    _c("save-unstable-field", """
        class Charm:
            def h(self):
                self.relation.save(Model(items=list(set(self.items))), self.app)
    """, "flap", ["ops:save-sink", "std:set-unordered"]),
    _c("save-sorted-field", """
        class Charm:
            def h(self):
                self.relation.save(Model(items=sorted(set(self.items))), self.app)
    """, "clean", ["ops:save-sink", "std:sorted-sanitises"]),

    # -- container.push (file sink) --
    _c("push-join-set", """
        class Charm:
            def h(self, container):
                container.push("/f", " ".join(set(self.items)))
    """, "flap", ["ops:push-file", "std:set-unordered"], "unordered-iteration"),
    _c("push-sorted", """
        class Charm:
            def h(self, container):
                container.push("/f", " ".join(sorted(set(self.items))))
    """, "clean", ["ops:push-file", "std:sorted-sanitises"]),

    # -- container.add_layer (plan sink, structural compare) --
    _c("plan-command-join-set", """
        class Charm:
            def h(self, container):
                layer = {"services": {"s": {"command": " ".join(set(self.args))}}}
                container.add_layer("s", layer)
    """, "flap", ["ops:add_layer-plan", "std:set-unordered"]),

    # -- container.list_files (pebble sorts by filename) -> file : clean --
    # Self-attribute receiver, so the only thing under test is the list_files
    # ordering contract (a bare-parameter receiver would trip the separate
    # unannotated-param rule and mask it).
    _c("list-files-into-file", """
        class Charm:
            def __init__(self):
                self._container = None
            def h(self):
                names = [f.name for f in self._container.list_files("/etc")]
                self._container.push("/manifest", "\\n".join(names))
    """, "clean", ["ops:list_files-ordered", "ops:push-file"]),

    # -- get_relation producer -> databag --
    _c("get-relation-set-databag", """
        class Charm:
            def h(self):
                rel = self.model.get_relation("peer")
                rel.data[self.app]["u"] = " ".join(set(self.items))
    """, "flap", ["ops:get_relation-producer", "ops:data-sink", "std:set-unordered"],
        "unordered-iteration"),

    # -- mapping-write sink (.update) --
    _c("update-join-set", """
        class Charm:
            def h(self):
                self.relation.data[self.app].update({"u": " ".join(set(self.items))})
    """, "flap", ["ops:data-sink", "std:set-unordered"], "unordered-iteration"),

    # -- hash change-detector sink --
    _c("hash-list-set", """
        import hashlib, json
        class Charm:
            def h(self):
                return hashlib.sha256(json.dumps(list(set(self.items))).encode()).hexdigest()
    """, "flap", ["std:set-unordered"]),
    _c("hash-sorted", """
        import hashlib, json
        class Charm:
            def h(self):
                return hashlib.sha256(json.dumps(sorted(set(self.items))).encode()).hexdigest()
    """, "clean", ["std:sorted-sanitises"]),

    # -- volatile values --
    _c("uuid-databag", """
        import uuid
        class Charm:
            def h(self):
                self.relation.data[self.app]["id"] = str(uuid.uuid4())
    """, "flap", ["ops:data-sink", "std:uuid4-volatile"], "nondeterministic"),
    _c("time-databag", """
        import time
        class Charm:
            def h(self):
                self.relation.data[self.app]["t"] = str(time.time())
    """, "flap", ["ops:data-sink", "std:time-volatile"], "nondeterministic"),

    # -- glob (stdlib unordered source) --
    _c("glob-join-databag", """
        import glob
        class Charm:
            def h(self):
                self.relation.data[self.app]["f"] = ",".join(glob.glob("*.json"))
    """, "flap", ["std:glob-unordered", "ops:data-sink"], "unordered-iteration"),
    _c("glob-sorted-databag", """
        import glob
        class Charm:
            def h(self):
                self.relation.data[self.app]["f"] = ",".join(sorted(glob.glob("*.json")))
    """, "clean", ["std:glob-unordered", "std:sorted-sanitises", "ops:data-sink"]),
)
