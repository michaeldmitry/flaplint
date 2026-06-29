"""Core data model: taint origins, per-function summaries, and findings.

These types are deliberately free of behaviour so every other module can depend
on them without creating import cycles.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union

#: A taint origin -- *why* a value is considered unstable. One of:
#:
#: * ``("local", path, node, func)`` -- an unordered value born in this function (a
#:   ``set``, a ``glob`` result, ``relation.units`` ...). This is assumed to
#:   manifest as *dict-key* order, so a key-sorting serializer (``yaml.dump``,
#:   ``json.dumps(sort_keys=True)``) launders it back to stable. The tuple carries
#:   the *born site* (``path`` of the file and the AST ``node`` that created the
#:   collection, plus the owning ``func``) so a finding can point ``origin=`` at
#:   where the churn is created, not just where it is written. ``path``/``func``
#:   may be ``None`` placeholders meaning "the file/function currently analysed";
#: * ``("element", path, node, func)`` -- *value-position* order instability: an element
#:   picked from an unstable collection (``unordered_list[0]``) or a value
#:   carrying such a pick. Key-sorting a serializer cannot fix a list element /
#:   scalar pick, so it survives ``yaml.dump`` / ``json.dumps(sort_keys=True)``
#:   -- but ``sorted()`` on the underlying collection still neutralizes it. The
#:   tuple carries the *provenance* of the pick (``path`` of the file and the AST
#:   ``node`` of the subscript) so the finding can point at the offending pick
#:   rather than the blameless serializer. ``path`` may be ``None``, meaning "the
#:   file currently being analysed" (an in-function pick);
#: * ``"volatile"`` -- a nondeterministic value (``uuid4()``, ``time()``, ...);
#: * ``("param", index)`` -- the value carries the instability of parameter
#:   ``index`` of the enclosing function.
#: * ``("iterparam", index, path, node)`` -- a *sequence* built by iterating
#:   parameter ``index`` (``[f(x) for x in param.items()]``). The resulting list's
#:   *element order* mirrors the parameter's iteration order, which a key-sorting
#:   serializer cannot launder (only ``sorted()`` on the source can), so -- like
#:   ``element`` -- it survives ``yaml.dump`` / ``json.dumps(sort_keys=True)``.
#:   It is reported as a contract-boundary finding *at the iteration site*
#:   (``node`` in file ``path``; ``path`` may be ``None`` == the current file).
#:   Distinct from ``("param", index)`` so the iteration site is locatable.
#: * ``("itercaller", path, node, None)`` -- a *confirmed* sequence-iteration
#:   instability, reported as ``unordered-iteration`` (``kind=caller``, high
#:   confidence) pointing at ``node`` in file ``path`` (``path`` may be ``None``
#:   == the current file). Arises two ways, both meaning "a sequence whose
#:   element order derives from a genuinely-unordered source, and that order
#:   survives a key-sorting serializer":
#:     1. a call-site argument with known-unstable taint was passed to a callee
#:        that iterates that parameter unsorted into a sequence (recorded in the
#:        callee's ``FuncInfo.iter_params``) -- the *traced-parameter* case; or
#:     2. a locally-born unordered collection is *materialized into a sequence*
#:        in this function -- ``list(some_set)`` / ``tuple(relation.units)`` /
#:        ``[x for x in some_set]`` -- converting dict-key disorder into
#:        list-element disorder. The fix (``sorted()``) lands at ``node``.
#:
#: An empty origin set means the value is order-stable.
Origin = Union[str, Tuple[str, int], Tuple[str, Optional[str], ast.AST, Optional[str]]]


def is_element(o: "Origin") -> bool:
    """True if ``o`` is a value-position (``"element"``) origin tuple."""
    return isinstance(o, tuple) and len(o) == 4 and o[0] == "element"


def has_element(origins: "Set[Origin]") -> bool:
    """True if any origin in the set is a value-position pick."""
    return any(is_element(o) for o in origins)


def is_local(o: "Origin") -> bool:
    """True if ``o`` is a locally-born unordered-collection origin tuple."""
    return isinstance(o, tuple) and len(o) == 4 and o[0] == "local"


def is_iterparam(o: "Origin") -> bool:
    """True if ``o`` is a ``("iterparam", index, path, node)`` origin tuple."""
    return isinstance(o, tuple) and len(o) == 4 and o[0] == "iterparam"


def is_itercaller(o: "Origin") -> bool:
    """True if ``o`` is a confirmed ``("itercaller", path, node, None)`` origin.

    Emitted at a call site when a known-unstable argument flows into a callee
    that iterates that parameter unsorted into a sequence. Carries the callee's
    iteration site so the finding points there instead of at the databag write.
    """
    return isinstance(o, tuple) and len(o) == 4 and o[0] == "itercaller"


def has_itercaller(origins: "Set[Origin]") -> bool:
    """True if any origin is a confirmed iteration instability."""
    return any(is_itercaller(o) for o in origins)


def has_local(origins: "Set[Origin]") -> bool:
    """True if any origin in the set is a locally-born unordered collection."""
    return any(is_local(o) for o in origins)


def local_site(o: "Origin") -> Optional[Tuple[Optional[str], ast.AST, Optional[str]]]:
    """``(path, node, func)`` born-site of a ``local`` origin (``None`` if not one).

    ``path``/``func`` may be ``None`` placeholders meaning "the file/function
    currently being analysed", resolved by the consumer (mirrors ``element``).
    """
    if is_local(o):
        return (o[1], o[2], o[3])
    return None


@dataclass
class Finding:
    """A single reported issue as structured fields, ready to render or JSON-dump.

    The fields are deliberately discrete (rather than one prose ``detail``) so the
    output is machine-parseable and uniform: location, the failure ``rule``,
    severity, the offending ``variable``, and the ``sink`` it reaches.

    ``rule`` is one of three *non-overlapping* failure modes -- the reason the
    written value flaps across two otherwise-identical reconciles:

    * ``nondeterministic`` -- the value is *regenerated* every reconcile
      (``uuid4()`` / ``time()`` / ``random()``); sorting cannot fix it, the value
      must be made stable/persistent.
    * ``unordered-collection`` -- the value is an *unordered collection*
      (``set`` / ``dict`` / ``relation.units``) serialized without ``sorted()``;
      fix by sorting the collection (or ``sort_keys=True``).
    * ``unordered-pick`` -- a *single element chosen by position* from an
      unordered collection (``addrs[0]``); the subtle one -- it survives
      ``sort_keys=True`` because it is a value not a key, so you must sort the
      collection *before* indexing.

    ``kind`` is the vantage point, not a separate failure mode: ``caller`` = a
    concrete value reaching a sink here; ``sink`` = a helper that writes one of
    its parameters unsorted (the contract boundary -- it trusts callers to pass
    something already ordered).

    ``level`` is the *blocking* status, decided by **who can fix it**:

    * ``error`` -- the fix lives in code the scanned charm owns (its ``src/`` or
      its own ``lib/charms/<charm-name>/`` namespace), so the charm can and
      should fix it. Errors drive a non-zero exit code (they fail CI).
    * ``warning`` -- the fix lives in a library the charm only *consumes* (an
      installed Python package, or a *vendored* ``lib/charms/<other-charm>/``
      copy it does not own). Surfaced for awareness, but it does not fail CI --
      the charm cannot fix someone else's library here.
    """

    path: str
    line: int
    col: int
    kind: str  # "caller" | "sink" (vantage point; also severity ranking / dedup)
    confidence: str  # criticality: "low" | "medium" | "high"
    rule: str  # failure mode: nondeterministic | unordered-collection |
    #            unordered-pick
    sink: str  # where the value lands: "databag" | "file" | "hash"
    variable: str  # offending variable / collection name ("" if anonymous)
    level: str = "error"  # blocking status: "error" (charm-owned fix) | "warning"
    #: provenance pointer: where the unstable value is *born* -- the ``set()`` /
    #: ``glob()`` / unsorted helper that creates the churn, as opposed to the
    #: ``path:line`` above which is where it is *written* to the databag. ``""`` /
    #: ``0`` when there is no distinct origin (e.g. the value is born at the sink
    #: itself, or this is a ``kind=sink`` parameter-contract finding).
    origin_path: str = ""
    origin_line: int = 0
    #: name of the function that owns the born site (``via=...`` in the chain
    #: from origin to sink); ``""`` if unknown or same as the finding's function.
    via: str = ""

    def format(self) -> str:
        """Render as ``path:line:col: [warning] key=value ...`` structured fields."""
        fields = [
            f"type={self.rule}",
            f"severity={self.confidence}",
            f"sink={self.sink}",
        ]
        if self.variable:
            fields.append(f"var={self.variable}")
        if self.origin_path:
            fields.append(f"origin={self.origin_path}:{self.origin_line}")
        if self.via:
            fields.append(f"via={self.via}")
        marker = "[warning] " if self.level == "warning" else ""
        return f"{self.path}:{self.line}:{self.col}: {marker}" + " ".join(fields)


@dataclass
class FuncInfo:
    """A discovered function plus the interprocedural summary computed for it.

    The first block of fields is populated during collection; the ``summary``
    block is filled in by the fixed-point iteration in
    :mod:`flaplint.summary`.
    """

    name: str
    path: str
    node: ast.AST  # FunctionDef / AsyncFunctionDef / Module
    params: List[str] = field(default_factory=list)
    param_index: Dict[str, int] = field(default_factory=dict)
    param_annotations: Dict[str, Optional[str]] = field(default_factory=dict)
    n_positional: int = 0
    is_method: bool = False
    is_property: bool = False
    class_name: Optional[str] = None
    primary: bool = False  # report findings for this function?
    #: True if this function/property *returns a relation databag* -- its body
    #: returns ``relation.data[app|unit]`` / ``relation.data.get(entity)`` (or
    #: chains to another such accessor). Lets a write through the accessor
    #: (``self.unit_databag.update(...)``) be recognised as a databag sink.
    returns_databag: bool = False

    # --- summary (computed by fixed point) ---
    #: parameter index -> "direct" (written to a sink here) | "via" (forwarded
    #: into another dangerous function).
    dangerous: Dict[int, str] = field(default_factory=dict)
    #: whether the function returns a locally-unordered value.
    returns_unordered: bool = False
    #: whether the function returns a value-position (``"element"``) unstable
    #: value -- one that survives a key-sorting serializer. Tracked separately
    #: from ``returns_unordered`` so the distinction is preserved across call
    #: boundaries (a caller of such a helper must keep treating it as
    #: key-sort-resistant rather than degrading it back to ``"local"``).
    returns_element: bool = False
    #: provenance ``(path, node)`` of the value-position pick this function
    #: returns, so callers can point a finding at the offending subscript instead
    #: of their own serializer. ``None`` until ``returns_element`` is set.
    element_site: Optional[Tuple[str, ast.AST, str]] = None
    #: provenance ``(path, node, func)`` of the locally-unordered value this
    #: function returns, so a caller's finding can point ``origin=`` at the
    #: ``set()`` / ``glob()`` that births the instability rather than the
    #: blameless serializer. ``None`` until ``returns_unordered`` is set.
    unordered_site: Optional[Tuple[str, ast.AST, str]] = None
    #: whether the function returns a value whose order derives from a *sequence
    #: materialized from a locally-born unordered collection* (``list(some_set)``)
    #: -- a key-sort-resistant ``itercaller`` flavor. Tracked separately from
    #: ``returns_unordered`` so callers keep treating it as key-sort-resistant
    #: (a key-sorting serializer must NOT launder it, unlike a bare ``local``).
    returns_itercaller: bool = False
    #: provenance ``(path, node, func)`` of the materialized sequence this
    #: function returns, so a caller's ``unordered-iteration`` finding points at
    #: the ``list(...)`` / comprehension. ``None`` until ``returns_itercaller``.
    itercaller_site: Optional[Tuple[str, ast.AST, str]] = None
    #: parameter indices whose taint flows through to the return value.
    returns_params: Set[int] = field(default_factory=set)
    #: parameter index -> ``(path, node)`` iteration site for params iterated
    #: unsorted into an order-dependent sequence that escapes the function (a
    #: ``[... for x in param.items()]`` whose list reaches a ``return`` or a
    #: sink). Reported as a contract-boundary ``sink`` finding pointing at the
    #: iteration, so the fix (``sorted()``) lands where the churn is created.
    iter_params: Dict[int, Tuple[str, ast.AST]] = field(default_factory=dict)


#: Function table keyed by *bare* name (``"as_dict"``), since a call site only
#: knows the callee's final attribute. Same-named methods across classes share a
#: bucket and are disambiguated by receiver class at the call site.
Registry = Dict[str, List[FuncInfo]]


@dataclass
class FileImports:
    """Per-file import aliases, so a renamed import resolves to its canonical name.

    Name-matching is on the *bound* name a call uses, so an ``as`` rename would hide
    a known source/serializer (``from uuid import uuid4 as gen`` -> ``gen()``). These
    maps undo the rename before matching.

    * ``names``  -- bound name -> canonical name, from ``from m import x [as y]``
      (``{"gen": "uuid4", "ddump": "dumps"}``).
    * ``modules`` -- bound top-name -> real module, from ``import m [as a]``
      (``{"j": "json", "o": "os"}``), used to resolve ``module_root`` checks.
    """

    names: Dict[str, str] = field(default_factory=dict)
    modules: Dict[str, str] = field(default_factory=dict)
