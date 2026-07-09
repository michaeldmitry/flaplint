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
    confidence: str  # how sure flaplint is: "low" | "medium" | "high"
    rule: str  # failure mode: nondeterministic | unordered-collection |
    #            unordered-pick
    sink: str  # where it lands: "databag"|"file"|"hash"|"plan"|"render"|"secret"
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
    #: downstream pointer: where the unstable value is actually *written* to the
    #: sink (the databag/file/hash/plan write), when that differs from the
    #: ``path:line`` above. For an ``unordered-pick`` / ``unordered-iteration``
    #: finding the location points at the *fix* site (the pick / the iteration),
    #: which can be several lines -- or a helper call -- away from the write; this
    #: pins where the value lands. ``""`` / ``0`` when the write coincides with the
    #: finding location (an ``unordered-collection`` / ``nondeterministic`` finding
    #: is reported *at* its write, so there is nothing extra to point at).
    sink_path: str = ""
    sink_line: int = 0
    sink_col: int = 0
    #: enclosing function/property that produces the anchored value -- a
    #: human-readable *fallback subject* when there is no nameable ``variable`` (an
    #: anonymous ``return list(set(...))``). Lets the report name *where* the
    #: ``sorted()`` goes ("the value returned by ``current_secret_fields``")
    #: instead of ``<anonymous>``. ``""`` when a variable already names the value
    #: or the enclosing function is unknown.
    scope: str = ""
    #: set only for findings surfaced by context-sensitive re-analysis (the
    #: self-pass mixin): the concrete runtime subclass whose attribute override
    #: made this flow reachable, and the ``self`` attribute it is bound to. Lets
    #: the description explain the polymorphism -- the value reaches the sink only
    #: because ``self.<via_attr>`` is a ``<via_subclass>`` at runtime, whose
    #: override differs from the base type visible at the read site. Both ``""``
    #: for ordinary statically-resolved findings.
    via_subclass: str = ""
    via_attr: str = ""
    #: set when the iterated value is a *formal parameter* of the enclosing function
    #: and the flap has no single born site -- a confirmed ``kind=caller``
    #: ``unordered-iteration`` at a *contract boundary*, where the disorder enters
    #: through whichever caller passes an unordered collection into the parameter
    #: (cos-proxy's ``_label_alert_rules(unit_rules, ...)`` is fed unordered dicts by
    #: three callers, so there is no one origin to point at). Lets the description
    #: attribute the instability to the caller boundary -- "a caller passes an
    #: unordered collection into ``unit_rules``" -- instead of implying the parameter
    #: is intrinsically unordered. ``False`` for every other finding.
    via_param: bool = False
    #: sibling locations folded into this finding by the pipeline collapse: the
    #: *same* unstable source reaching the *same* physical write through other call
    #: paths (litmus's file write hit via both the charm wrapper and the coordinator).
    #: Each entry is ``(path, line, variable)``. Surfaced so the reader sees the one
    #: fix here also resolves those spots -- a collapsed duplicate is not a missed
    #: true positive. Empty for a finding that stands alone.
    also_at: "Tuple[Tuple[str, int, str], ...]" = ()

    def format(self) -> str:
        """Render as ``path:line:col: owner=... confidence=... key=value ...``.

        The two axes are distinct greppable fields -- ``owner`` (whose job the fix
        is: ``yours``/``dependency``; only ``yours`` fails the run) and
        ``confidence`` (how sure flaplint is: ``high``/``medium``/``low``) -- so
        neither reads as the other's severity. ``owner`` replaces the old
        ``[warning]`` marker; ``confidence`` replaces the old ``severity=``.
        """
        owner = "yours" if self.level == "error" else "dependency"
        fields = [
            f"owner={owner}",
            f"type={self.rule}",
            f"confidence={self.confidence}",
            f"sink={self.sink}",
        ]
        if self.variable:
            fields.append(f"var={self.variable}")
        elif self.scope:
            fields.append(f"in={self.scope}")
        if self.origin_path:
            fields.append(f"origin={self.origin_path}:{self.origin_line}")
        if self.via:
            fields.append(f"via={self.via}")
        if self.via_subclass:
            fields.append(f"via_subclass={self.via_subclass}")
        if self.sink_line:
            fields.append(f"sink_at={self.sink_path}:{self.sink_line}")
        if self.also_at:
            fields.append(
                "also_at=" + ",".join(f"{p}:{ln}" for p, ln, _ in self.also_at)
            )
        return f"{self.path}:{self.line}:{self.col}: " + " ".join(fields)


@dataclass
class Gap:
    """A blind spot: a write whose content flaplint could not fully trace.

    Emitted only under ``--explain-gaps``. A gap is *not* a finding -- it's a place
    the analysis gave up, so it's where a missed flap (a false negative) could hide.
    Each names the write, the kind of target it reaches, and *why* the content
    couldn't be traced (an unresolved call, a value-object field, an untraced
    parameter). Diagnostic only: gaps never change the exit code.
    """

    path: str
    line: int
    col: int
    sink: str  # target reached: "databag"|"file"|"plan"|"hash"|"render"|"secret"
    reason: str  # plain-English description of what couldn't be traced
    snippet: str = ""  # the un-traced expression, for quick scanning

    def format(self) -> str:
        """Render as ``path:line:col: gap sink=... reason=...`` structured fields."""
        return (
            f"{self.path}:{self.line}:{self.col}: gap sink={self.sink} "
            f"reason={self.reason}"
        )


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
    #: parameters annotated as a mapping whose *value* type is an unordered set
    #: (``Dict[str, Set[str]]``), so ``p[k]`` / ``p.get(k)`` / ``p.values()`` hand back
    #: an unordered collection -- iterating one unsorted flaps. The mapping's own key
    #: order is laundered by serializers, but its set *values* are not.
    unordered_value_params: Set[str] = field(default_factory=set)
    n_positional: int = 0
    is_method: bool = False
    is_property: bool = False
    class_name: Optional[str] = None
    primary: bool = False  # report findings for this function?
    #: databag-provenance kind this function/property *returns* -- one of
    #: ``"relation"`` / ``"relation_data"`` / ``"databag"`` (see
    #: :mod:`flaplint.databag`), or ``None``. Lets a write through an accessor
    #: (``self.unit_databag.update(...)``) be recognised as a databag sink, however
    #: many property/alias hops -- ``get_relation`` -> ``.data`` -> ``[entity]`` --
    #: separate the producer from the write.
    returns_databag_kind: Optional[str] = None

    # --- summary (computed by fixed point) ---
    #: parameter index -> "direct" (written to a sink here) | "via" (forwarded
    #: into another dangerous function).
    dangerous: Dict[int, str] = field(default_factory=dict)
    #: for each dangerous parameter, the set of sink families it reaches --
    #: ``"databag"``, ``"secret"`` and/or ``"file"`` (the byte-compared destinations
    #: that fold into parameter summaries). Lets a caller passing an unstable value
    #: get one finding per destination (a param written to *both* a databag and a
    #: file churns both). Empty/absent is read as ``{"databag"}`` for back-compat.
    dangerous_sinks: Dict[int, Set[str]] = field(default_factory=dict)
    #: for each dangerous parameter and sink family, the ``(path, lineno, col)`` of
    #: the *actual write* inside this function -- so a caller's finding can point at
    #: the real databag / secret write (e.g. the ``set_content`` line), not just the
    #: call site. Earliest write per (param, sink) is kept.
    dangerous_sites: Dict[int, Dict[str, Tuple[str, int, int]]] = field(
        default_factory=dict
    )
    #: field-sensitive analogue of ``dangerous``: a *projection* of a parameter -- a
    #: value-object field (``ctx.job`` -> accessor ``".job"``) or a fixed dict key
    #: (``payload['jobs']`` -> ``"['jobs']"``) -- written to a sink. Keyed
    #: ``param_idx -> accessor -> {sink_family: (path, lineno, col)}``. Distinct from
    #: ``dangerous`` so a caller is flagged only when *that* projection of the argument
    #: is unstable: a clean field of a partly-unstable value object stays clean (no
    #: false positive), unlike the coarse whole-object contract.
    dangerous_proj: Dict[int, Dict[str, Dict[str, Tuple[str, int, int]]]] = field(
        default_factory=dict
    )
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
    #: *all* distinct value-position pick sites this function returns (not just the
    #: earliest ``element_site``). One config the function returns can aggregate
    #: several independently-unstable picks; each is its own place a ``sorted()`` is
    #: needed, so callers emit one finding per site rather than a single representative.
    element_sites: "Set[Tuple[str, ast.AST, str]]" = field(default_factory=set)
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
    #: *all* distinct materialization sites this function returns (not just the
    #: earliest ``itercaller_site``). A function that aggregates several unstable
    #: sources into one returned config (``_generate_config`` merging loki endpoints
    #: *and* prometheus jobs) carries a born-site per source; each is a separate place
    #: to ``sorted()``, so callers emit one finding per site -- distinct entries for
    #: one write reached by many origins (not folded into one representative).
    itercaller_sites: "Set[Tuple[str, ast.AST, str]]" = field(default_factory=set)
    #: parameter indices whose taint flows through to the return value.
    returns_params: Set[int] = field(default_factory=set)
    #: the class this function's ``-> Ret`` annotation names, so a local bound to its
    #: result (``prm = _get_policy_resource_manager()``) is typed for method resolution
    #: -- turning an untyped ``prm.reconcile(...)`` (which would hit the same-name union
    #: and collide with an unrelated ``Nginx.reconcile``) into a precise one. ``None``
    #: when unannotated. Only used when it names a class flaplint actually analysed.
    returns_class: Optional[str] = None
    #: for a function that returns a *value object* (a constructed dataclass /
    #: pydantic model / NamedTuple), the per-field taint of that object: ``field
    #: name -> origins``. Lets a caller read an unstable field back off the returned
    #: object (``ctx = self._build(); ctx.targets``) -- the cross-function half of
    #: value-object field provenance. Born-sites in these origins are resolved to
    #: this function's file/name so a caller's finding can point into the helper.
    returns_field_origins: Dict[str, Set["Origin"]] = field(default_factory=dict)
    #: parameter index -> ``(path, node)`` iteration site for params iterated
    #: unsorted into an order-dependent sequence that escapes the function (a
    #: ``[... for x in param.items()]`` whose list reaches a ``return`` or a
    #: sink). Reported as a contract-boundary ``sink`` finding pointing at the
    #: iteration, so the fix (``sorted()``) lands where the churn is created.
    iter_params: Dict[int, Tuple[str, ast.AST]] = field(default_factory=dict)
    #: per-*position* taint of a returned tuple/list literal, so a caller unpacking
    #: the result (``rw, ro, _ = self.get_cluster_endpoints(...)``) gets each name's
    #: own instability -- position 0 (a ``",".join(set)``) is unstable while a stable
    #: sibling position (``cert, key = ...``: the ``key``) stays clean. ``None`` until
    #: a tuple return is seen; born-sites are resolved to this function. Set back to
    #: ``None`` and :attr:`returns_tuple_unreliable` on an arity conflict.
    returns_tuple_origins: Optional[List[Set["Origin"]]] = None
    #: True once returns of *differing* arity were seen -- the per-position summary is
    #: then meaningless and must not be consumed (a terminal state).
    returns_tuple_unreliable: bool = False
    #: parameter index -> the ``self.<attr>`` name this method *absorbs* it into: a
    #: setter/accumulator that stores a param directly into the receiver's own state
    #: (``def add_component(self, ..., config): self._config[...][name] = config`` ->
    #: ``{3: "_config"}``). At a call site ``self.builder.add_component(..., <unstable>)``
    #: the argument's taint is recorded onto the *callee class*'s instance attribute, so
    #: a later state-returning method on that class (``build()`` -> ``yaml.safe_dump(
    #: self._config)``) surfaces it -- the cross-object config-builder chain. Kept
    #: conservative (value must be the bare parameter, target a ``self``-rooted
    #: subscript/accumulator) so it models a pass-through container, not a transform.
    absorbs: Dict[int, str] = field(default_factory=dict)
    #: ``self.<attr>`` names this method's *return* exposes (``build(): return
    #: yaml.safe_dump(self._config)`` -> ``{"_config"}``). Marks a class as a
    #: *renderable builder*: absorbing an order-dependent parameter (``iterparam``)
    #: into one of these attrs is a contract-boundary file sink, so a caller passing an
    #: unsorted value is flagged. The gate that keeps a private, never-returned cache's
    #: setter from becoming a false sink.
    returns_self_attrs: Set[str] = field(default_factory=set)
    #: the ``self.<attr>`` sub-path a *pure getter* returns -- set only when every
    #: ``return`` in the method is exactly ``return self.<attr>[.<attr>…]`` naming the
    #: same attribute (``def _get_ctx(self): return self._ctx`` -> ``"_ctx"``). Unlike
    #: :attr:`returns_self_attrs` (any self-attr *mentioned* in a return, including a
    #: wrapped ``yaml.dump(self._config)``), this is the strict "the returned object
    #: *is* that attribute" case, so a caller can treat the call as an alias of it.
    returns_self_attr: Optional[str] = None


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
    #: bound name -> the module it was imported *from*, for absolute
    #: ``from a.b.c import Name [as N]`` (``{"N": "a.b.c"}``). Lets resolution pin a
    #: same-named class/method to the exact vendored module version it came from
    #: (``charms.foo.v0.bar`` vs ``...v1...``) instead of unioning both.
    from_modules: Dict[str, str] = field(default_factory=dict)
