"""Sink visitors: what to *do* when the traversal reaches a sink or a return.

The traversal is decoupled from policy through the :class:`Handler` interface.
The same statement walk drives two passes:

* :class:`SummaryHandler` records parameter/return taint into a function's
  summary during the fixed-point computation;
* :class:`ReportHandler` collects concrete, user-facing findings for the final
  report.
"""

from __future__ import annotations

import ast
from typing import List, Optional, Set, Tuple

from . import astutils
from .constants import NONSORTING_SERIALIZERS, PROPAGATE_CALLS, VOLATILE_CALLS
from .model import (
    FuncInfo,
    Origin,
    has_element,
    has_itercaller,
    has_local,
    is_element,
    is_itercaller,
    is_iterparam,
    is_local,
    local_site,
)


def _loc_key(site: Tuple) -> Tuple[str, int, int]:
    """Sort key ``(path, line, col)`` for a ``(path, node, ...)`` pick site."""
    path, node = site[0], site[1]
    return (path, getattr(node, "lineno", 0), getattr(node, "col_offset", 0))


def _pick_local_site(origins, fi: FuncInfo):
    """``(path, line, via)`` born-site of the earliest ``local`` origin (or ``None``).

    Points a finding's ``origin=`` at where the unordered value is *created* (the
    ``set()`` / ``glob()`` / unsorted helper) rather than where it is written.
    ``None`` placeholders in an origin resolve to ``fi``'s file/name; ``via`` is
    blanked when the born site lives in the finding's own function (the
    ``origin=`` pointer already says so).
    """
    sites = [local_site(o) for o in origins if is_local(o)]
    if not sites:
        return None
    path, node, func = min(
        ((s[0] or fi.path, s[1], s[2] or fi.name) for s in sites),
        key=lambda t: _loc_key((t[0], t[1])),
    )
    via = "" if func == fi.name else func
    return (path, getattr(node, "lineno", 0), via)


#: Wrapper callables whose offending content is their *first argument*, not the
#: wrapper itself. ``str(peers)`` / ``json.dumps(peers)`` / ``list(peers)`` all
#: serialise or repackage ``peers`` -- so the variable a user should look at is
#: the argument inside, not ``str`` / ``dumps`` / ``list``.
_TRANSPARENT_WRAPPERS: Set[str] = (
    NONSORTING_SERIALIZERS | PROPAGATE_CALLS | {"dumps", "dump", "safe_dump"}
)


def _unwrap(node: ast.AST) -> ast.AST:
    """Peel transparent serialiser / repackaging calls to the real value.

    ``str(json.dumps(list(x)))`` -> ``x``: each layer just reformats its first
    argument, so the offending identifier is whatever they all wrap. Receiver
    methods that pass their value through unchanged -- ``x.encode()`` /
    ``x.decode()`` -- are peeled to their *receiver* (``str(peers).encode()`` ->
    ``peers``), mirroring the taint engine's encode/decode pass-through; without
    this the name would wrongly resolve to the outer ``str`` wrapper.
    """
    cur = node
    while isinstance(cur, ast.Call):
        name = astutils.final_attr(cur.func)
        if (
            name in ("encode", "decode")
            and isinstance(cur.func, ast.Attribute)
        ):
            cur = cur.func.value  # peel to the receiver: ``x.encode()`` -> ``x``
        elif name in _TRANSPARENT_WRAPPERS and cur.args:
            cur = cur.args[0]
        else:
            break
    return cur


def _variable(node: ast.AST) -> str:
    """Best-effort name of the offending variable/collection (``""`` if none).

    The root of an access chain (``addrs[0]`` -> ``addrs``, ``glob(...)`` ->
    ``glob``) is the actionable identifier a user looks at; anonymous values
    (a bare ``{...}`` set literal) have no name and yield ``""``. Transparent
    serialiser wrappers (``str(peers)``) are peeled first so the collection is
    named, not the wrapper.
    """
    name = astutils.root_name(_unwrap(node))
    return name if name and name not in ("self", "cls") else ""


def _volatile_name(node: Optional[ast.AST]) -> str:
    """Name the nondeterministic call inside ``node`` (``uuid4`` / ``time`` ...).

    For a volatile write the offending thing is the regenerating call, not the
    serializer wrapping it -- so ``json.dumps({"id": str(uuid.uuid4())})`` should
    report ``var=uuid4``, not ``var=json``. Walk the subtree for the first call
    whose final attribute is a known volatile source and return that name.
    """
    if node is None:
        return ""
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            name = astutils.final_attr(sub.func)
            if name in VOLATILE_CALLS:
                return name
    return ""



def _resolve_field_origin(o: Origin, fi: FuncInfo):
    """Resolve a returned field origin's born-site to the callee's file/name.

    A field origin computed in the callee carries ``None`` placeholders (== "this
    file / this function"). When the field is read back by a caller in *another*
    file, those placeholders must already point at the callee, so a finding blames
    the ``set()`` in the helper, not the caller's serializer. Param-flavored origins
    are dropped: they can't be remapped to the caller without the call's arg
    mapping, and a value-object field is rarely a bare parameter.
    """
    if o == "volatile":
        return o
    if not isinstance(o, tuple):
        return None
    tag = o[0]
    if tag in ("local", "element"):
        return (tag, o[1] or fi.path, o[2], o[3] or fi.name)
    if tag == "itercaller":
        return (tag, o[1] or fi.path, o[2], o[3])
    return None  # param / iterparam: not cross-function-resolvable here


class Handler:
    """Callbacks invoked by the traversal at sinks and returns.

    The default implementation ignores everything; subclasses override the
    callbacks they care about.
    """

    #: When True, the traversal computes and reports blind spots via :meth:`gap`.
    #: Off by default so a normal run pays nothing for the gap analysis.
    wants_gaps: bool = False

    def gap(self, node: ast.AST, sink: str, reason: str) -> None:
        """Called for a write whose content couldn't be fully traced (``--explain-gaps``)."""

    def sink(
        self,
        node: ast.AST,
        origins: Set[Origin],
        kind: str,
        desc: str,
        arg: ast.AST,
        sink_type: str = "databag",
    ) -> None:
        """Called when ``origins`` reach a sink (``databag`` or ``hash``)."""

    def ret(self, origins: Set[Origin]) -> None:
        """Called for each ``return <value>`` with the value's taint."""

    def ret_fields(self, field_map: "dict[str, Set[Origin]]") -> None:
        """Called for each ``return <value object>`` with its per-field taint."""


class SummaryHandler(Handler):
    """Accumulate a function's interprocedural summary from one analysis pass."""

    def __init__(self, fi: FuncInfo) -> None:
        self.fi = fi
        self.changed = False

    def _mark(self, idx: int, kind: str) -> None:
        prev = self.fi.dangerous.get(idx)
        if prev is None:
            self.fi.dangerous[idx] = kind
            self.changed = True
        elif prev == "via" and kind == "direct":
            self.fi.dangerous[idx] = "direct"
            self.changed = True

    def _mark_iter(self, idx: int, origin: Origin) -> None:
        """Record the iteration site of a sequence-from-parameter (``iterparam``).

        Keeps the earliest (by location) site so the finding points at the first
        offending iteration. ``None`` placeholders resolve to this function.
        """
        site = (origin[2] or self.fi.path, origin[3])
        prev = self.fi.iter_params.get(idx)
        if prev is None or _loc_key(site) < _loc_key(prev):
            self.fi.iter_params[idx] = site
            self.changed = True

    def sink(self, node, origins, kind, desc, arg, sink_type="databag") -> None:
        # Hash sinks are reported only at concrete local-origin sites, not folded
        # into parameter summaries (which describe relation-data writes).
        if sink_type != "databag":
            return
        marker = "direct" if kind == "direct" else "via"
        for origin in origins:
            if isinstance(origin, tuple) and origin[0] == "param":
                self._mark(origin[1], marker)
            elif is_iterparam(origin):
                # A sequence built from a parameter reaches a relation-data write:
                # the strongest evidence that the iteration order escapes.
                self._mark_iter(origin[1], origin)

    def ret(self, origins) -> None:
        for origin in origins:
            if is_local(origin):
                # A locally-born unordered value reaches the return: remember its
                # born site (mirrors ``element_site``) so callers can blame the
                # ``set()`` / ``glob()`` rather than their own serializer. ``None``
                # placeholders mean "this function's file/name".
                site = local_site(origin)
                resolved = (
                    site[0] or self.fi.path,
                    site[1],
                    site[2] or self.fi.name,
                )
                if self.fi.unordered_site is None or _loc_key(
                    resolved
                ) < _loc_key(self.fi.unordered_site):
                    self.fi.unordered_site = resolved
                    self.changed = True
                if not self.fi.returns_unordered:
                    self.fi.returns_unordered = True
                    self.changed = True
            elif is_element(origin):
                # Remember *where* the pick happened (and which function owns it)
                # so callers can blame the subscript, not their own serializer.
                # ``path is None`` means the pick is in this function's own file;
                # ``func is None`` means this function owns it.
                site = (
                    origin[1] or self.fi.path,
                    origin[2],
                    origin[3] or self.fi.name,
                )
                if self.fi.element_site is None or _loc_key(
                    site
                ) < _loc_key(self.fi.element_site):
                    self.fi.element_site = site
                    self.changed = True
                if not self.fi.returns_element:
                    self.fi.returns_element = True
                    self.changed = True
            elif is_itercaller(origin):
                # A sequence materialized from a locally-born unordered collection
                # (``return list(some_set)``) escapes via return. Remember the
                # materialization site so callers blame the ``list(...)`` rather
                # than their own serializer, and mark the return key-sort-resistant
                # (a key-sorting serializer must NOT launder it). ``None``
                # placeholders resolve to this function's file/name.
                site = (origin[1] or self.fi.path, origin[2], self.fi.name)
                if self.fi.itercaller_site is None or _loc_key(
                    site
                ) < _loc_key(self.fi.itercaller_site):
                    self.fi.itercaller_site = site
                    self.changed = True
                if not self.fi.returns_itercaller:
                    self.fi.returns_itercaller = True
                    self.changed = True
            elif is_iterparam(origin):
                # A sequence built by iterating a parameter escapes via return.
                # Record the iteration site (contract-boundary finding) and keep
                # the param flowing to callers so the eventual concrete sink is
                # still reported at its write site.
                self._mark_iter(origin[1], origin)
                if origin[1] not in self.fi.returns_params:
                    self.fi.returns_params.add(origin[1])
                    self.changed = True
            elif isinstance(origin, tuple) and origin[0] == "param":
                if origin[1] not in self.fi.returns_params:
                    self.fi.returns_params.add(origin[1])
                    self.changed = True

    def ret_fields(self, field_map) -> None:
        # A returned value object's per-field taint becomes this function's
        # ``returns_field_origins`` summary, so a caller can read an unstable field
        # back off the object. Born-sites are resolved to this function so the
        # finding points into the helper. Monotone union -> fixed-point safe.
        for fld, origins in field_map.items():
            resolved = set()
            for o in origins:
                r = _resolve_field_origin(o, self.fi)
                if r is not None:
                    resolved.add(r)
            if not resolved:
                continue
            prev = self.fi.returns_field_origins.get(fld, set())
            merged = prev | resolved
            if merged != prev:
                self.fi.returns_field_origins[fld] = merged
                self.changed = True


class ReportHandler(Handler):
    """Collect concrete findings (local/volatile origins) for one function.

    Each record is the structured tuple
    ``(node, confidence, rule, sink_type, variable, path, origin)`` consumed by
    :func:`flaplint.report.report`. ``origin`` is the
    ``(path, line, via)`` born-site pointer (or ``None``).
    """

    def __init__(self, fi: FuncInfo, sink_out: List[Tuple], gaps_out=None) -> None:
        self.fi = fi
        self.out = sink_out
        self.gaps_out = gaps_out

    @property
    def wants_gaps(self) -> bool:
        return self.gaps_out is not None

    def gap(self, node, sink, reason) -> None:
        from .model import Gap

        snippet = ""
        if hasattr(ast, "unparse"):
            try:
                snippet = ast.unparse(node)
            except Exception:
                snippet = ""
        if len(snippet) > 70:
            snippet = snippet[:67] + "…"
        self.gaps_out.append(
            Gap(
                self.fi.path,
                getattr(node, "lineno", 0),
                getattr(node, "col_offset", 0) + 1,
                sink,
                reason,
                snippet,
            )
        )

    def sink(self, node, origins, kind, desc, arg, sink_type="databag") -> None:
        # Only locally-born unstable values are concrete bugs at this site;
        # parameter-only flows are reported on the helper that owns the sink.
        # ``element`` is value-position order instability (a pick) and reports
        # like ``local``. ``itercaller`` is a confirmed iteration instability
        # traced from a concrete unstable argument through a callee's unsorted
        # iteration.
        volatile = "volatile" in origins
        if (
            not has_local(origins)
            and not has_element(origins)
            and not volatile
            and not has_itercaller(origins)
        ):
            return
        # A builtin ``hash()`` inside a value-object dunder (``__hash__`` /
        # ``__eq__``) is in-process object hashing -- consistent only within one
        # interpreter by design -- not a cross-reconcile change-detection gate,
        # so it never causes churn. Suppress to avoid flagging e.g.
        # ``hash((..., frozenset(x), ...))``.
        if sink_type == "hash":
            fname = self.fi.name or ""
            if fname.startswith("__") and fname.endswith("__"):
                return
        if volatile:
            # A fresh nondeterministic value (uuid/time/random) churns on *every*
            # reconcile and sorting cannot fix it -- strictly worse than order
            # instability. Name the regenerating call, not the serializer.
            self.out.append(
                (
                    node,
                    "high",
                    "nondeterministic",
                    sink_type,
                    _volatile_name(arg) or _variable(arg),
                    self.fi.path,
                    None,
                )
            )
            return
        if has_element(origins):
            # Value-position instability: a value picked by *position* from an
            # unordered collection (``addrs[0]``). It survives key-sorting, so the
            # serializer / write site is NOT where to fix it. Report *at the pick*
            # (its own file:line), not at the blameless sink.
            site_path, site_node = min(
                (
                    (o[1] or self.fi.path, o[2])
                    for o in origins
                    if is_element(o)
                ),
                key=_loc_key,
            )
            self.out.append(
                (
                    site_node,
                    "high",
                    "unordered-pick",
                    sink_type,
                    _variable(site_node),
                    site_path,
                    None,
                )
            )
            return
        if has_itercaller(origins):
            # Confirmed iteration instability: either a traced unstable argument
            # through a callee's unsorted parameter iteration, or a locally-born
            # unordered collection materialized into a sequence (``list(some_set)``).
            # Point the finding at the iteration / materialization site (where
            # ``sorted()`` belongs), not at the databag write here (the blameless
            # sink). Any co-occurring ``local`` taint is suppressed: ``itercaller``
            # is strictly more informative (it pinpoints the fix location). A
            # ``None`` path means "born in this function's file".
            site_path, site_node = min(
                (
                    (o[1] or self.fi.path, o[2])
                    for o in origins
                    if is_itercaller(o)
                ),
                key=_loc_key,
            )
            self.out.append(
                (
                    site_node,
                    "high",
                    "unordered-iteration",
                    sink_type,
                    _variable(site_node),
                    site_path,
                    None,
                )
            )
            return
        self.out.append(
            (
                node,
                "high",
                "unordered-collection",
                sink_type,
                _variable(arg),
                self.fi.path,
                _pick_local_site(origins, self.fi),
            )
        )
