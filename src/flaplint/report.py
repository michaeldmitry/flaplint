"""Final report generation: turn summaries into user-facing findings.

Two kinds of finding are emitted, both only for *primary* (in-scope) functions:

* **caller** -- a locally-born unordered/volatile value reaches a sink in this
  function (possibly forwarded through a sibling-library helper);
* **sink** -- this function writes one of its *parameters* to relation data
  unsorted, so unordered callers will churn. Its confidence is graded by the
  parameter's annotation.
"""

from __future__ import annotations

import ast
from typing import Dict, List, Optional, Set, Tuple

from .constants import (
    DEFINITELY_UNORDERED_ANNOTATIONS,
    ORDERED_ANNOTATIONS,
    UNORDERED_ANNOTATIONS,
)
from .handlers import ReportHandler
from .model import Finding, FuncInfo, Gap
from .traversal import FunctionAnalyzer

#: Annotations that name a *concrete object type* whose ordering a caller cannot
#: control by sorting (a dataclass / value object, e.g. ``ScrapeJobContext``). A
#: contract-boundary ``sink`` finding asks the caller to pass something ordered;
#: that advice is meaningless for an opaque object -- if it carries unordered
#: data, the fault is at *its* construction, reported there. ``Any``/``object``
#: are genuinely-unknown (could be a collection), so they stay a medium sink.
_AMBIGUOUS_ANNOTATIONS = {"Any", "object"}


def _grade_param(ann: "str | None") -> "str | None":
    """Confidence for a parameter written/iterated to a databag, or ``None`` to skip.

    ``None`` -> not a contract-boundary the helper owns: an ordered/mapping type
    (the caller's responsibility) or an opaque object type (no ``sorted()`` fix
    applies). Otherwise ``high`` only for a *definitely*-unordered annotation (the
    set family), ``medium`` for an ambiguous iterable/view (``Iterable`` admits
    ``list``), an unannotated, or a genuinely-unknown one.
    """
    if ann in ORDERED_ANNOTATIONS:
        return None
    if (
        ann is not None
        and ann not in UNORDERED_ANNOTATIONS
        and ann not in _AMBIGUOUS_ANNOTATIONS
        and ann[:1].isupper()
    ):
        return None  # a concrete object type, not a collection a caller can sort
    return "high" if ann in DEFINITELY_UNORDERED_ANNOTATIONS else "medium"


def _read_self_attrs(node: ast.AST, attrs: Set[str]) -> Set[str]:
    """The subset of ``attrs`` that ``node``'s body reads as ``self.<attr>``."""
    hit: Set[str] = set()
    for sub in ast.walk(node):
        if (
            isinstance(sub, ast.Attribute)
            and isinstance(sub.value, ast.Name)
            and sub.value.id in ("self", "cls")
            and sub.attr in attrs
        ):
            hit.add(sub.attr)
    return hit


def report(
    functions: List[FuncInfo],
    analyzer: FunctionAnalyzer,
    suppressed: Dict[str, Set[int]],
    explain_gaps: bool = False,
    selfpass_refinements: "Dict[str, Set[str]] | None" = None,
) -> "Tuple[List[Finding], List[Gap]]":
    """Produce the deduplicated, suppression-aware findings (and, optionally, gaps)."""
    findings: List[Finding] = []
    gaps: List[Gap] = []
    seen: Set[Tuple] = set()

    def _enclosing_scope(path: str, line: int) -> str:
        """Innermost function/property whose body spans ``(path, line)``, or ``""``.

        Used as a fallback subject when the anchored value has no nameable variable
        (an anonymous ``return list(set(...))``): its enclosing property is exactly
        where the ``sorted()`` fix goes. Spans *all* collected functions (not just
        primary ones) so a born site inside a vendored library still resolves.
        """
        best_name = ""
        best_start = -1
        for fi in functions:
            if fi.path != path:
                continue
            start = getattr(fi.node, "lineno", 0)
            end = getattr(fi.node, "end_lineno", start) or start
            if start <= line <= end and start > best_start and fi.name not in ("", "<module>"):
                best_name, best_start = fi.name, start
        return best_name

    def _is_unannotated_enclosing_param(path: str, line: int, name: str) -> bool:
        """Is ``name`` an *unannotated* formal parameter of the function at ``line``?

        Distinguishes an iterated *parameter* whose disorder is invisible from this
        line (an unannotated contract boundary -- the "why" is a caller passing an
        unordered collection) from both an intrinsically-unordered local and an
        *annotated* param (``peer_unit_names: Set[str]``), where the signature already
        shows why it is unordered and the direct wording reads fine. Only the
        invisible case earns the caller-boundary rephrasing.
        """
        if not name:
            return False
        best_start, best = -1, None
        for fi in functions:
            if fi.path != path:
                continue
            start = getattr(fi.node, "lineno", 0)
            end = getattr(fi.node, "end_lineno", start) or start
            if start <= line <= end and start > best_start:
                best_start, best = start, fi
        if best is None or name not in best.params:
            return False
        return not best.param_annotations.get(name)

    def emit(
        path: str,
        node: ast.AST,
        kind: str,
        conf: str,
        rule: str,
        sink: str,
        variable: str,
        origin: "Optional[Tuple]" = None,
        sink_loc: "Tuple[str, ast.AST] | None" = None,
        via_subclass: str = "",
        via_attr: str = "",
    ) -> None:
        line = getattr(node, "lineno", 0)
        if line in suppressed.get(path, ()):
            return
        col = getattr(node, "col_offset", 0) + 1
        # Include ``sink`` so a value that reaches *two* stores at the same spot
        # (a param written to both a databag and a secret) yields one finding per
        # store -- they're distinct churn sources with distinct fixes.
        #
        # Include the upstream *origin* too, but only when it is away from this
        # anchor (a re-attributed cross-file pick/iteration, whose finding sits at
        # the consuming write rather than at its own fix site). Two independent
        # unstable sources that both flow into the *same* write collapse to one
        # ``(path, line, col, kind, sink)`` otherwise -- and only one origin
        # survives, hiding the second (e.g. postgresql's ``get_standby_endpoints``
        # is masked by ``_peer_members_ips`` at the same ``patroni.yaml`` render).
        # Each needs its own ``sorted()`` at its own source, so they are distinct
        # findings. Same-source duplicates (identical/absent origin) still collapse.
        origin_key = (
            (origin[0], origin[1])
            if origin and (origin[0], origin[1]) != (path, line)
            else None
        )
        key = (path, line, col, kind, sink, origin_key)
        if key in seen:
            return
        seen.add(key)
        # Downstream sink pointer: where the value is actually written, when that
        # differs from the finding location (an ``unordered-pick`` / iteration
        # finding sits at the *fix* site, which can be lines or a helper away from
        # the write). Suppressed when the write is on the *same line* as the
        # finding (e.g. an inline comprehension in the databag write), to avoid a
        # redundant "reaches databag at <the same line>".
        sink_path, sink_line, sink_col = "", 0, 0
        if sink_loc is not None:
            s_path = sink_loc[0]
            s_line = getattr(sink_loc[1], "lineno", 0)
            s_col = getattr(sink_loc[1], "col_offset", 0) + 1
            if (s_path, s_line) != (path, line):
                sink_path, sink_line, sink_col = s_path, s_line, s_col
        # Upstream born-at pointer, suppressed when it resolves to the finding's own
        # line (e.g. ``list(set(x))`` -- the set and the materialization share a
        # line), so it never redundantly points at itself.
        origin_path, origin_line, via = "", 0, ""
        if origin and (origin[0], origin[1]) != (path, line):
            origin_path, origin_line, via = origin[0], origin[1], origin[2]
        # Contract-boundary iteration: a confirmed unordered iteration of a *formal
        # parameter* with no single born site -- the disorder enters through whichever
        # caller passes an unordered collection in. Flagged only when there is no
        # upstream origin (a named born site would already explain it) so the report
        # can attribute it to the caller boundary rather than the parameter itself.
        via_param = (
            rule == "unordered-iteration"
            and kind == "caller"
            and not origin_path
            and _is_unannotated_enclosing_param(path, line, variable)
        )
        findings.append(
            Finding(
                path,
                line,
                col,
                kind,
                conf,
                rule,
                sink,
                variable,
                origin_path=origin_path,
                origin_line=origin_line,
                via=via,
                sink_path=sink_path,
                sink_line=sink_line,
                sink_col=sink_col,
                scope="" if variable else _enclosing_scope(path, line),
                via_subclass=via_subclass,
                via_attr=via_attr,
                via_param=via_param,
            )
        )

    # Iteration sites confirmed by a traced unstable caller (``kind=caller``
    # ``unordered-iteration`` findings). A precautionary ``kind=sink`` finding at
    # the same site is redundant -- the confirmed one is strictly stronger -- so
    # it is suppressed below. Collected across *all* functions before the
    # precautionary pass, since the confirming caller and the iterating helper are
    # usually different functions analysed in different iterations.
    confirmed_iter: Set[Tuple[str, int, int]] = set()
    iter_candidates: List[Tuple[str, ast.AST, str, str]] = []

    for fi in functions:
        if not fi.primary:
            continue

        # caller findings: local unordered/volatile value -> sink.
        sink_out: List[Tuple] = []
        gaps_out: "Optional[List[Gap]]" = [] if explain_gaps else None
        analyzer.analyze(fi, ReportHandler(fi, sink_out, gaps_out))
        if gaps_out:
            gaps.extend(gaps_out)
        for node, conf, rule, sink, variable, path, origin, sink_loc in sink_out:
            emit(path, node, "caller", conf, rule, sink, variable, origin, sink_loc)
            if rule == "unordered-iteration":
                confirmed_iter.add(
                    (
                        path,
                        getattr(node, "lineno", 0),
                        getattr(node, "col_offset", 0) + 1,
                    )
                )

        # sink findings: a helper writes one of its parameters unsorted. This is
        # the ``unordered-collection`` failure mode seen at the contract boundary
        # (``kind=sink``): the helper trusts callers to pass something ordered.
        for idx, mark in fi.dangerous.items():
            if mark != "direct":
                continue
            pname = fi.params[idx]
            if pname in ("self", "cls"):
                continue
            conf = _grade_param(fi.param_annotations.get(pname))
            if conf is None:
                continue
            for st in sorted(fi.dangerous_sinks.get(idx) or {"databag"}):
                emit(
                    fi.path,
                    fi.node,
                    "sink",
                    conf,
                    "unordered-collection",
                    st,
                    pname,
                )

        # iteration-site candidates: a helper iterates one of its parameters
        # unsorted into an order-dependent sequence that escapes (the
        # ``[... for x in param.items()]`` shape). This is a *contract boundary*:
        # we cannot prove from here that callers pass an unordered collection, but
        # if any does, the sequence's element order flaps and key-sorting cannot
        # fix it. Reported (medium, or high for a known-unordered annotation) at
        # the iteration so the ``sorted()`` fix lands where the churn is created.
        #
        # Deferred until all confirmed-by-trace sites are known: when a caller is
        # *proven* to pass an unstable value (an ``itercaller`` finding above),
        # the precautionary finding here would merely duplicate that stronger,
        # higher-confidence one -- so it is dropped at confirmed sites.
        for idx, (ipath, inode) in fi.iter_params.items():
            pname = fi.params[idx]
            if pname in ("self", "cls"):
                continue
            conf = _grade_param(fi.param_annotations.get(pname))
            if conf is None:
                continue
            iter_candidates.append((ipath, inode, conf, pname))

    for ipath, inode, conf, pname in iter_candidates:
        site = (
            ipath,
            getattr(inode, "lineno", 0),
            getattr(inode, "col_offset", 0) + 1,
        )
        if site in confirmed_iter:
            continue  # a traced caller already reported this iteration at high conf
        emit(ipath, inode, "sink", conf, "unordered-iteration", "databag", pname)

    # Context-sensitive re-analysis (self-pass mixin). An inherited method reads a
    # self-attribute whose concrete type a *subclass* refined via a constructor
    # self-pass (``class DataPeer(DataPeerData, DataPeerEventHandlers)`` wiring the
    # handler to itself). The method was analysed once under its defining class, where
    # the attribute has the base (clean) type; re-run it with ``self`` bound to the
    # subclass, so the attribute resolves to the subclass's override. New findings flow
    # through the same dedup ``emit`` -- identical clean re-runs collapse, only the
    # divergent (subclass-specific) finding is added. Bounded to inherited methods that
    # actually read a refined attribute.
    if selfpass_refinements:
        engine = analyzer.engine
        for cls, attrs in selfpass_refinements.items():
            chain = engine._class_chain(cls)
            for fi in functions:
                if not fi.primary or fi.class_name == cls or fi.class_name not in chain:
                    continue
                matched = _read_self_attrs(fi.node, attrs)
                if not matched:
                    continue
                via_attr = sorted(matched)[0]
                reout: "List[Tuple]" = []
                analyzer.analyze(fi, ReportHandler(fi, reout, None), cls_override=cls)
                for node, conf, rule, sink, variable, path, origin, sink_loc in reout:
                    emit(
                        path, node, "caller", conf, rule, sink, variable, origin,
                        sink_loc, via_subclass=cls, via_attr=via_attr,
                    )

    # Collapse a bare (no-origin) finding into a sibling that carries a concrete
    # upstream origin at the same anchor: they are the same flow whose provenance
    # merely resolved differently on two downstream paths (e.g. one iteration
    # reaching two databag writes -- one path names the born helper, the other
    # doesn't). Distinct *non-empty* origins are kept: those are genuinely separate
    # sources feeding one write (postgresql's patroni.yaml fed by both
    # ``_peer_members_ips`` and ``get_standby_endpoints``), each needing its own
    # sorted(). The streaming dedup above already keeps one finding per distinct
    # origin; this only drops the redundant origin-less twin.
    with_origin = {
        (f.path, f.line, f.col, f.kind, f.sink)
        for f in findings
        if f.origin_path
    }
    findings = [
        f
        for f in findings
        if f.origin_path
        or (f.path, f.line, f.col, f.kind, f.sink) not in with_origin
    ]

    # A gap on a line that already produced a finding is redundant -- the finding
    # already tells you to look there. Drop those, and de-duplicate the rest.
    if gaps:
        finding_lines = {(f.path, f.line) for f in findings}
        deduped: List[Gap] = []
        seen_gaps: Set[Tuple[str, int, int, str]] = set()
        for g in gaps:
            if (g.path, g.line) in finding_lines:
                continue
            key = (g.path, g.line, g.col, g.reason)
            if key in seen_gaps:
                continue
            seen_gaps.add(key)
            deduped.append(g)
        gaps = sorted(deduped, key=lambda g: (g.path, g.line, g.col))

    return findings, gaps


def collapse_pipelines(findings: List[Finding]) -> List[Finding]:
    """Collapse the redundant call-path *duplicates* of one write into one finding.

    When one upstream unstable source -- itself independently flagged -- reaches *the
    same physical write* through more than one call path, each path produces a finding
    that is byte-for-byte the same churn with the same fix. The nginx shape: a set
    iterated into a rendered config, that rendered string then pushed to one file, but
    reached via both the charm's ``_nginx_config()`` wrapper and the coordinator's
    ``nginx_config`` -- two findings, one write, one ``sorted()`` fix. Keep the single
    most actionable one: code the charm *owns* (an error) over a vendored dependency
    (a warning), the *confirmed* trace over a precautionary boundary, higher confidence
    first, then the most *downstream* (leaf) anchor -- the one in the consuming code
    that re-attribution exists to surface. The survivor still names the upstream fix
    (via its "Fix at the source" trail), so no fix location is ever lost.

    Deliberately *narrow* -- grouped by ``(source, physical write)``, not by source
    alone. A source that fans out to two **different** sinks (a databag *and* a file,
    or a databag *and* a secret) keeps a finding per sink: those are distinct churn
    symptoms even when one ``sorted()`` fixes both, so merging them across sinks would
    hide real signal (measured at ~70 fleet-wide). Only literal same-write duplicates
    -- zero information difference beyond which call path surfaced them -- collapse.

    Safety invariants: a finding only groups when its origin lands *on another
    finding's anchor* (the source is already flagged with its own fix), so a value
    whose shared source is a mere unflagged *parameter* (the traefik databag+secret
    shape) is never grouped. Two *distinct* sources into one write (postgresql's
    patroni.yaml) have different origins -> different groups -> both survive.

    Must run *after* ``f.level`` is assigned (ownership classification): the
    error/warning axis is the primary tie-break, and before it is set every finding
    defaults to ``error`` -- which would silently fall through to the path tie-break
    and (with absolute paths) prefer the vendored ``.venv`` copy over owned ``src``.
    """
    anchor_set = {(f.path, f.line) for f in findings}
    carrier_roots = {
        (f.origin_path, f.origin_line)
        for f in findings
        if f.origin_path and (f.origin_path, f.origin_line) in anchor_set
    }
    if not carrier_roots:
        return findings

    conf_rank = {"high": 0, "medium": 1, "low": 2}

    def _root_of(f: Finding):
        if f.origin_path and (f.origin_path, f.origin_line) in carrier_roots:
            return (f.origin_path, f.origin_line)
        if (f.path, f.line) in carrier_roots:
            return (f.path, f.line)
        return None

    def _sink_loc(f: Finding):
        # The physical write -- an off-anchor sink pointer when present (the write is a
        # helper/lines away), else the finding's own line. Two findings collapse only
        # when this *and* the source match: same value, same write, different call path.
        return (
            f.sink_path or f.path,
            f.sink_line or f.line,
            f.sink,
        )

    def _group_of(f: Finding):
        r = _root_of(f)
        return None if r is None else (r, _sink_loc(f))

    def _priority(f: Finding):
        return (
            0 if f.level == "error" else 1,       # owned (actionable) first
            conf_rank.get(f.confidence, 3),       # more confident first
            0 if f.kind == "caller" else 1,       # confirmed before precautionary
            # leaf before root: the most downstream finding (nothing carries from it)
            # is the one in the consuming code that re-attribution exists to surface.
            1 if (f.path, f.line) in carrier_roots else 0,
            f.path, f.line, f.col,                # stable, deterministic
        )

    groups: "Dict[Tuple, List[Finding]]" = {}
    for f in findings:
        g = _group_of(f)
        if g is not None:
            groups.setdefault(g, []).append(f)

    keep = set()
    for members in groups.values():
        members.sort(key=_priority)
        winner = members[0]
        keep.add(id(winner))
        # Record the folded siblings on the survivor so the report can point at the
        # other spots this one fix also covers -- a collapsed duplicate must read as
        # "also here", never as a silently-dropped true positive.
        folded = sorted(members[1:], key=lambda m: (m.path, m.line, m.col))
        if folded:
            winner.also_at = tuple((m.path, m.line, m.variable) for m in folded)
    return [f for f in findings if _group_of(f) is None or id(f) in keep]
