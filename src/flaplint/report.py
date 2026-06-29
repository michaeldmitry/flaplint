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
from typing import Dict, List, Set, Tuple

from .constants import ORDERED_ANNOTATIONS, UNORDERED_ANNOTATIONS
from .handlers import ReportHandler
from .model import Finding, FuncInfo
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
    applies). Otherwise ``high`` for a known-unordered annotation, ``medium`` for
    an unannotated or genuinely-unknown one.
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
    return "high" if ann in UNORDERED_ANNOTATIONS else "medium"


def report(
    functions: List[FuncInfo],
    analyzer: FunctionAnalyzer,
    suppressed: Dict[str, Set[int]],
) -> List[Finding]:
    """Produce the deduplicated, suppression-aware list of findings."""
    findings: List[Finding] = []
    seen: Set[Tuple[str, int, int, str]] = set()

    def emit(
        path: str,
        node: ast.AST,
        kind: str,
        conf: str,
        rule: str,
        sink: str,
        variable: str,
        origin: Tuple = None,
    ) -> None:
        line = getattr(node, "lineno", 0)
        if line in suppressed.get(path, ()):
            return
        col = getattr(node, "col_offset", 0) + 1
        key = (path, line, col, kind)
        if key in seen:
            return
        seen.add(key)
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
                origin_path=origin[0] if origin else "",
                origin_line=origin[1] if origin else 0,
                via=origin[2] if origin else "",
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
        analyzer.analyze(fi, ReportHandler(fi, sink_out))
        for node, conf, rule, sink, variable, path, origin in sink_out:
            emit(path, node, "caller", conf, rule, sink, variable, origin)
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
            emit(
                fi.path,
                fi.node,
                "sink",
                conf,
                "unordered-collection",
                "databag",
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

    return findings
