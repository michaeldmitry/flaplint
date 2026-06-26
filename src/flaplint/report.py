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

    for fi in functions:
        if not fi.primary:
            continue

        # caller findings: local unordered/volatile value -> sink.
        sink_out: List[Tuple] = []
        analyzer.analyze(fi, ReportHandler(fi, sink_out))
        for node, conf, rule, sink, variable, path, origin in sink_out:
            emit(path, node, "caller", conf, rule, sink, variable, origin)

        # sink findings: a helper writes one of its parameters unsorted. This is
        # the ``unordered-collection`` failure mode seen at the contract boundary
        # (``kind=sink``): the helper trusts callers to pass something ordered.
        for idx, mark in fi.dangerous.items():
            if mark != "direct":
                continue
            pname = fi.params[idx]
            if pname in ("self", "cls"):
                continue
            ann = fi.param_annotations.get(pname)
            if ann in ORDERED_ANNOTATIONS:
                continue  # an ordered parameter is the caller's responsibility
            conf = "high" if ann in UNORDERED_ANNOTATIONS else "medium"
            emit(
                fi.path,
                fi.node,
                "sink",
                conf,
                "unordered-collection",
                "databag",
                pname,
            )

    return findings
