"""Interprocedural summary computation.

Each function's summary -- which parameters reach a sink, and how taint flows to
the return value -- depends on the summaries of the functions it calls. We reach
a consistent set of summaries by iterating the whole function table to a fixed
point: keep re-analyzing until no summary changes. Termination is guaranteed
because every field only ever grows (booleans flip once, sets only gain members)
within a finite domain.
"""

from __future__ import annotations

from typing import List

from .handlers import SummaryHandler
from .model import FuncInfo
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
