"""Static interprocedural taint linter for Juju relation-databag ordering churn.

Juju fires ``relation-changed`` only when the *textual* value of a databag key
changes. Serializing an *unordered* value (a ``set``, a ``glob`` result, set
algebra, ...) -- or writing a *nondeterministic* one (``uuid4()``, ``time()``) --
produces different bytes for the same logical content across reconciles, causing
spurious ``relation-changed`` events and endless databag "ping-pong" churn.

This package reads charm source code (no tests, no running) and flags those
sites. It is a heuristic *flagger for human review*, not an autofixer.

Public API
----------
The simplest entry point is :func:`analyze_paths`, which mirrors the CLI::

    from flaplint import analyze_paths

    findings = analyze_paths(["src/"], relations_unordered=False)
    for finding in findings:
        print(finding.format())

For finer control construct an :class:`~flaplint.analyzer.Analyzer`
directly. The command-line entry point lives in
:func:`flaplint.cli.main`.
"""

from __future__ import annotations

from .analyzer import Analyzer, analyze_paths
from .model import Finding, FuncInfo, Origin, Registry

__all__ = [
    "Analyzer",
    "analyze_paths",
    "Finding",
    "FuncInfo",
    "Origin",
    "Registry",
    "__version__",
]

__version__ = "1.0.0"  # x-release-please-version
