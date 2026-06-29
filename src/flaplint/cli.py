"""Command-line interface for the databag-ordering linter."""

from __future__ import annotations

import argparse
import json
import sys
from typing import List, Optional

from .analyzer import Analyzer
from .render import colour_enabled, render_gaps, render_report

_DESCRIPTION = (
    "Detect order-unstable values written to Juju relation data, which cause "
    "spurious relation-changed churn (and restart/replan loops)."
)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=_DESCRIPTION)
    parser.add_argument("paths", nargs="+", help="charm source files or directories")
    parser.add_argument(
        "--dep",
        action="append",
        default=[],
        metavar="PATH",
        help="extra source root to ANALYZE and REPORT on, e.g. a checked-out or "
        "vendored charm lib. Findings here are shown but keep their natural "
        "level (vendored code stays a warning); use a positional path for code "
        "you own. Contrast --venv, which is resolve-only.",
    )
    parser.add_argument(
        "--venv",
        action="append",
        default=[],
        metavar="PATH",
        help="virtualenv (or site-packages) to FOLLOW INTO for call resolution "
        "only -- installed dependencies are traced to see if they write to "
        "relation data, but are NOT reported unless --report-deps. Contrast "
        "--dep, which is also reported.",
    )
    parser.add_argument(
        "--auto-deps",
        action="store_true",
        help="auto-detect which installed dependencies write to relation data "
        "and trace only those (locates a sibling .venv/venv if no --venv given). "
        "The charm's own vendored lib/ is always auto-included.",
    )
    parser.add_argument(
        "--python",
        default="",
        metavar="PATH",
        help="interpreter of an environment that has the charm's dependencies "
        "installed (e.g. a `uv sync`-created .venv's bin/python). Imported deps "
        "are resolved through THAT interpreter's import system -- following PEP "
        "420 namespace packages like charmlibs.interfaces.otlp -- and the ones "
        "that write relation data are traced. Resolve-only (like --venv), but "
        "version-exact to that env and not tied to a sibling .venv location. "
        "Installs nothing; the deps must already be present in that env.",
    )
    parser.add_argument(
        "--report-deps",
        action="store_true",
        help="also report findings inside --venv site-packages (default: trace only)",
    )
    parser.add_argument(
        "--min-confidence",
        choices=("low", "medium", "high"),
        default="medium",
        help="minimum confidence to report (default: medium)",
    )
    parser.add_argument(
        "--sort",
        choices=("criticality", "location"),
        default="criticality",
        help="order findings by criticality (most severe first) or by file "
        "location (default: criticality)",
    )
    parser.add_argument(
        "--format",
        choices=("pretty", "concise", "json"),
        default="pretty",
        help="output style: a grouped, colourised report (pretty, default); the "
        "one-line-per-finding form for editors/grep (concise); or machine JSON "
        "(json). --json is an alias for --format json.",
    )
    parser.add_argument("--json", action="store_true", help="alias for --format json")
    parser.add_argument(
        "--explain-gaps",
        action="store_true",
        help="also list blind spots: writes whose content flaplint couldn't fully "
        "trace (an unresolved library call, a value-object field, an untraced "
        "parameter). These are NOT findings and never fail the run -- they're a "
        "worklist of where a missed flap could hide.",
    )
    parser.add_argument(
        "--relations-unordered",
        action="store_true",
        help="treat model.relations[name] iteration as an unordered source "
        "(paranoid audit; Juju relation order is usually stable)",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """Parse arguments, run the analysis, print findings, return an exit code."""
    args = _build_parser().parse_args(argv)

    analyzer = Analyzer(
        args.paths,
        deps=args.dep,
        venvs=args.venv,
        auto_deps=args.auto_deps,
        python=args.python,
        report_deps=args.report_deps,
        relations_unordered=args.relations_unordered,
        min_confidence=args.min_confidence,
        sort=args.sort,
        explain_gaps=args.explain_gaps,
    )
    findings = analyzer.run()
    gaps = analyzer.gaps

    fmt = "json" if args.json else args.format

    if fmt == "json":
        payload = [f.__dict__ for f in findings]
        if args.explain_gaps:
            payload = {
                "findings": payload,
                "gaps": [g.__dict__ for g in gaps],
            }
        print(json.dumps(payload, indent=2))
    elif fmt == "concise":
        for finding in findings:
            print(finding.format())
        for gap in gaps:
            print(gap.format())
        errors = sum(1 for f in findings if f.level == "error")
        warnings = len(findings) - errors
        gap_note = f", {len(gaps)} blind spot(s)" if args.explain_gaps else ""
        print(
            f"\n{len(findings)} potential issue(s): "
            f"{errors} error(s), {warnings} warning(s){gap_note} "
            f"in {len(analyzer.primary_files)} file(s).",
            file=sys.stderr,
        )
    else:  # pretty
        report = render_report(
            findings,
            len(analyzer.primary_files),
            colour=colour_enabled(sys.stdout),
        )
        print(report)
        if args.explain_gaps:
            print(render_gaps(gaps, colour=colour_enabled(sys.stdout)))

    # Only charm-owned (error) findings fail the run; dependency warnings don't.
    return 1 if any(f.level == "error" for f in findings) else 0
