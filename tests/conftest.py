"""Shared pytest fixtures and helpers for the databag-order-lint suite.

The central helper, :func:`lint_source`, runs the *whole* pipeline over an inline
charm snippet written to a temp file, so tests read like end-to-end behaviour
specs rather than white-box assertions against internal passes.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import List

import pytest

from flaplint.analyzer import Analyzer
from flaplint.model import Finding


@pytest.fixture
def lint_source(tmp_path: Path):
    """Return a callable that lints an inline snippet and yields findings.

    Usage::

        findings = lint_source('''
            def handler(self):
                self.relation.data[self.app]["x"] = json.dumps({1, 2})
        ''', min_confidence="low")
    """

    counter = {"n": 0}

    def _run(source: str, *, min_confidence: str = "low", **kwargs) -> List[Finding]:
        counter["n"] += 1
        path = tmp_path / f"charm_{counter['n']}.py"
        path.write_text(textwrap.dedent(source))
        return Analyzer(
            [str(path)],
            min_confidence=min_confidence,
            **kwargs,
        ).run()

    return _run


def details(findings: List[Finding]) -> str:
    """Join all findings' structured renderings into one searchable string."""
    return "\n".join(f.format() for f in findings)
