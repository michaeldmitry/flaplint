"""Tests for the command-line interface and output contract."""

from __future__ import annotations

import json
import textwrap
from pathlib import Path

from flaplint.cli import main


def _write(tmp_path: Path, source: str) -> str:
    path = tmp_path / "charm.py"
    path.write_text(textwrap.dedent(source))
    return str(path)


_BUGGY = """
    import json

    class Charm:
        def _on_changed(self, event):
            self.relation.data[self.app]["v"] = json.dumps({"a", "b"})
"""

_CLEAN = """
    import json

    class Charm:
        def _on_changed(self, event):
            self.relation.data[self.app]["v"] = json.dumps(["a", "b"])
"""


def test_exit_code_nonzero_on_findings(tmp_path):
    path = _write(tmp_path, _BUGGY)
    assert main([path, "--min-confidence", "low"]) == 1


def test_exit_code_zero_when_clean(tmp_path):
    path = _write(tmp_path, _CLEAN)
    assert main([path, "--min-confidence", "low"]) == 0


def test_json_output_shape(tmp_path, capsys):
    path = _write(tmp_path, _BUGGY)
    main([path, "--min-confidence", "low", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert isinstance(payload, list) and len(payload) == 1
    entry = payload[0]
    assert set(entry) == {
        "path",
        "line",
        "col",
        "kind",
        "confidence",
        "rule",
        "sink",
        "variable",
        "level",
        "origin_path",
        "origin_line",
        "via",
    }
    assert entry["kind"] == "caller"
    assert entry["confidence"] == "high"


def test_suppress_comment_silences_finding(tmp_path):
    path = _write(
        tmp_path,
        """
        import json

        class Charm:
            def _on_changed(self, event):
                self.relation.data[self.app]["v"] = json.dumps({"a", "b"})  # databag-order: ignore
        """,
    )
    assert main([path, "--min-confidence", "low"]) == 0


def test_min_confidence_filters_medium_sinks(tmp_path, capsys):
    # An unannotated helper sink is medium; --min-confidence high must drop it.
    path = _write(
        tmp_path,
        """
        import json

        class Charm:
            def publish(self, values):
                self.relation.data[self.app]["v"] = json.dumps(values)
        """,
    )
    code = main([path, "--min-confidence", "high", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert payload == []
    assert code == 0
