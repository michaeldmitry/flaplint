"""Tests for the pretty terminal report and the ``--format`` flag."""

from __future__ import annotations

import textwrap
from pathlib import Path

from flaplint.cli import main
from flaplint.model import Finding
from flaplint.render import colour_enabled, render_report


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


def _finding(**over) -> Finding:
    base = dict(
        path="src/charm.py",
        line=10,
        col=5,
        kind="caller",
        confidence="high",
        rule="unordered-collection",
        sink="databag",
        variable="peers",
        level="error",
        origin_path="",
        origin_line=0,
        via="",
    )
    base.update(over)
    return Finding(**base)


def test_render_groups_by_file_and_has_plain_english():
    findings = [
        _finding(path="src/a.py", rule="unordered-collection", variable="peers"),
        _finding(path="src/a.py", rule="nondeterministic", variable="uuid4"),
        _finding(path="src/b.py", rule="unordered-pick", variable="list"),
    ]
    report = render_report(findings, files_scanned=2, colour=False)
    # File headers appear once each, in first-appearance order.
    assert report.index("src/a.py") < report.index("src/b.py")
    assert report.count("src/a.py") == 1
    # Human titles and a concrete description, not raw rule slugs only.
    assert "unordered collection" in report
    assert "peers" in report  # concrete description names the variable
    # Footer summary with totals.
    assert "3 problem(s)" in report


def test_render_clean_message():
    report = render_report([], files_scanned=4, colour=False)
    assert "No flapping risks found" in report
    assert "4 file(s) scanned" in report


def test_render_no_ansi_when_colour_disabled():
    report = render_report([_finding()], files_scanned=1, colour=False)
    assert "\033[" not in report


def test_render_ansi_when_colour_enabled():
    report = render_report([_finding()], files_scanned=1, colour=True)
    assert "\033[" in report


def test_warning_finding_notes_dependency_ownership():
    report = render_report(
        [_finding(level="warning")], files_scanned=1, colour=False
    )
    # A warning finding renders with the warning mark and is counted as such.
    assert "▲" in report
    assert "warning(s)" in report


def test_colour_enabled_respects_no_color(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.delenv("FORCE_COLOR", raising=False)

    class _TTY:
        def isatty(self):
            return True

    assert colour_enabled(_TTY()) is False


def test_colour_enabled_force_color(monkeypatch):
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("FORCE_COLOR", "1")

    class _NotTTY:
        def isatty(self):
            return False

    assert colour_enabled(_NotTTY()) is True


def test_format_concise_matches_finding_format(tmp_path, capsys):
    path = _write(tmp_path, _BUGGY)
    main([path, "--min-confidence", "low", "--format", "concise"])
    out = capsys.readouterr().out
    assert "type=unordered-collection" in out
    assert "severity=high" in out


def test_format_pretty_is_default(tmp_path, capsys):
    path = _write(tmp_path, _BUGGY)
    main([path, "--min-confidence", "low"])
    out = capsys.readouterr().out
    assert "flaplint" in out
    assert "unordered collection" in out


def test_json_flag_is_alias_for_format_json(tmp_path, capsys):
    path = _write(tmp_path, _BUGGY)
    main([path, "--min-confidence", "low", "--json"])
    out = capsys.readouterr().out.lstrip()
    assert out.startswith("[")
