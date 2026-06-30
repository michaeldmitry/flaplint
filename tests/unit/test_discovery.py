"""Tests for dependency auto-discovery and criticality ordering.

These exercise the two newest capabilities end-to-end: ``--auto-deps`` (find the
installed packages that actually write to relation data and trace only those)
and ``--sort criticality`` (most severe findings first).
"""

from __future__ import annotations

import os
import sys
import textwrap
from pathlib import Path
from typing import List

from flaplint.analyzer import Analyzer
from flaplint.discovery import (
    candidate_venvs,
    filter_sink_roots,
    imported_top_levels,
    interpreter_module_paths,
    sink_dep_roots,
)
from flaplint.model import Finding


def _write(path: Path, source: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(textwrap.dedent(source))
    return path


# --- import scanning ------------------------------------------------------


def test_imported_top_levels_collects_import_and_from(tmp_path: Path) -> None:
    f = _write(
        tmp_path / "charm.py",
        """
        import cosl.coordinated_workers
        import json
        from ops import CharmBase
        from . import helpers  # relative -> ignored
        """,
    )
    assert imported_top_levels([str(f)]) == {"cosl", "json", "ops"}


# --- sink package discovery ----------------------------------------------


def _fake_site_packages(tmp_path: Path) -> Path:
    """A site-packages with one databag-writing dep and one innocent dep."""
    sp = tmp_path / "site-packages"
    _write(
        sp / "writerdep" / "__init__.py",
        """
        def publish(relation, app, payload):
            relation.data[app]["rules"] = payload
        """,
    )
    _write(
        sp / "innocentdep" / "__init__.py",
        """
        def add(a, b):
            return a + b
        """,
    )
    return sp


def test_sink_dep_roots_keeps_only_databag_writers(tmp_path: Path) -> None:
    sp = _fake_site_packages(tmp_path)
    roots = sink_dep_roots([str(sp)])
    assert roots == [str(sp / "writerdep")]


def test_sink_dep_roots_respects_imported_filter(tmp_path: Path) -> None:
    sp = _fake_site_packages(tmp_path)
    # The charm imports the writer -> included.
    assert sink_dep_roots([str(sp)], {"writerdep"}) == [str(sp / "writerdep")]
    # The charm never imports it -> skipped even though it writes a databag.
    assert sink_dep_roots([str(sp)], {"json"}) == []


def test_sink_dep_roots_recognizes_relation_save(tmp_path: Path) -> None:
    """A dep that publishes via the ops ``relation.save(obj, app)`` API is selected."""
    sp = tmp_path / "site-packages"
    _write(
        sp / "savedep" / "__init__.py",
        """
        class Requirer:
            def publish(self, relation, data):
                relation.save(data, self._charm.app)
        """,
    )
    assert sink_dep_roots([str(sp)]) == [str(sp / "savedep")]


# --- interpreter-based resolution (--python) ------------------------------


def test_interpreter_module_paths_resolves_and_filters(
    tmp_path: Path, monkeypatch
) -> None:
    """Resolve real on-disk deps through an interpreter, then keep only writers."""
    sp = tmp_path / "envsite"
    _write(
        sp / "savedep" / "__init__.py",
        """
        class Requirer:
            def publish(self, relation, data):
                relation.save(data, self._charm.app)
        """,
    )
    _write(sp / "plaindep" / "__init__.py", "X = 1\n")
    monkeypatch.setenv("PYTHONPATH", str(sp))

    resolved = interpreter_module_paths(
        sys.executable, {"savedep", "plaindep", "json"}
    )
    normalised = {os.path.normpath(p) for p in resolved}
    assert os.path.normpath(str(sp / "savedep")) in normalised
    assert os.path.normpath(str(sp / "plaindep")) in normalised
    # stdlib is skipped, never resolved.
    assert not any("json" == os.path.basename(p) for p in resolved)
    # ...and only the databag writer survives the sink filter.
    assert filter_sink_roots(resolved) == [str(sp / "savedep")]


def test_interpreter_module_paths_bad_interpreter_is_quiet(tmp_path: Path) -> None:
    assert interpreter_module_paths(str(tmp_path / "nope"), {"json"}) == []


def test_python_flag_traces_writer_dependency(
    tmp_path: Path, monkeypatch
) -> None:
    """End-to-end: --python resolves an installed dep and traces the bug across it."""
    sp = tmp_path / "envsite"
    _write(
        sp / "writerdep" / "__init__.py",
        """
        import json
        def publish(relation, app, value):
            relation.data[app]["x"] = json.dumps(value)
        """,
    )
    monkeypatch.setenv("PYTHONPATH", str(sp))
    charm = _write(
        tmp_path / "src" / "charm.py",
        """
        import writerdep
        def handler(self):
            writerdep.publish(self.relation, self.app, {1, 2, 3})
        """,
    )

    without = Analyzer([str(charm)], min_confidence="low").run()
    assert without == []  # dep not resolvable -> bug invisible

    with_py = Analyzer(
        [str(charm)],
        python=sys.executable,
        min_confidence="low",
    ).run()
    assert any(f.kind == "caller" for f in with_py)


def test_candidate_venvs_finds_sibling_dot_venv(tmp_path: Path) -> None:
    (tmp_path / "src").mkdir()
    (tmp_path / ".venv").mkdir()
    found = candidate_venvs([str(tmp_path / "src")])
    assert str(tmp_path / ".venv") in found


# --- auto-deps wired through the analyzer --------------------------------


def test_auto_deps_traces_writer_dependency(tmp_path: Path) -> None:
    """An unordered value forwarded into a dep helper is caught only with deps."""
    sp = tmp_path / ".venv" / "lib" / "python3.14" / "site-packages"
    _write(
        sp / "writerdep" / "__init__.py",
        """
        import json
        def publish(relation, app, value):
            relation.data[app]["x"] = json.dumps(value)
        """,
    )
    charm = _write(
        tmp_path / "src" / "charm.py",
        """
        import writerdep
        def handler(self):
            writerdep.publish(self.relation, self.app, {1, 2, 3})
        """,
    )

    without = Analyzer([str(charm)], min_confidence="low").run()
    assert without == []  # the bug lives across the dep boundary

    with_deps = Analyzer(
        [str(charm)], auto_deps=True, min_confidence="low"
    ).run()
    assert any(f.kind == "caller" for f in with_deps)


# --- criticality ordering ------------------------------------------------


def _kinds_and_conf(findings: List[Finding]) -> List[tuple]:
    return [(f.confidence, f.kind) for f in findings]


def test_criticality_sort_puts_high_callers_first(tmp_path: Path) -> None:
    charm = _write(
        tmp_path / "charm.py",
        """
        import json, uuid
        def helper(self, data):  # sink/medium: param to databag, no sort
            self.relation.data[self.app]["h"] = json.dumps(data)
        def handler(self):       # caller/high: volatile written to databag
            self.relation.data[self.app]["v"] = json.dumps(uuid.uuid4())
        """,
    )
    crit = Analyzer([str(charm)], min_confidence="low").run()
    loc = Analyzer(
        [str(charm)], min_confidence="low", sort="location"
    ).run()

    # Same finding set, different order.
    assert {f.format() for f in crit} == {f.format() for f in loc}
    # Criticality: the high/caller finding sorts ahead of the medium/sink one.
    confs = [f.confidence for f in crit]
    assert confs == sorted(confs, key=lambda c: {"high": 0, "medium": 1, "low": 2}[c])
    assert crit[0].confidence == "high"
