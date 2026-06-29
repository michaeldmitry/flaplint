"""Blind-spot reporting (``--explain-gaps``).

A *gap* is a write whose content flaplint couldn't fully trace — an unresolved
library call, a value-object field it doesn't model, or an untraced parameter into a
file/plan/hash write. Gaps are diagnostics, not findings: they never fail the run,
they're a worklist of where a missed flap (a false negative) could hide.
"""

from __future__ import annotations

import textwrap

from flaplint.analyzer import Analyzer


def _gaps(tmp_path, source: str):
    path = tmp_path / "charm.py"
    path.write_text(textwrap.dedent(source))
    a = Analyzer([str(path)], min_confidence="low", explain_gaps=True)
    a.run()
    return a.gaps


def _reasons(gaps):
    return " || ".join(g.reason for g in gaps)


def test_no_gaps_without_the_flag(tmp_path):
    # The analysis pays nothing, and reports nothing, unless explain_gaps is on.
    path = tmp_path / "charm.py"
    path.write_text(
        textwrap.dedent(
            """
            class Charm:
                def reconcile(self, c):
                    c.push("/f", external_render(self.data))
            """
        )
    )
    a = Analyzer([str(path)], min_confidence="low")  # no explain_gaps
    a.run()
    assert a.gaps == []


def test_unresolved_call_into_a_write_is_a_gap(tmp_path):
    # A call flaplint can't see into, feeding a file write, is a blind spot.
    gaps = _gaps(
        tmp_path,
        """
        class Charm:
            def reconcile(self, container):
                container.push("/etc/app.conf", external_render(self.config))
        """,
    )
    assert any("external_render" in g.reason and g.sink == "file" for g in gaps)


def test_fully_traced_write_has_no_gap(tmp_path):
    # A write whose content is a known-stable expression is fully accounted for.
    gaps = _gaps(
        tmp_path,
        """
        class Charm:
            def reconcile(self, container):
                container.push("/etc/app.conf", ",".join(sorted(self.names)))
        """,
    )
    assert gaps == []


def test_untraced_parameter_into_file_write_is_a_gap(tmp_path):
    # A helper that writes a parameter to a file gets no caller-contract check, so
    # an unordered caller would slip through — flag it as a blind spot.
    gaps = _gaps(
        tmp_path,
        """
        class Charm:
            def _write(self, container, data):
                container.push("/etc/app.conf", data)
        """,
    )
    assert any("parameter `data`" in g.reason and g.sink == "file" for g in gaps)


def test_self_is_not_reported_as_an_untraced_parameter(tmp_path):
    # `self` is a parameter but never the unstable content — must not be flagged.
    gaps = _gaps(
        tmp_path,
        """
        class Charm:
            def _write(self, container):
                container.push("/etc/app.conf", self.path.read_bytes())
        """,
    )
    assert not any("`self`" in g.reason for g in gaps)


def test_opaque_value_object_field_is_a_gap(tmp_path):
    # A value object's field flaplint doesn't track (here, buried in a dict) read back
    # and written is exactly the dataclass-field blind spot.
    gaps = _gaps(
        tmp_path,
        """
        class Charm:
            def reconcile(self, container):
                ctx = Ctx(cfg={"jobs": list(self.jobs)})
                container.push("/etc/app.conf", ctx.cfg)
        """,
    )
    assert any(".cfg" in g.reason and "value object" in g.reason for g in gaps)


def test_gap_is_dropped_when_a_finding_already_covers_the_line(tmp_path):
    # A concrete finding and a gap on the same line is redundant — keep the finding.
    path = tmp_path / "charm.py"
    path.write_text(
        textwrap.dedent(
            """
            class Charm:
                def reconcile(self, container):
                    container.push("/etc/app.conf", ",".join(set(self.names)))
            """
        )
    )
    a = Analyzer([str(path)], min_confidence="low", explain_gaps=True)
    findings = a.run()
    assert any(f.kind == "caller" for f in findings)  # the join-of-set is flagged
    finding_lines = {(f.path, f.line) for f in findings}
    assert all((g.path, g.line) not in finding_lines for g in a.gaps)


def test_ordered_annotated_param_into_file_is_not_a_gap(tmp_path):
    # A parameter the caller promises to keep ordered (`data: str`) is the caller's
    # responsibility, not a blind spot.
    gaps = _gaps(
        tmp_path,
        """
        class Charm:
            def _write(self, container, data: str):
                container.push("/etc/app.conf", data)
        """,
    )
    assert not any("`data`" in g.reason for g in gaps)


def test_format_with_kwargs_param_is_not_a_gap(tmp_path):
    # `template.format(**context)` is ordered by the template, not by `context`'s
    # dict order — the param's instability never reaches the output, so no gap.
    gaps = _gaps(
        tmp_path,
        """
        class Charm:
            def _write(self, dest, context):
                dest.write_text(TEMPLATE.format(**context))
        """,
    )
    assert not any("context" in g.reason for g in gaps)


def test_method_call_receiver_is_not_a_field_gap(tmp_path):
    # `obj.method()` is a method call, not a field read — must not be reported as an
    # opaque value-object field.
    gaps = _gaps(
        tmp_path,
        """
        class Charm:
            def reconcile(self, container):
                model = Model(name="x")
                container.push("/f", model.render())
        """,
    )
    assert not any("`.render`" in g.reason for g in gaps)


def test_reading_a_file_is_not_a_gap(tmp_path):
    # Hashing a file's contents (read_bytes) is the intended change-detector input,
    # deterministic given the file — not an ordering blind spot.
    gaps = _gaps(
        tmp_path,
        """
        import hashlib

        class Charm:
            def _digest(self, path):
                return hashlib.sha256(path.read_bytes()).hexdigest()
        """,
    )
    assert not any("read_bytes" in g.reason for g in gaps)
