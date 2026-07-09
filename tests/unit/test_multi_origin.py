"""One sink reached by *several* independent unstable sources must surface as
separate findings -- one per origin -- not a single representative.

A function like grafana-agent's ``_generate_config`` aggregates several sections
(loki endpoints, prometheus jobs, ...) into one config dict written to a file.
More than one of those inputs can be order-unstable; each is its own place a
``sorted()`` is needed. The summary must retain *all* return born-sites (not just
the earliest), so a reader gets the full worklist rather than whichever source
happened to sort first. This is the dual of pipeline-collapse's ``also_at`` (one
origin -> many places); here it is one place -> many origins, kept as distinct
entries.
"""

from __future__ import annotations

from conftest import details


def test_one_write_many_sources_reports_each_origin(lint_source):
    findings = lint_source(
        """
        import yaml

        class C:
            def _part_a(self):
                return list({self._x, self._y})     # materialization site A

            def _part_b(self):
                return list({self._p, self._q})     # materialization site B

            def _generate_config(self):
                return {"a": self._part_a(), "b": self._part_b()}

            def write(self):
                self._container.push("/cfg", yaml.dump(self._generate_config()))
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    # Both materialization sites must be reported, not collapsed to one.
    assert len(iters) >= 2, details(findings)
    # They are distinct entries (different anchor lines), not duplicates.
    assert len({(f.path, f.line) for f in iters}) >= 2, details(findings)
