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



def test_local_multi_origin_same_sink_dispatching_property(lint_source):
    """Two branches of a dispatching property, each building an unstable dict,
    both reach the same databag write — the proxy_loki_endpoints pattern.

    Both born-sites must surface as distinct findings (not collapsed to the
    earliest), so a reader sees the full worklist.
    """
    findings = lint_source(
        """
        import json

        class Worker:
            def proxy_endpoints(self, relations):
                endpoints = {}
                for r in relations:
                    for u in r.units:
                        endpoints[u.name] = f"proxy-{u.name}"
                return endpoints

            def upstream_endpoints(self, relations):
                endpoints = {}
                for r in relations:
                    for u in r.units:
                        endpoints[u.name] = f"upstream-{u.name}"
                return endpoints

            @property
            def endpoints(self):
                relations = self.model.relations.get("logging", [])
                if self._proxy_enabled:
                    return self.proxy_endpoints(relations)
                return self.upstream_endpoints(relations)

            def publish(self):
                bag = self.model.get_relation("cluster").data[self.app]
                bag["endpoints"] = json.dumps(self.endpoints)
        """
    )
    local_findings = [f for f in findings if f.rule == "unordered-collection"]
    # Both branches must be reported at the same sink.
    assert len(local_findings) >= 2, details(findings)
    # Distinct origin sites (proxy_endpoints and upstream_endpoints).
    origins = {(f.origin_path, f.origin_line, f.via) for f in local_findings if f.via}
    assert len(origins) >= 2, f"Expected 2+ distinct origins, got {origins}"
    # Same sink (line 38: the databag write).
    assert len({(f.path, f.line) for f in local_findings}) == 1, details(findings)


def test_element_multi_origin_same_sink(lint_source):
    """Two distinct positional picks from unordered sources, combined into one
    value written to a sink — both picks must be reported.
    """
    findings = lint_source(
        """
        import json

        class C:
            def publish(self):
                items_a = {"x", "y", "z"}
                items_b = {"p", "q", "r"}
                first_a = list(items_a)[0]
                first_b = list(items_b)[0]
                bag = self.model.get_relation("cluster").data[self.app]
                bag["picks"] = json.dumps([first_a, first_b])
        """
    )
    picks = [f for f in findings if f.rule == "unordered-pick"]
    # Both pick sites must be reported.
    assert len(picks) >= 2, details(findings)
    # Distinct pick lines.
    assert len({(f.path, f.line) for f in picks}) >= 2, details(findings)


def test_local_multi_origin_different_sinks(lint_source):
    """Two unstable sources reaching *different* sinks are independent findings."""
    findings = lint_source(
        """
        import json

        class C:
            def build_a(self, relations):
                d = {}
                for r in relations:
                    for u in r.units:
                        d[u.name] = "a"
                return d

            def build_b(self, relations):
                d = {}
                for r in relations:
                    for u in r.units:
                        d[u.name] = "b"
                return d

            def publish(self):
                relations = self.model.relations.get("logging", [])
                bag = self.model.get_relation("cluster").data[self.app]
                bag["a"] = json.dumps(self.build_a(relations))
                bag["b"] = json.dumps(self.build_b(relations))
        """
    )
    local_findings = [f for f in findings if f.rule == "unordered-collection"]
    # Both sources reported.
    assert len(local_findings) >= 2, details(findings)
    # Different sink lines (bag["a"] and bag["b"]).
    assert len({(f.path, f.line) for f in local_findings}) >= 2, details(findings)