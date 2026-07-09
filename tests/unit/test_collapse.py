"""Tests for ``collapse_pipelines`` -- the narrow same-write call-path deduper.

The rule keeps exactly the findings that carry *distinct* information: it drops a
finding only when another finding describes the *same physical write* fed by the
*same upstream source*, reached via a different call path. A source that fans out to
two different sinks keeps a finding per sink (distinct churn symptoms), and a value
whose shared source is unflagged is never touched.
"""

from __future__ import annotations

from flaplint.model import Finding
from flaplint.report import collapse_pipelines


def _f(path, line, *, sink, level="error", kind="caller", conf="high",
       variable="v", origin_path="", origin_line=0, sink_path="", sink_line=0):
    return Finding(
        path=path, line=line, col=1, kind=kind, confidence=conf,
        rule="unordered-iteration", sink=sink, variable=variable, level=level,
        origin_path=origin_path, origin_line=origin_line, via="src",
        sink_path=sink_path, sink_line=sink_line,
    )


def test_same_source_same_write_via_two_call_paths_collapses_to_owned():
    # The nginx shape: ``addresses`` (source at lib/nginx.py:594) reaches the *same*
    # file write (lib/nginx.py:972) through both the owned charm wrapper and the
    # vendored coordinator. One write, one fix -> keep the owned (error) finding; the
    # vendored duplicate call path drops.
    source = _f("lib/nginx.py", 594, sink="render", level="warning",
                sink_path="lib/nginx.py", sink_line=450)
    charm = _f("src/charm.py", 165, sink="file", level="error", variable="_cfg()",
               origin_path="lib/nginx.py", origin_line=594,
               sink_path="lib/nginx.py", sink_line=972)
    coord = _f("lib/coordinator.py", 473, sink="file", level="warning",
               variable="nginx_config", origin_path="lib/nginx.py", origin_line=594,
               sink_path="lib/nginx.py", sink_line=972)
    kept = collapse_pipelines([source, charm, coord])
    # The two identical file writes collapse to the owned one; the render (a *different*
    # sink on the same source) survives -- it is a distinct symptom, not a duplicate.
    assert charm in kept
    assert coord not in kept
    assert source in kept
    assert len(kept) == 2
    # The folded call path is recorded on the survivor, so the report can say "also
    # reached via ..." -- a collapsed duplicate must read as covered, not missed.
    assert charm.also_at == (("lib/coordinator.py", 473, "nginx_config"),)
    assert source.also_at == ()  # the render stands alone, nothing folded into it


def test_same_source_two_different_sinks_are_both_kept():
    # A source reaching a databag *and* a file is two distinct churn symptoms (one
    # sorted() fixes both, but each write flaps independently). The narrow rule groups
    # by (source, write), so different sinks never merge.
    source = _f("lib/h.py", 10, sink="databag", origin_path="", origin_line=0)
    to_bag = _f("src/charm.py", 20, sink="databag", origin_path="lib/h.py",
                origin_line=10, sink_path="src/charm.py", sink_line=20)
    to_file = _f("src/charm.py", 25, sink="file", origin_path="lib/h.py",
                 origin_line=10, sink_path="src/charm.py", sink_line=25)
    kept = collapse_pipelines([source, to_bag, to_file])
    assert to_bag in kept and to_file in kept  # both distinct sinks survive


def test_unflagged_shared_source_is_never_grouped():
    # The traefik shape: two carriers share an origin, but that origin is a mere
    # parameter with *no finding at it* -- so it is not an anchor, the carriers are not
    # recognised as pipeline carriers, and nothing collapses (each store stands alone).
    a = _f("src/charm.py", 20, sink="databag", origin_path="src/charm.py",
           origin_line=99, sink_path="src/charm.py", sink_line=20)
    b = _f("src/charm.py", 21, sink="secret", origin_path="src/charm.py",
           origin_line=99, sink_path="src/charm.py", sink_line=21)
    # No finding sits at line 99 (the param) -> no carrier_roots -> untouched.
    kept = collapse_pipelines([a, b])
    assert kept == [a, b]


def test_two_distinct_sources_into_one_write_both_survive():
    # postgresql's patroni.yaml: two independent sources feed one render. Different
    # origins -> different groups -> both kept, each needing its own sorted().
    src1 = _f("lib/x.py", 5, sink="file", sink_path="lib/x.py", sink_line=5)
    src2 = _f("lib/y.py", 8, sink="file", sink_path="lib/y.py", sink_line=8)
    c1 = _f("src/charm.py", 30, sink="file", origin_path="lib/x.py", origin_line=5,
            sink_path="lib/render.py", sink_line=100)
    c2 = _f("src/charm.py", 31, sink="file", origin_path="lib/y.py", origin_line=8,
            sink_path="lib/render.py", sink_line=100)
    kept = collapse_pipelines([src1, src2, c1, c2])
    assert c1 in kept and c2 in kept  # same write, but distinct sources -> both stay
