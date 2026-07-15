"""Tests for the pretty terminal report and the ``--format`` flag."""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from flaplint.cli import main
from flaplint.handlers import _variable
from flaplint.model import Finding
from flaplint.render import _describe, colour_enabled, render_report


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
    assert "3 flap risk(s)" in report


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


def test_dependency_finding_reads_as_ownership_not_severity():
    report = render_report(
        [_finding(level="warning")], files_scanned=1, colour=False
    )
    # A dependency finding uses the ▲ mark -- never the word "warning", which read
    # as a severity clashing with the confidence axis. Ownership is conveyed by the
    # mark + footer legend, not repeated as words on each finding.
    assert "▲" in report
    assert "warning" not in report
    assert "in dependencies" in report  # summary tally
    assert "high confidence" in report  # confidence still on the header
    # Ownership words are NOT duplicated onto the finding line.
    assert "not yours to fix" not in report


def test_owned_finding_shows_confidence_and_marks():
    report = render_report([_finding(level="error")], files_scanned=1, colour=False)
    assert "✖" in report
    assert "high confidence" in report
    # The header carries confidence only; ownership lives on the ✖ mark and the
    # summary tally ("N yours"), not repeated as words on each finding line.
    assert "yours to fix" not in report
    assert "yours" in report  # summary tally names ownership


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
    assert "confidence=high" in out
    assert "owner=yours" in out
    assert "severity=" not in out  # the confusing word is gone


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


# -- offending-variable naming (handlers._variable) -------------------------


def _expr(src: str) -> ast.AST:
    return ast.parse(src, mode="eval").body


def test_variable_names_a_one_level_instance_attribute():
    # The charm idiom: an instance attribute is the actionable identifier, not the
    # useless bare ``self`` (which root_name would yield and we'd drop).
    assert _variable(_expr("self.upgrade_stack")) == "self.upgrade_stack"


def test_variable_drills_into_a_mapping_literal():
    # ``databag.update({"k": json.dumps(self.x)})`` -- the offending value is nested
    # inside the mapping; name it rather than reporting <anonymous>.
    assert _variable(_expr('{"upgrade-stack": json.dumps(self.upgrade_stack)}')) == (
        "self.upgrade_stack"
    )


def test_variable_drills_into_a_list_and_peels_wrappers():
    assert _variable(_expr("[str(peers)]")) == "peers"


def test_variable_keeps_access_chain_root_for_subscript_and_call():
    # Regression: the existing root-of-chain behaviour must survive.
    assert _variable(_expr("addrs[0]")) == "addrs"
    assert _variable(_expr("glob('*.json')")) == "glob"


def test_variable_names_the_member_for_a_deep_self_subscript():
    # ``for x in self._charm.model.relations[name]`` -- root_name is the useless
    # ``self``; name the innermost member collection (what you'd sort), not
    # <anonymous>. (The cos-proxy vector-config shape.)
    assert _variable(_expr("self._charm.model.relations[relation_name]")) == "relations"
    assert _variable(_expr("self.a.b.peers")) == "peers"


def test_variable_names_the_method_for_a_self_call():
    # ``[... for p in self.requested_tracing_protocols()]`` -- root_name gives the
    # useless ``self``; name the method that produced the value, not <anonymous>
    # (parallels the free call ``glob(...)`` -> ``glob``).
    assert _variable(_expr("self.requested_tracing_protocols()")) == (
        "requested_tracing_protocols()"
    )
    # a call on a *named* receiver keeps the informative receiver root, unchanged.
    assert _variable(_expr("obj.bar()")) == "obj"


def test_variable_peels_a_mapping_view_to_its_receiver():
    # ``for k, v in self._relation_hosts(rel).items()`` -- the view is a
    # transparent window onto the mapping, so name the mapping that produced it
    # (``_relation_hosts()``), never the blameless ``items()`` (the grafana_source
    # shape). ``.keys()`` / ``.values()`` peel the same way.
    assert _variable(_expr("self._relation_hosts(rel).items()")) == (
        "_relation_hosts()"
    )
    assert _variable(_expr("hosts.keys()")) == "hosts"
    assert _variable(_expr("self.mapping.values()")) == "self.mapping"
    # A same-named method that takes arguments is NOT a view -- don't peel it.
    assert _variable(_expr("queue.items(limit)")) == "queue"


def test_variable_is_empty_for_a_bare_self_and_an_anonymous_literal():
    assert _variable(_expr("self")) == ""
    assert _variable(_expr("{1, 2, 3}")) == ""  # no named value to point at


# -- iteration-finding description wording -----------------------------------


def _describe_of(f: Finding) -> str:
    """The single-sentence description for one finding (unwrapped)."""
    return _describe(f)


def test_upstream_iteration_description_omits_redundant_fix_hint():
    # When the instability has an upstream origin, "Fix at the source" carries the
    # advice -- the generic "Sort the collection before iterating" and the wordy
    # "not at this write" are dropped.
    f = Finding(
        path="charm.py", line=10, col=5, kind="caller", confidence="high",
        rule="unordered-iteration", sink="databag", variable="self.app_units",
        origin_path="lib/upgrade.py", origin_line=551, via="app_units",
        sink_path="lib/upgrade.py", sink_line=994,
    )
    text = _describe_of(f)
    assert "Fix at the source" in text
    assert "Sort the collection before iterating" not in text
    assert "not at this write" not in text
    assert "994" in text  # still shows where it lands


def test_reattributed_pick_description_does_not_call_the_subject_the_pick():
    # A cross-file re-attributed ``unordered-pick`` anchors at the *consuming* value
    # (``config``, a rendered blob), not at the positional pick (which is upstream).
    # So the description must not claim ``config`` "is selected by position" -- it
    # *carries* an upstream pick. Discriminated by origin_path being a different file.
    f = Finding(
        path="src/charm.py", line=637, col=13, kind="caller", confidence="high",
        rule="unordered-pick", sink="file", variable="config",
        origin_path="src/vector.py", origin_line=247, via="loki_endpoints",
    )
    text = _describe_of(f)
    assert "config` carries a value picked by position" in text
    assert "config` is selected by position" not in text
    assert "Fix at the source" in text


def test_same_file_pick_description_names_the_value_taken_from_the_subject():
    # A same-file pick anchors *at* the pick. The direct wording says a value is
    # taken *by position from* the subject -- true for both a literal ``addr[0]``
    # subscript and an ``enumerate`` value target (where each element is bound to a
    # position). It must not claim the collection itself "is selected by position"
    # (which reads as a single ``addr[N]`` and is wrong for the enumerate shape),
    # nor use the cross-file "carries a value picked" wording.
    f = Finding(
        path="charm.py", line=10, col=5, kind="caller", confidence="high",
        rule="unordered-pick", sink="databag", variable="addr",
        origin_path="charm.py", origin_line=8,
    )
    text = _describe_of(f)
    assert "value taken by position from `addr`" in text
    assert "is selected by position" not in text
    assert "carries a value picked by position" not in text


def test_confirmed_iteration_description_does_not_blame_the_caller():
    # A ``kind=caller`` iteration finding is *confirmed* here -- the source was
    # traced -- so it must not hedge with "if a caller passes an unordered
    # collection". It states the source is unordered, and weaves the sink
    # location into the sentence rather than tacking it on at the end.
    f = Finding(
        path="charm.py", line=4, col=15, kind="caller", confidence="high",
        rule="unordered-iteration", sink="render", variable="relation.units",
        sink_path="charm.py", sink_line=6,
    )
    text = _describe_of(f)
    assert "If a caller passes" not in text
    assert "unordered source iterated without sorted()" in text
    assert "It reaches" not in text  # location is inline, not a trailing sentence
    assert "rendered workload config at charm.py:6" in text


def test_crossfile_iteration_carrier_is_not_called_the_iteration_site():
    # A ``kind=caller`` iteration finding whose born site is in *another file* anchors
    # at a downstream *carrier* -- often not even a collection (``_nginx_config()``
    # returns a str; ``json.dumps(jobs)`` a serialized blob). The disorder was baked
    # in by an unsorted iteration upstream. So the description must not claim the
    # subject "is an unordered source iterated" at this line; it *carries* pre-baked
    # disorder. Discriminated by origin_path being a different file (mirrors the
    # cross-file ``unordered-pick`` carrier branch).
    f = Finding(
        path="src/charm.py", line=165, col=9, kind="caller", confidence="high",
        rule="unordered-iteration", sink="file", variable="_nginx_config()",
        origin_path="lib/nginx.py", origin_line=594, via="addresses",
        sink_path="lib/nginx.py", sink_line=972,
    )
    text = _describe_of(f)
    assert "carries a value whose element order was baked in" in text
    assert "is an unordered source iterated" not in text
    assert "Fix at the source" in text  # still points at the real iteration
    assert "addresses" in text


def test_folded_siblings_are_surfaced_as_also_reached_via():
    # A survivor of the pipeline collapse names the other call paths that hit the same
    # write, so a reader who expected a finding at one of them sees it was folded in,
    # not silently dropped.
    f = Finding(
        path="src/charm.py", line=165, col=9, kind="caller", confidence="high",
        rule="unordered-iteration", sink="file", variable="_cfg()",
        origin_path="lib/nginx.py", origin_line=594, via="addresses",
        sink_path="lib/nginx.py", sink_line=972,
        also_at=(("lib/coordinator.py", 473, "nginx_config"),),
    )
    text = _describe_of(f)
    assert "same write is also reached via `nginx_config` (lib/coordinator.py:473)" in text
    assert "covers that path too" in text


def test_no_folded_siblings_adds_no_also_reached_clause():
    f = Finding(
        path="src/charm.py", line=10, col=5, kind="caller", confidence="high",
        rule="unordered-iteration", sink="databag", variable="x",
    )
    assert "also reached via" not in _describe_of(f)


def test_param_boundary_iteration_blames_the_caller_not_the_parameter():
    # A confirmed iteration of a *formal parameter* with no single born site (several
    # callers feed it) -- cos-proxy's ``_label_alert_rules(unit_rules, ...)``. The
    # reader can't see from this line *why* the param is unordered, so the description
    # must name the caller boundary and offer the type-annotation fix, not imply the
    # parameter is intrinsically unordered.
    f = Finding(
        path="src/agg.py", line=678, col=33, kind="caller", confidence="high",
        rule="unordered-iteration", sink="databag", variable="unit_rules",
        via_param=True, sink_path="src/agg.py", sink_line=201,
    )
    text = _describe_of(f)
    assert "a caller passes an unordered collection into `unit_rules`" in text
    assert "is an unordered source iterated" not in text
    assert "annotate `unit_rules` as dict/list" in text


def test_samefile_iteration_born_here_still_says_iterated_here():
    # The carrier rewording must NOT swallow a same-file born-here iteration: when the
    # unsorted iteration is at *this* line (origin absent, or in the same file), the
    # subject really is the source being looped -- keep the direct "iterated" wording.
    f = Finding(
        path="lib/nginx.py", line=594, col=45, kind="caller", confidence="high",
        rule="unordered-iteration", sink="render", variable="addresses",
        sink_path="lib/nginx.py", sink_line=450,
    )
    text = _describe_of(f)
    assert "is an unordered source iterated without sorted()" in text
    assert "carries a value whose element order" not in text
