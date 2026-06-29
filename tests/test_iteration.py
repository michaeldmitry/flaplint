"""Tests for the ``unordered-iteration`` contract-boundary finding.

A helper that iterates one of its parameters (``[f(x) for x in param.items()]``)
builds a list whose *element order* mirrors the parameter's iteration order. A
key-sorting serializer (``json.dumps(sort_keys=True)`` / ``yaml.dump``) cannot
launder list-element order, so when the list escapes to a databag the only fix is
``sorted()`` at the iteration -- which is where the finding must point. This is
the ``cos-proxy`` ``ScrapeConfig.from_targets`` shape.
"""

from __future__ import annotations


def test_param_iterated_into_returned_sequence_is_flagged(lint_source):
    # The ``from_targets`` shape: a caller builds ``targets`` from an unordered
    # source (``relation.units`` is a frozenset), passes it to a helper that
    # iterates it into a list, which escapes to a databag. The finding must be
    # confirmed (``kind=caller``, ``confidence=high``) and point at the iteration
    # site in the helper -- not at the caller's databag write.
    findings = lint_source(
        """
        import json

        class ScrapeConfig:
            def from_targets(self, targets, app):
                return {
                    "static_configs": [
                        {"host": t["hostname"], "unit": name}
                        for name, t in targets.items()
                    ],
                }

        class Charm:
            def reconcile(self, relation, sc):
                # targets built from relation.units (frozenset) → locally-born
                # unordered dict: the confirmed-unstable argument.
                targets = {u.name: {"hostname": str(u)} for u in relation.units}
                job = sc.from_targets(targets, relation.app.name)
                relation.data[self.app]["scrape_jobs"] = json.dumps(job)
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    assert len(iters) == 1
    assert iters[0].kind == "caller"   # confirmed, not a heuristic sink
    assert iters[0].variable == "targets"
    assert iters[0].confidence == "high"  # confirmed from concrete unstable arg
    # Points at the ``for ... in targets.items()`` line inside from_targets.
    assert iters[0].line == 9


def test_param_iterated_with_stable_arg_is_precautionary_medium(lint_source):
    # Even when the (only visible) caller passes a plain dict literal, the
    # iteration of an unannotated parameter into an escaping sequence is a
    # *contract boundary*: we cannot prove every caller passes ordered data. So a
    # precautionary ``kind=sink`` medium finding stands at the iteration site --
    # this is what keeps the root cause (scrape_config.py:74 in cos-proxy) from
    # being a false negative when the real flow is too indirect to trace.
    findings = lint_source(
        """
        import json

        class ScrapeConfig:
            def from_targets(self, targets, app):
                return [name for name, t in targets.items()]

        class Charm:
            def reconcile(self, relation, sc):
                job = sc.from_targets({"a": {"hostname": "a"}}, relation.app.name)
                relation.data[self.app]["scrape_jobs"] = json.dumps(job)
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    assert len(iters) == 1
    assert iters[0].kind == "sink"          # precautionary, not traced
    assert iters[0].confidence == "medium"  # unannotated param
    assert iters[0].variable == "targets"


def test_untraced_iteration_is_flagged_precautionary(lint_source):
    # The cos-proxy false-negative shape in miniature: a helper iterates an
    # unannotated param into a returned sequence, and NO caller in scope writes it
    # to a databag with a traceable unstable value. The iteration must still be
    # surfaced (medium, kind=sink) -- otherwise the actual fix location is a blind
    # spot, which was the reported false negative.
    findings = lint_source(
        """
        class ScrapeConfig:
            def from_targets(self, targets, app):
                return {
                    "static_configs": [
                        {"host": t["hostname"], "unit": name}
                        for name, t in targets.items()
                    ],
                }
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    assert len(iters) == 1
    assert iters[0].kind == "sink"
    assert iters[0].confidence == "medium"
    assert iters[0].variable == "targets"


def test_sorted_iteration_source_silences_the_finding(lint_source):
    # Even when the caller passes an unordered source, wrapping the iteration in
    # ``sorted()`` removes the instability -- no iterparam is emitted, so no
    # itercaller fires, and the finding disappears.
    findings = lint_source(
        """
        import json

        class ScrapeConfig:
            def from_targets(self, targets, app):
                return [name for name, t in sorted(targets.items())]

        class Charm:
            def reconcile(self, relation, sc):
                targets = {u.name: {} for u in relation.units}
                job = sc.from_targets(targets, relation.app.name)
                relation.data[self.app]["scrape_jobs"] = json.dumps(job)
        """
    )
    assert [f for f in findings if f.rule == "unordered-iteration"] == []


def test_ordered_annotated_iterated_param_is_not_flagged(lint_source):
    # A ``List``/``Dict`` parameter is the caller's responsibility -- iterating it
    # is not a contract-boundary the helper owns.
    findings = lint_source(
        """
        from typing import Dict

        class ScrapeConfig:
            def from_targets(self, targets: Dict[str, str], app):
                return [name for name in targets]
        """
    )
    assert [f for f in findings if f.rule == "unordered-iteration"] == []


def test_set_annotated_iterated_param_is_high(lint_source):
    # A ``Set`` parameter iterated into a sequence is high confidence -- the
    # annotation proves the source is genuinely unordered.
    findings = lint_source(
        """
        import json
        from typing import Set

        class Charm:
            def publish(self, values: Set[str]):
                self.relation.data[self.app]["v"] = json.dumps([v for v in values])
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    assert len(iters) == 1
    assert iters[0].confidence == "high"


def test_iteration_finding_survives_sort_keys(lint_source):
    # List element order is NOT fixed by key-sorting, so a ``sort_keys=True`` dump
    # still flaps -- the iteration finding must survive it.
    findings = lint_source(
        """
        import json
        from typing import Set

        class Charm:
            def publish(self, values: Set[str]):
                seq = [v for v in values]
                self.relation.data[self.app]["v"] = json.dumps(seq, sort_keys=True)
        """
    )
    assert any(f.rule == "unordered-iteration" for f in findings)


def test_dict_comprehension_over_param_is_not_iteration_flagged(lint_source):
    # A *dict* comprehension's only instability is key order, which a key-sorting
    # serializer launders -- so it must NOT raise the sequence-iteration finding.
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, values):
                d = {k: 1 for k in values}
                self.relation.data[self.app]["v"] = json.dumps(d, sort_keys=True)
        """
    )
    assert [f for f in findings if f.rule == "unordered-iteration"] == []


def test_opaque_object_param_method_into_databag_is_not_a_sink(lint_source):
    # The cos-proxy ``_update_cos_agent(scrape_job_context: Optional[ScrapeJobContext])``
    # shape: the param is a *value object*, not a collection. Calling a method on it
    # and serializing the result must NOT raise a contract-boundary ``sink``
    # finding -- you cannot ``sorted()`` a dataclass; the real churn (if any) is at
    # the object's construction, reported there.
    findings = lint_source(
        """
        import json
        from typing import Optional

        class Charm:
            def _update(self, ctx: Optional[ScrapeJobContext] = None):
                config = {}
                if ctx is not None:
                    config["jobs"] = ctx.get_updated_jobs([])
                self.relation.data[self.unit]["config"] = json.dumps(config)
        """
    )
    assert [f for f in findings if f.kind == "sink"] == []


def test_unknown_any_param_into_databag_is_still_a_medium_sink(lint_source):
    # ``Any`` is genuinely unknown (it could be a collection), so it stays a
    # medium contract-boundary sink -- only *named* concrete object types are
    # exempted.
    findings = lint_source(
        """
        import json
        from typing import Any

        class Charm:
            def publish(self, values: Any):
                self.relation.data[self.app]["v"] = json.dumps(values)
        """
    )
    sinks = [f for f in findings if f.kind == "sink"]
    assert len(sinks) == 1
    assert sinks[0].confidence == "medium"


# -- materializing a local unordered collection into a sequence ----------------
# ``list(some_set)`` / ``[x for x in some_set]`` turns dict-key disorder (which a
# key-sorting serializer launders) into list-element disorder (which it cannot).
# These must survive ``yaml.dump`` / ``json.dumps(sort_keys=True)``.


def test_list_of_set_into_keysorting_serializer_is_flagged(lint_source):
    # The alertmanager config_builder shape: list(set(...)) serialized with a
    # key-sorting serializer (yaml.safe_dump). Previously laundered (false
    # negative); must now be flagged as unordered-iteration at the materialization.
    findings = lint_source(
        """
        import yaml

        class Charm:
            def publish(self, route):
                group_by = set(route.get("group_by", []))
                group_by = list(group_by.union(["juju_model", "juju_application"]))
                self.relation.data[self.app]["c"] = yaml.safe_dump({"g": group_by})
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    assert len(iters) == 1
    assert iters[0].kind == "caller"
    assert iters[0].confidence == "high"
    assert iters[0].variable == "group_by"


def test_listcomp_over_set_into_sort_keys_is_flagged(lint_source):
    # ``[x for x in some_set]`` then json.dumps(sort_keys=True): list-element order
    # is not fixed by key-sorting, so it must survive.
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, values):
                seq = [x for x in set(values)]
                self.relation.data[self.app]["v"] = json.dumps(seq, sort_keys=True)
        """
    )
    assert any(f.rule == "unordered-iteration" for f in findings)


def test_bare_set_into_keysorting_serializer_still_laundered(lint_source):
    # A *bare* set (no sequence materialization) serialized by a key-sorting
    # serializer IS fixed by key-sorting (yaml renders a set as a sorted mapping),
    # so it must NOT be flagged -- the promotion is specific to list/tuple, not
    # an over-broad "any set near a serializer".
    findings = lint_source(
        """
        import yaml

        class Charm:
            def publish(self, values):
                s = set(values)
                self.relation.data[self.app]["v"] = yaml.safe_dump(s)
        """
    )
    assert [f for f in findings if f.rule in ("unordered-iteration", "unordered-collection")] == []


def test_sorted_of_set_into_keysorting_serializer_is_clean(lint_source):
    # sorted(set(...)) is the fix: deterministic order, no finding.
    findings = lint_source(
        """
        import yaml

        class Charm:
            def publish(self, route):
                group_by = sorted(set(route.get("group_by", [])))
                self.relation.data[self.app]["c"] = yaml.safe_dump({"g": group_by})
        """
    )
    assert [f for f in findings if f.rule == "unordered-iteration"] == []


def test_returned_list_of_set_propagates_across_call(lint_source):
    # Cross-function: a helper returns list(set(...)); the caller serializes it
    # with a key-sorting serializer. The materialization taint must propagate
    # through the return (returns_itercaller) so the caller's write is flagged,
    # pointing back at the helper's list(...) site.
    findings = lint_source(
        """
        import json

        class Charm:
            def _members(self, units):
                return list(set(units))

            def publish(self, units):
                self.relation.data[self.app]["m"] = json.dumps(self._members(units), sort_keys=True)
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    assert len(iters) == 1
    assert iters[0].kind == "caller"
    assert iters[0].confidence == "high"


def test_pick_from_list_of_set_is_still_unordered_pick(lint_source):
    # Subscripting a materialized sequence (list(set(...))[0]) selects one
    # position-dependent element -- that is a *pick*, reported as unordered-pick at
    # the subscript, not as a whole-sequence unordered-iteration.
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, units):
                addrs = list(set(units))
                self.relation.data[self.app]["a"] = json.dumps(addrs[0], sort_keys=True)
        """
    )
    picks = [f for f in findings if f.rule == "unordered-pick"]
    assert len(picks) == 1
    assert picks[0].variable == "addrs"
    assert [f for f in findings if f.rule == "unordered-iteration"] == []
