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


def test_bound_unordered_call_is_named_by_its_full_expression(lint_source):
    # The cos_agent ``_dashboards`` shape: iterating ``Path(d).glob("*")`` into a list
    # that reaches a databag. The offending source is an anonymous expression (no
    # variable), so the label shows the whole thing -- what you'd wrap in ``sorted()``
    # -- not the receiver chain's root constructor ``Path``. (``ast.unparse`` renders
    # the string literal with single quotes.)
    findings = lint_source(
        """
        import json
        from pathlib import Path

        class Charm:
            def reconcile(self, relation, d):
                paths = [str(p) for p in Path(d).glob("*")]
                relation.data[self.app]["dashboards"] = json.dumps(paths)
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    assert len(iters) == 1
    assert iters[0].variable == "Path(d).glob('*')"


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


def test_loop_append_over_set_into_keysorting_serializer_is_flagged(lint_source):
    # The imperative twin of ``[x for x in set]``: a *list* built by appending while
    # iterating an unordered source bakes the iteration order into element order, so
    # it must survive a key-sorting serializer exactly like the comprehension. (Was a
    # false negative: the accumulator inherited raw ``local``, which yaml laundered.)
    findings = lint_source(
        """
        import yaml

        class Charm:
            def publish(self, relation):
                eps = []
                for unit in relation.units:
                    eps.append(relation.data[unit]["endpoint"])
                relation.data[self.app]["v"] = yaml.safe_dump(eps)
        """
    )
    assert any(f.rule == "unordered-iteration" for f in findings)


def test_loop_set_accumulator_into_keysorting_serializer_stays_laundered(lint_source):
    # Field-sensitivity of the promotion: a *set* accumulator (``s.add(...)``) is not
    # a sequence -- its disorder is key-order, which a key-sorting serializer fixes.
    # It must NOT be promoted to itercaller (that would be a false positive).
    findings = lint_source(
        """
        import yaml

        class Charm:
            def publish(self, relation):
                s = set()
                for unit in relation.units:
                    s.add(relation.data[unit]["endpoint"])
                relation.data[self.app]["v"] = yaml.safe_dump(sorted(s))
        """
    )
    assert [f for f in findings if f.rule in ("unordered-iteration", "unordered-collection")] == []


def test_loop_dict_accumulator_into_keysorting_serializer_stays_laundered(lint_source):
    # Same guard for a ``dict`` accumulator (``d[k] = v``): key-order, laundered by a
    # key-sorting serializer -- must stay un-promoted.
    findings = lint_source(
        """
        import yaml

        class Charm:
            def publish(self, relation):
                d = {}
                for unit in relation.units:
                    d[unit.name] = relation.data[unit]["endpoint"]
                relation.data[self.app]["v"] = yaml.safe_dump(d)
        """
    )
    assert [f for f in findings if f.rule in ("unordered-iteration", "unordered-collection")] == []


def test_enumerate_index_keyed_dict_is_flagged(lint_source):
    # ``{f"k-{idx}": e for idx, e in enumerate(unstable_list)}`` -- enumerate pairs an
    # element with its index, so the index->element binding flaps even though the keys
    # sort. ``enumerate`` propagates the list's itercaller taint to the dict values.
    findings = lint_source(
        """
        import yaml

        class Charm:
            def publish(self, relation):
                eps = []
                for unit in relation.units:
                    eps.append(relation.data[unit]["endpoint"])
                sinks = {}
                for idx, e in enumerate(eps):
                    sinks[f"loki-{idx}"] = e
                relation.data[self.app]["v"] = yaml.safe_dump(sinks)
        """
    )
    # Each ``e`` is the element at position ``idx`` -- a value-position pick, so the
    # dict values carry ``element`` taint (rule ``unordered-pick``) key-sorting can't fix.
    assert any(f.rule == "unordered-pick" for f in findings)


def test_enumerate_element_keyed_dict_is_not_flagged(lint_source):
    # FP guard: a dict keyed by the *element* (not the index) has deterministic keys a
    # serializer sorts -- so ``enumerate`` must propagate (not promote): no finding.
    findings = lint_source(
        """
        import yaml

        class Charm:
            def publish(self, relation):
                d = {}
                for idx, e in enumerate(sorted(relation.data[self.app])):
                    d[e] = idx
                relation.data[self.app]["v"] = yaml.safe_dump(d)
        """
    )
    assert [f for f in findings if f.rule in ("unordered-iteration", "unordered-collection")] == []


def test_nested_unordered_loops_flag_both_sources(lint_source):
    # An accumulator filled inside two nested unordered loops is scrambled by *each*
    # loop independently, so each is a distinct place a ``sorted()`` is needed --
    # both must be flagged, not just the outer one (the cos-proxy vector-config shape
    # with --relations-unordered).
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, rel1, rel2):
                eps = []
                for u1 in rel1.units:
                    for u2 in rel2.units:
                        eps.append(rel1.data[u1]["e"])
                self.rel.data[self.app]["v"] = json.dumps(eps, sort_keys=True)
        """
    )
    sources = {f.variable for f in findings if f.rule == "unordered-iteration"}
    assert sources == {"rel1.units", "rel2.units"}


def test_nested_container_element_mutation_taints_root(lint_source):
    # ``template["sinks"].update(unstable)`` outside a loop writes ``unstable`` into a
    # nested element, so the root ``template`` is order-unstable and a later
    # ``yaml.dump(template)`` flaps -- the cos-proxy vector config shape.
    findings = lint_source(
        """
        import yaml

        class Charm:
            def publish(self, relation):
                template = {"sinks": {}}
                eps = []
                for unit in relation.units:
                    eps.append(relation.data[unit]["endpoint"])
                sinks = {}
                for idx, e in enumerate(eps):
                    sinks[f"loki-{idx}"] = e
                template["sinks"].update(sinks)
                relation.data[self.app]["v"] = yaml.safe_dump(template)
        """
    )
    assert any(f.rule == "unordered-pick" for f in findings)



# -- downstream sink pointer (where the value is written, when it's not inline) --
# An iteration / pick finding is reported at the *fix* site (the loop / the index),
# which can be several lines -- or a helper call -- away from the databag write. The
# finding carries that downstream write location so the report can point at it.


def test_iteration_finding_carries_downstream_sink_location(lint_source):
    # The materialised list is built on one line and written to the databag several
    # lines later: the finding sits at the materialisation, and pins the later write.
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, relation):
                eps = list(relation.units)          # line 6: the iteration (fix here)
                payload = json.dumps(eps)            # line 7
                relation.data[self.app]["v"] = payload   # line 8: the write
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    assert iters, "expected an unordered-iteration finding"
    f = iters[0]
    assert f.line == 6           # reported at the iteration
    assert f.sink_line == 8      # points at the databag write downstream
    assert f.sink_path == f.path


def test_inline_iteration_has_no_redundant_sink_pointer(lint_source):
    # When the iteration and the write are on the *same line* (an inline
    # comprehension in the databag write), the pointer would just repeat the
    # finding's own line, so it is suppressed.
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, relation):
                relation.data[self.app]["v"] = json.dumps([u.name for u in relation.units])
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    assert iters, "expected an unordered-iteration finding"
    assert iters[0].sink_line == 0   # no separate pointer for a same-line write


def test_sink_pointer_appears_in_concise_output(lint_source):
    # The machine-readable one-liner surfaces the pointer as ``sink_at=path:line``.
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, relation):
                eps = list(relation.units)
                payload = json.dumps(eps)
                relation.data[self.app]["v"] = payload
        """
    )
    line = next(f.format() for f in findings if f.rule == "unordered-iteration")
    assert "sink_at=" in line and ":8" in line.split("sink_at=", 1)[1]


# -- born-at origin on iteration findings (restored after the local→itercaller shift) --
# The finding anchors at the materialisation (the fix site); the born-site of the
# underlying unordered value is carried through the promotion so the finding can still
# point ``origin=`` at the ``set()`` that created the churn -- the trail that used to
# ride the ``local`` flavor before it was split into ``itercaller``.


def test_iteration_finding_points_origin_at_the_born_set(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, relation):
                s = set(self.hosts)              # line 6: born here
                eps = list(s)                    # line 7: materialised (fix here)
                relation.data[self.app]["v"] = json.dumps(eps)   # line 8: written
        """
    )
    f = next(f for f in findings if f.rule == "unordered-iteration")
    assert f.line == 7                      # anchored at the materialisation
    assert f.origin_line == 6               # points back at the born set
    assert f.sink_line == 8                 # and forward at the write


def test_inline_materialisation_has_no_redundant_origin(lint_source):
    # ``list(set(x))`` on one line: the born set and the materialisation share a line,
    # so the origin would just point at itself and is suppressed.
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, relation):
                relation.data[self.app]["v"] = json.dumps(list(set(self.hosts)))
        """
    )
    f = next(f for f in findings if f.rule == "unordered-iteration")
    assert f.origin_line == 0               # no redundant self-pointing origin


def test_sink_pointer_lands_on_the_write_line_not_the_construction(lint_source):
    # ``Model(\n...\n).dump(bag)`` -- the outer call's lineno is the model line, but
    # the databag write is on the ``.dump(bag)`` line. The sink pointer must land on
    # the write, not the start of the multi-line construction.
    findings = lint_source(
        """
        from pydantic import BaseModel

        class Data(BaseModel):
            items: list

        class Charm:
            def publish(self, relation):
                eps = list(relation.units)          # line 9: the iteration
                Data(
                    items=eps,
                ).dump(relation.data[self.app])     # line 12: the write
        """
    )
    f = next(f for f in findings if f.rule == "unordered-iteration")
    assert f.line == 9        # anchored at the iteration
    assert f.sink_line == 12  # points at the .dump write, not the Data( line


# -- set built incrementally via .add()/.update() (intrinsic hash disorder) ------
# A set's iteration order is hash-seeded, so a set built up with .add()/.update() is
# unstable *regardless of what was inserted* -- even from an ordered source, and even
# though the empty ``set()`` it started from is otherwise stable. This is the
# ``requested_protocols = set(); for ...: .update(...)`` idiom (cos_agent), which
# must be caught without needing ``--relations-unordered``.


def test_empty_set_updated_in_loop_then_iterated_is_flagged(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def collect(self):
                acc = set()
                for x in self.things:      # source order irrelevant: acc is a set
                    acc.update(x)
                return acc

            def publish(self, relation):
                relation.data[self.app]["v"] = json.dumps(list(self.collect()))
        """
    )
    assert any(f.rule == "unordered-iteration" and f.sink == "databag" for f in findings)


def test_empty_set_add_then_serialized_is_flagged(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, relation):
                acc = set()
                acc.add(self.name)
                relation.data[self.app]["v"] = json.dumps(list(acc))
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_incrementally_built_set_sorted_before_sink_is_clean(lint_source):
    # The sanitiser is honoured: sorting the set before it reaches the sink is clean.
    findings = lint_source(
        """
        import json

        class Charm:
            def collect(self):
                acc = set()
                for x in self.things:
                    acc.add(x)
                return sorted(acc)

            def publish(self, relation):
                relation.data[self.app]["v"] = json.dumps(self.collect())
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_dict_accumulator_from_ordered_source_is_not_flagged(lint_source):
    # Guard against over-tainting: a *dict* built in a loop keeps insertion order, so
    # from an ordered source it is stable -- only a set has intrinsic hash disorder.
    findings = lint_source(
        """
        import json

        class Charm:
            def collect(self):
                d = {}
                for x in self.ordered_list:
                    d[x] = 1
                return d

            def publish(self, relation):
                relation.data[self.app]["v"] = json.dumps(self.collect(), sort_keys=True)
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_empty_set_never_mutated_stays_stable(lint_source):
    # An empty set that is never populated has one stable serialization -- it must
    # not be flagged just for being a set.
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, relation):
                acc = set()
                relation.data[self.app]["v"] = json.dumps(list(acc))
        """
    )
    assert not any(f.sink == "databag" for f in findings)


# --- enumerate: a value written directly under its positional index -------------
# ``for i, x in enumerate(some_set): sink(f"...{i}...", x)`` -- enumerate pairs each
# element with a *positional* index, so the value under each (stable) index flaps.
# The accumulator rule doesn't cover a sink written *directly* in the loop body
# (a ``{i}.crt`` file, a ``.../{idx}`` component), so the value target is seeded.
# This is the postgresql/loki/otel received-CA-cert anti-pattern.


def test_enumerate_value_written_to_numbered_file_is_flagged(lint_source):
    findings = lint_source(
        """
        from typing import Set

        class Charm:
            def _certs(self) -> Set[str]:
                return self._opaque()

            def receive(self, folder):
                ca_certs = self._certs()
                for i, cert in enumerate(ca_certs):
                    folder.joinpath(f"{i}.crt").write_text(cert)
        """
    )
    files = [f for f in findings if f.sink == "file"]
    assert len(files) == 1
    # ``cert`` is the element at position ``i`` -- a value-position pick.
    assert files[0].rule == "unordered-pick"
    assert files[0].confidence == "high"


def test_enumerate_value_pushed_to_workload_is_flagged(lint_source):
    # The loki shape: ``container.push(f"{i}.crt", cert)`` inside enumerate over a set.
    findings = lint_source(
        """
        from typing import Set

        class Charm:
            def _certs(self) -> Set[str]:
                return self._opaque()

            def receive(self, container):
                for i, cert in enumerate(self._certs()):
                    container.push(f"/certs/{i}.crt", cert, make_dirs=True)
        """
    )
    assert any(f.sink == "file" and f.rule == "unordered-pick" for f in findings)


def test_enumerate_sorted_source_direct_write_is_clean(lint_source):
    # The fix: sort before enumerate. The value target must not be seeded.
    findings = lint_source(
        """
        from typing import Set

        class Charm:
            def _certs(self) -> Set[str]:
                return self._opaque()

            def receive(self, folder):
                for i, cert in enumerate(sorted(self._certs())):
                    folder.joinpath(f"{i}.crt").write_text(cert)
        """
    )
    assert findings == []


def test_enumerate_over_plain_param_is_a_contract_boundary(lint_source):
    # Enumerating a bare parameter materialises it into positional bindings: the value
    # under each index (``cert``) is a contract-boundary pick the caller controls
    # (``iterparam``). Like ``[x for x in param]``, this is a *medium* contract-boundary
    # finding at the iteration -- a caller passing an unordered ``items`` would flap the
    # numbered files -- not the clean pass it used to be (that was a false negative).
    findings = lint_source(
        """
        class Charm:
            def receive(self, folder, items):
                for i, cert in enumerate(items):
                    folder.joinpath(f"{i}.crt").write_text(cert)
        """
    )
    iters = [f for f in findings if f.rule == "unordered-iteration"]
    assert iters and iters[0].confidence == "medium"


def test_enumerate_index_used_alone_is_clean(lint_source):
    # The index target ``i`` (0, 1, 2 …) is stable; only the *value* target is seeded.
    # Writing something derived solely from ``i`` must not flag.
    findings = lint_source(
        """
        from typing import Set

        class Charm:
            def _certs(self) -> Set[str]:
                return self._opaque()

            def receive(self, folder):
                for i, cert in enumerate(self._certs()):
                    folder.joinpath(f"{i}.marker").write_text(str(i))
        """
    )
    assert findings == []


# --- a field read off a value-position pick inherits the pick -------------------
# Picking an element by position from an unstable collection (``list(peers)[0]``)
# and then reading a *field* of it (``[0]["ip"]``) is still position-dependent:
# the whole object flaps, so every field does. A fixed-key subscript must inherit
# that ``element`` taint -- mirroring ``.get("ip")``, which already does via the
# method-call path. Narrow to ``element``: a plain param / local dict stays
# field-sensitive (its individual keys are order-stable).


def test_field_read_off_a_pick_is_flagged(lint_source):
    findings = lint_source(
        """
        class Charm:
            def go(self):
                addr = list(self.model.get_relation("p").units)[0]
                self.relation.data[self.app]["v"] = addr["ip"]
        """
    )
    picks = [f for f in findings if f.rule == "unordered-pick"]
    assert len(picks) == 1


def test_subscript_and_get_field_read_are_consistent(lint_source):
    # ``[0]["ip"]`` and ``[0].get("ip")`` must both be caught -- findings can't
    # depend on which spelling of the field access was used.
    sub = lint_source(
        """
        class Charm:
            def go(self):
                self.relation.data[self.app]["v"] = list(
                    self.model.get_relation("p").units
                )[0]["ip"]
        """
    )
    get = lint_source(
        """
        class Charm:
            def go(self):
                self.relation.data[self.app]["v"] = list(
                    self.model.get_relation("p").units
                )[0].get("ip")
        """
    )
    assert [f.rule for f in sub] == [f.rule for f in get] == ["unordered-pick"]


def test_deep_field_chain_off_a_pick_is_flagged(lint_source):
    findings = lint_source(
        """
        class Charm:
            def go(self):
                cfg = list(self.model.get_relation("p").units)[0]
                self.relation.data[self.app]["v"] = cfg["scrape"]["targets"]
        """
    )
    assert any(f.rule == "unordered-pick" for f in findings)


def test_field_read_off_a_param_dict_stays_clean(lint_source):
    # The field-sensitivity guard: a fixed-key read off a plain parameter is not a
    # flap (a mapping's individual keys are order-stable), so it must stay clean.
    findings = lint_source(
        """
        class Charm:
            def go(self, config):
                self.relation.data[self.app]["v"] = config["endpoint"]
        """
    )
    assert findings == []


def test_field_read_off_a_local_dict_stays_clean(lint_source):
    # A fixed-key read off a dict built locally (even one holding unstable values
    # under *other* keys) is field-sensitive: a clean key stays clean.
    findings = lint_source(
        """
        class Charm:
            def go(self):
                d = {"a": ",".join(sorted(self.x)), "b": list(self.y)}
                self.relation.data[self.app]["v"] = d["a"]
        """
    )
    assert findings == []
