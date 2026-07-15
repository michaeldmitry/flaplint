"""End-to-end tests for ordering-instability (``local`` origin) detection.

Each test writes a small charm-like snippet and asserts on the reported
findings, mirroring the real-world bug: an order-unstable value serialized into
relation data causes spurious ``relation-changed`` churn.
"""

from __future__ import annotations



def test_set_serialized_to_databag_is_flagged(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def _on_changed(self, event):
                rel = self.model.get_relation("peers")
                rel.data[self.app]["targets"] = json.dumps({"a", "b", "c"})
        """
    )
    assert len(findings) == 1
    assert findings[0].kind == "caller"
    assert findings[0].confidence == "high"
    assert findings[0].sink == "databag"


def test_sorted_set_is_silenced(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def _on_changed(self, event):
                rel = self.model.get_relation("peers")
                rel.data[self.app]["targets"] = json.dumps(sorted({"a", "b"}))
        """
    )
    assert findings == []


def test_json_dumps_sort_keys_silences_dict_order(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def _on_changed(self, event):
                payload = {item: 1 for item in self.some_set}
                rel = self.model.get_relation("peers")
                rel.data[self.app]["x"] = json.dumps(payload, sort_keys=True)
        """
    )
    assert findings == []


def test_relation_units_iteration_is_unordered(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def _on_changed(self, event):
                names = [u.name for u in self.relation.units]
                self.relation.data[self.app]["units"] = json.dumps(names)
        """
    )
    assert len(findings) == 1
    assert findings[0].confidence == "high"


def test_self_units_is_not_mistaken_for_relation_units(lint_source):
    # ``self.units`` on the charm's own class is a bare-name collision with the ops
    # ``Relation.units`` set. Since ``self`` resolves to a known user class that does
    # not declare ``units`` as a set field, the framework guess must be suppressed --
    # a charm's own unit count / ordered value is not an unordered ops collection.
    findings = lint_source(
        """
        import json

        class Charm:
            def __init__(self):
                self.units = ["a", "b", "c"]

            def _on_changed(self, event):
                self.relation.data[self.app]["u"] = json.dumps(self.units)
        """
    )
    assert findings == []


def test_self_units_still_unordered_when_declared_as_a_set(lint_source):
    # ...but if the class actually declares ``units`` as a set field, the read is
    # genuinely unordered and must still fire (deferring to ``class_set_fields``).
    findings = lint_source(
        """
        import json
        from typing import Set

        class Charm:
            units: Set[str]

            def _on_changed(self, event):
                self.relation.data[self.app]["u"] = json.dumps(self.units)
        """
    )
    assert len(findings) == 1
    assert findings[0].confidence == "high"


def test_loop_accumulator_inherits_unordered_source(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def _on_changed(self, event):
                acc = {}
                for item in {"x", "y", "z"}:
                    acc[item] = 1
                self.relation.data[self.app]["d"] = json.dumps(acc)
        """
    )
    assert len(findings) == 1
    assert findings[0].rule == "unordered-collection"


def test_stable_list_is_not_flagged(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def _on_changed(self, event):
                rel = self.model.get_relation("peers")
                rel.data[self.app]["targets"] = json.dumps(["a", "b", "c"])
        """
    )
    assert findings == []


def test_iterating_module_level_dict_constant_is_stable(lint_source):
    """Regression: loki_push_api.py ``_promtail_binary_url`` pattern.

    A property accumulates a dict by iterating a module-level literal dict
    constant (deterministic insertion order) and serializes it via
    ``json.dumps`` before pushing it into a databag. This must not be flagged.
    """
    findings = lint_source(
        """
        import json

        BINARIES = {
            "amd64": {"filename": "a"},
            "arm64": {"filename": "b"},
        }

        class Charm:
            @property
            def _binary_url(self):
                out = {}
                for arch, info in BINARIES.items():
                    out[arch] = info
                return {"zip_url": json.dumps(out)}

            def _on_changed(self, event):
                event.relation.data[self.app].update(self._binary_url)
        """
    )
    assert findings == []


def test_single_element_literal_dict_to_config_sink_is_stable(lint_source):
    """Regression: loki_push_api.py ``disable_forwarding`` add_layer pattern.

    A single-element literal dict is the only order-bearing input to a config
    write. One element cannot be mis-ordered, so it must not be flagged.
    """
    findings = lint_source(
        """
        class Charm:
            def _disable(self, container, unit_name):
                endpoints = {unit_name: "(removed)"}
                layer = self._build_layer(endpoints)
                container.add_layer("forwarding", layer=layer, combine=True)

            def _build_layer(self, endpoints):
                return {"log-targets": endpoints}
        """
    )
    assert findings == []


def test_builtin_items_does_not_collide_with_user_items_property(lint_source):
    """Regression: cross-class collision through a builtin ``dict.items()``.

    Under ``--relations-unordered`` an unrelated class' ``items`` *property*
    (which walks ``model.relations[...]``) returns unordered. A separate class
    iterating a literal dict's builtin ``.items()`` must NOT resolve to that
    property by bare name and inherit its taint -- ``dict.items()`` follows the
    receiver's insertion order, which here is a deterministic literal.
    """
    findings = lint_source(
        """
        import json

        class CatalogueProvider:
            @property
            def items(self):
                return [r for r in self._charm.model.relations["catalogue"]]

        BINARIES = {"amd64": {"f": "a"}, "arm64": {"f": "b"}}

        class Charm:
            @property
            def _binary_url(self):
                out = {}
                for arch, info in BINARIES.items():
                    out[arch] = info
                return {"zip_url": json.dumps(out)}

            def _on_changed(self, event):
                event.relation.data[self.app].update(self._binary_url)
        """,
        relations_unordered=True,
    )
    assert findings == []
