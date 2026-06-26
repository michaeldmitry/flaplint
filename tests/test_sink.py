"""Tests for sink findings, annotation grading, and hash-sink behaviour."""

from __future__ import annotations


def test_helper_writing_set_annotated_param_is_high(lint_source):
    findings = lint_source(
        """
        import json
        from typing import Set

        class Charm:
            def publish(self, values: Set[str]):
                self.relation.data[self.app]["v"] = json.dumps(values)
        """
    )
    sinks = [f for f in findings if f.kind == "sink"]
    assert len(sinks) == 1
    assert sinks[0].confidence == "high"  # Set annotation -> high


def test_helper_with_unannotated_param_is_medium(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, values):
                self.relation.data[self.app]["v"] = json.dumps(values)
        """
    )
    sinks = [f for f in findings if f.kind == "sink"]
    assert len(sinks) == 1
    assert sinks[0].confidence == "medium"


def test_ordered_annotation_param_is_not_a_sink(lint_source):
    # A List parameter is the caller's responsibility, not the helper's fault.
    findings = lint_source(
        """
        import json
        from typing import List

        class Charm:
            def publish(self, values: List[str]):
                self.relation.data[self.app]["v"] = json.dumps(values)
        """
    )
    assert [f for f in findings if f.kind == "sink"] == []


def test_hash_of_set_is_flagged(lint_source):
    findings = lint_source(
        """
        import hashlib

        class Charm:
            def _hash(self):
                digest = hashlib.sha256(str({"a", "b"}).encode()).hexdigest()
                return digest
        """
    )
    assert len(findings) == 1
    assert findings[0].sink == "hash"


def test_hash_inside_dunder_is_suppressed(lint_source):
    # __hash__/__eq__ object hashing is in-process and never causes churn.
    findings = lint_source(
        """
        class Value:
            def __hash__(self):
                return hash((self.name, frozenset(self.tags)))
        """
    )
    assert findings == []


def test_update_on_literal_databag_is_a_sink(lint_source):
    # ``relation.data[app].update(<unordered>)`` is a relation-data write even
    # though no item-assignment syntax appears -- detected structurally.
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation):
                relation.data[self.app].update({"members": set(self._units)})
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].sink == "databag"


def test_update_on_aliased_databag_is_a_sink(lint_source):
    # A local aliased to a databag mapping is still a databag.
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation):
                bag = relation.data[self.app]
                bag.update({"members": set(self._units)})
        """
    )
    assert len([f for f in findings if f.kind == "caller"]) == 1


def test_item_assign_on_aliased_databag_is_a_sink(lint_source):
    # ``bag[k] = <unordered>`` where ``bag`` is a databag alias (single subscript).
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation):
                bag = relation.data[self.app]
                bag["members"] = set(self._units)
        """
    )
    assert len([f for f in findings if f.kind == "caller"]) == 1


def test_setdefault_on_databag_is_a_sink(lint_source):
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation):
                bag = relation.data[self.app]
                bag.setdefault("members", set(self._units))
        """
    )
    assert len([f for f in findings if f.kind == "caller"]) == 1


def test_update_on_aliased_databag_propagates_param_taint(lint_source):
    # A helper that writes a parameter into a databag via ``.update`` exposes the
    # param as a sink, just like an item-assignment would.
    findings = lint_source(
        """
        from typing import Set

        class Charm:
            def publish(self, relation, values: Set[str]):
                bag = relation.data[self.app]
                bag.update({"v": values})
        """
    )
    sinks = [f for f in findings if f.kind == "sink"]
    assert len(sinks) == 1
    assert sinks[0].confidence == "high"  # Set annotation -> high


def test_non_databag_update_is_not_a_sink(lint_source):
    # ``.update`` on a plain dict (not a ``.data[entity]`` mapping) is not a sink.
    findings = lint_source(
        """
        class Charm:
            def build(self):
                payload = {}
                payload.update({"members": set(self._units)})
                return payload
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_model_dump_escape_with_unordered_field_is_a_sink(lint_source):
    # ``model = Model(field=<unordered>); model.dump(bag)`` -- the databag is
    # passed *as an argument* to a writer, and the model carries the field's
    # instability (pydantic-field taint). This is the cosl ``DatabagModel.dump``
    # idiom.
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation):
                bag = relation.data[self.app]
                model = ProviderApplicationData(members=set(self._units))
                model.dump(bag)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].rule == "unordered-collection"


def test_inline_model_dump_escape_is_a_sink(lint_source):
    # ``Model(field=<unordered>).dump(relation.data[app])`` -- inline constructed
    # value object, no intermediate variable.
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation):
                ProviderApplicationData(members=set(self._units)).dump(
                    relation.data[self.app]
                )
        """
    )
    assert len([f for f in findings if f.kind == "caller"]) == 1


def test_free_writer_with_databag_arg_and_unordered_sibling_is_a_sink(lint_source):
    # ``write(relation.data[app], <unordered>)`` -- the databag is the
    # destination; the unordered sibling argument is the content written into it.
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation):
                update_relation_data(relation.data[self.app], set(self._units))
        """
    )
    assert len([f for f in findings if f.kind == "caller"]) == 1


def test_model_dump_escape_propagates_param_taint(lint_source):
    # A helper that constructs a model from a ``Set`` parameter and dumps it into
    # a databag exposes that parameter as a sink (high, Set annotation).
    findings = lint_source(
        """
        from typing import Set

        class Charm:
            def publish(self, relation, data: Set[str]):
                bag = relation.data[self.app]
                ProviderApplicationData(certificates=data).dump(bag, True)
        """
    )
    sinks = [f for f in findings if f.kind == "sink"]
    assert len(sinks) == 1
    assert sinks[0].confidence == "high"


def test_databag_passed_to_reader_is_not_a_sink(lint_source):
    # ``acc.extend(relation.data[app])`` *reads* the bag into a list; the bag is
    # the source, not a write destination, so it must not be flagged.
    findings = lint_source(
        """
        class Charm:
            def collect(self, relation):
                acc = []
                acc.extend(relation.data[self.app])
                return acc
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


# -- ops Relation.save / Relation.load ----------------------------------------


def test_relation_save_of_unordered_field_is_a_sink(lint_source):
    # ``relation.save(Model(field=<unordered>), entity)`` -- the ops typed-databag
    # API serialises the model's fields into ``relation.data[entity]``, so an
    # unordered field value is a relation-data write that flaps the databag.
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation):
                relation.save(TracingRequirerData(receivers=set(self._units)), self.app)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].sink == "databag"
    assert callers[0].rule == "unordered-collection"


def test_relation_save_of_var_model_is_a_sink(lint_source):
    # A model bound to a local first, then saved, carries its field taint.
    findings = lint_source(
        """
        class Charm:
            def publish(self, event):
                data = TracingRequirerData(receivers={"a", "b"})
                event.relation.save(data, self.unit)
        """
    )
    assert len([f for f in findings if f.kind == "caller"]) == 1


def test_relation_save_of_sorted_content_is_silent(lint_source):
    # Stable (sorted) field content writes deterministic databag data.
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation):
                relation.save(TracingRequirerData(receivers=sorted(self._units)), self.app)
        """
    )
    assert findings == []


def test_relation_save_propagates_param_taint(lint_source):
    # A helper that saves a model built from a ``Set`` parameter exposes that
    # parameter as a sink, matching the ``.update``/``.dump`` idioms.
    findings = lint_source(
        """
        from typing import Set

        class Charm:
            def publish(self, relation, values: Set[str]):
                relation.save(TracingRequirerData(receivers=values), self.app)
        """
    )
    sinks = [f for f in findings if f.kind == "sink"]
    assert len(sinks) == 1
    assert sinks[0].confidence == "high"  # Set annotation -> high


def test_relation_load_roundtrip_is_silent(lint_source):
    # ``relation.load`` is a stable read (deserialises sorted databag data); a
    # model loaded and re-saved unchanged introduces no instability.
    findings = lint_source(
        """
        class Charm:
            def publish(self, event):
                loaded = event.relation.load(TracingRequirerData, event.app)
                event.relation.save(loaded, self.app)
        """
    )
    assert findings == []


def test_non_relation_save_is_not_a_sink(lint_source):
    # ``.save`` whose second argument is not an entity (``.app``/``.unit``) is an
    # unrelated method, not the ops ``Relation.save`` API.
    findings = lint_source(
        """
        class Charm:
            def persist(self, store):
                store.save(set(self._units), commit=True)
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


# -- config / file write sinks ------------------------------------------------


def test_container_push_of_unordered_is_a_config_sink(lint_source):
    # An unordered value rendered into a container push flaps the workload
    # config -> spurious pebble replan / restart.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self, container, names):
                config = "\\n".join(set(names))
                container.push("/etc/app.conf", config)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].confidence == "high"
    assert callers[0].sink == "config"


def test_pebble_add_layer_with_unordered_value_is_a_config_sink(lint_source):
    findings = lint_source(
        """
        class Charm:
            def reconcile(self, container, units):
                layer = {"services": {"app": {"command": " ".join(set(units))}}}
                container.add_layer("app", layer)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].confidence == "high"


def test_path_write_text_of_unordered_is_a_config_sink(lint_source):
    findings = lint_source(
        """
        from pathlib import Path

        class Charm:
            def reconcile(self, paths):
                Path("/etc/app.conf").write_text(str(set(paths)))
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1


def test_write_text_via_source_kwarg_is_a_config_sink(lint_source):
    findings = lint_source(
        """
        class Charm:
            def reconcile(self, container, names):
                container.push("/etc/app.conf", source=str(set(names)))
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1


def test_config_write_of_sorted_value_is_not_a_sink(lint_source):
    # Sorting the unordered value before rendering removes the instability.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self, container, names):
                container.push("/etc/app.conf", "\\n".join(sorted(set(names))))
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_volatile_value_in_config_write_is_high(lint_source):
    findings = lint_source(
        """
        import uuid

        class Charm:
            def reconcile(self, container):
                container.push("/etc/app.conf", str(uuid.uuid4()))
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].confidence == "high"
    assert callers[0].rule == "nondeterministic"


def test_fixed_index_pick_of_unordered_reaches_config_sink(lint_source):
    # The mimir "scheduler_addrs[0]" pattern: pick element 0 of an order-unstable
    # list and render it into config -> the chosen address flaps across reconciles.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self, container, units):
                addrs = list(set(units))
                container.push("/etc/app.conf", addrs[0])
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1


def test_dict_key_lookup_is_not_an_unstable_pick(lint_source):
    # Indexing a mapping by a fixed key is order-independent, so it must not be
    # treated like a sequence pick.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self, container):
                d = {"scheduler": "a", "ruler": "b"}
                container.push("/etc/app.conf", d["scheduler"])
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


# --- Phase B: return-render config handoff (the mimir `config()` chain) -------


def test_element_pick_through_return_rendered_yaml_is_a_sink(lint_source):
    # The full mimir shape: a helper picks element 0 of an order-unstable list
    # (`scheduler_addrs[0]`), nests it in a config dict, and the entry point
    # `return yaml.dump(cfg)` hands it to the workload. Key-sorting cannot fix a
    # value-position pick, so the rendered config still flaps across reconciles.
    findings = lint_source(
        """
        class Charm:
            def _frontend(self, units):
                addrs = list(set(units))
                return {"scheduler_address": addrs[0]}

            def config(self, units):
                cfg = {"frontend": self._frontend(units)}
                return yaml.dump(cfg)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].confidence == "high"
    # The finding must point at the *pick* (`addrs[0]` on the `_frontend` return,
    # line 5) -- not the blameless `yaml.dump` on line 9.
    assert callers[0].line == 5
    # ...and the structured fields name the pick (rule + offending collection),
    # not the serializer.
    assert callers[0].rule == "unordered-pick"
    assert callers[0].variable == "addrs"


def test_volatile_through_return_rendered_yaml_is_a_sink(lint_source):
    # A nondeterministic value survives key-sorting too, so a rendered-config
    # return that embeds one churns the workload on every reconcile.
    findings = lint_source(
        """
        import uuid

        class Charm:
            def config(self):
                return yaml.dump({"id": str(uuid.uuid4())})
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].confidence == "high"
    assert callers[0].rule == "nondeterministic"


def test_sorted_pick_in_return_rendered_yaml_is_not_a_sink(lint_source):
    # Sorting the collection before the pick makes element 0 deterministic, so
    # the rendered config is stable -- no finding.
    findings = lint_source(
        """
        class Charm:
            def config(self, units):
                addrs = sorted(set(units))
                return yaml.dump({"scheduler_address": addrs[0]})
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_local_key_order_is_laundered_by_default_yaml_dump(lint_source):
    # A dict whose only instability is key-insertion order (built by iterating an
    # unordered `rel.units`) is laundered by `yaml.dump`'s default key-sorting,
    # so returning it is benign -- this is exactly why ``local`` must NOT survive
    # a key-sorting serializer.
    findings = lint_source(
        """
        class Charm:
            def config(self, rel):
                cfg = {}
                for u in rel.units:
                    cfg[u.name] = 1
                return yaml.dump(cfg)
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_local_key_order_with_sort_keys_false_is_a_sink(lint_source):
    # Disabling key-sorting preserves the unstable insertion order, so the same
    # dict now flaps the rendered config.
    findings = lint_source(
        """
        class Charm:
            def config(self, rel):
                cfg = {}
                for u in rel.units:
                    cfg[u.name] = 1
                return yaml.dump(cfg, sort_keys=False)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1


def test_chained_items_on_unordered_helper_reaches_sink(lint_source):
    # The grafana_source shape: a helper returns a dict built from `rel.units`
    # (so its iteration order is unstable), and the caller loops over
    # ``helper().items()`` to accumulate a list. Taint must flow through the
    # method receiver that is itself a call.
    findings = lint_source(
        """
        class Charm:
            def _hosts(self, rel):
                h = {}
                for u in rel.units:
                    h[u.name] = 1
                return h

            def reconcile(self, rel, container):
                data = []
                for name, addr in self._hosts(rel).items():
                    data.append(name)
                container.push("/etc/app.conf", data)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1


def test_subscript_receiver_accumulator_returns_unordered(lint_source):
    # The `gather_addresses_by_role` shape: a dict-of-sets built by
    # ``data[key].add(v)`` inside a loop over an unordered collection. The
    # mutation through a subscript receiver must taint the root accumulator.
    findings = lint_source(
        """
        class Charm:
            def _gather(self, rels):
                data = {}
                for rel in rels:
                    for u in rel.units:
                        data[rel.id].add(u.name)
                return data

            def reconcile(self, rels, container):
                container.push("/etc/app.conf", str(self._gather(rels)))
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1



