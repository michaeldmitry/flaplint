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


def test_shake_hash_of_unordered_is_flagged(lint_source):
    # ``shake_128``/``shake_256`` are hashlib hashes too -- an unstable value hashed
    # with one still flaps the change-gate (the postgresql generate_user_hash shape).
    findings = lint_source(
        """
        from hashlib import shake_128

        class Charm:
            def _user_hash(self, names):
                return shake_128(str(set(names)).encode()).hexdigest(16)
        """
    )
    hashes = [f for f in findings if f.sink == "hash"]
    assert len(hashes) == 1
    assert hashes[0].confidence == "high"


def test_hash_finding_names_the_collection_not_the_wrapper(lint_source):
    # ``sha256(str(peers).encode())`` -- the offending identifier is ``peers``,
    # the set being hashed, NOT the ``str`` serializer wrapper nor the ``.encode``
    # method. The encode/decode pass-through must be peeled to its receiver.
    findings = lint_source(
        """
        import hashlib

        class Charm:
            def _hash(self):
                peers = {u.name for u in self.units}
                return hashlib.sha256(str(peers).encode()).hexdigest()
        """
    )
    hashes = [f for f in findings if f.sink == "hash"]
    assert len(hashes) == 1
    assert hashes[0].variable == "peers"


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


def test_builtin_hash_of_json_dumps_is_salted_even_when_sorted(lint_source):
    # ``hash(json.dumps(x, sort_keys=True))`` -- the content is stable, but the
    # *builtin* hash() is PYTHONHASHSEED-salted for str content, so it returns a
    # different int every process (every Juju hook). A persisted-and-compared hash
    # then flaps regardless of sorting: flag it as nondeterministic.
    findings = lint_source(
        """
        import json

        class Charm:
            def _config_hash(self):
                return hash(json.dumps(self._get_certs(), sort_keys=True))
        """
    )
    hashes = [f for f in findings if f.sink == "hash"]
    assert len(hashes) == 1
    assert hashes[0].rule == "nondeterministic"
    assert hashes[0].confidence == "high"
    # The finding is about the hash *call*, not a single content variable.
    assert hashes[0].variable == "hash()"


def test_builtin_hash_of_tuple_containing_a_string_is_salted(lint_source):
    # The traefik ``_config_hash`` shape: a tuple mixing attributes with a
    # ``json.dumps(...)`` -- the string element makes the whole hash salted.
    findings = lint_source(
        """
        import json

        class Charm:
            def _config_hash(self):
                return hash((self._addr, self.config["mode"], json.dumps(self._certs())))
        """
    )
    assert any(f.sink == "hash" and f.rule == "nondeterministic" for f in findings)


def test_hashlib_of_sorted_content_is_not_salted(lint_source):
    # hashlib.sha256 is stable across processes, so hashing *sorted* bytes is fine
    # -- the salted-hash rule must apply only to the builtin ``hash()``.
    findings = lint_source(
        """
        import json, hashlib

        class Charm:
            def _config_hash(self):
                blob = json.dumps(self._certs(), sort_keys=True).encode()
                return hashlib.sha256(blob).hexdigest()
        """
    )
    assert [f for f in findings if f.sink == "hash"] == []


def test_builtin_hash_of_non_string_is_not_flagged(lint_source):
    # ``hash((a, b))`` where nothing is provably a string: ints/bytes-unknown are
    # not necessarily salted, so stay conservative and do not flag.
    findings = lint_source(
        """
        class Charm:
            def _config_hash(self):
                return hash((self._port, self._replicas))
        """
    )
    assert [f for f in findings if f.sink == "hash"] == []


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


# -- cross-boundary model dump: built in one method, dumped in another -----------


def test_model_built_in_init_dumped_in_handler_is_a_sink(lint_source):
    # ``self._data = Model(field=<unordered>)`` in __init__, ``self._data.dump(bag)``
    # in a handler -- construction and dump live in different methods. The dump must
    # carry the field taint via instance-attribute provenance (the DatabagModel
    # idiom split build/publish across methods).
    findings = lint_source(
        """
        class Charm:
            def __init__(self):
                self._data = ProviderApplicationData(members=set(self._units))
            def publish(self, relation):
                self._data.dump(relation.data[self.app])
        """
    )
    assert len([f for f in findings if f.kind == "caller" and f.sink == "databag"]) == 1


def test_model_from_builder_method_dumped_is_a_sink(lint_source):
    # ``self._build().dump(bag)`` -- the model is returned by a builder, then dumped.
    # The dump must carry the builder's returned-field taint (returns_field_origins).
    findings = lint_source(
        """
        class Charm:
            def _build(self):
                return ProviderApplicationData(members=set(self._units))
            def publish(self, relation):
                self._build().dump(relation.data[self.app])
        """
    )
    assert len([f for f in findings if f.kind == "caller" and f.sink == "databag"]) == 1


def test_clean_model_built_in_init_dumped_is_not_flagged(lint_source):
    # Monotonicity guard: a *sorted* field built in __init__ and dumped in a handler
    # must stay clean -- the cross-boundary carry must not invent taint.
    findings = lint_source(
        """
        class Charm:
            def __init__(self):
                self._data = ProviderApplicationData(members=sorted(self._units))
            def publish(self, relation):
                self._data.dump(relation.data[self.app])
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_list_receiver_reading_bag_is_not_flagged(lint_source):
    # Field-sensitivity / FP guard: a plain list attribute that *reads* the bag
    # (``self._acc.extend(bag)``) is not a constructed value object, so the gate
    # must not taint it.
    findings = lint_source(
        """
        class Charm:
            def __init__(self):
                self._acc = []
            def publish(self, relation):
                self._acc.extend(relation.data[self.app])
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_optional_scalar_param_is_not_a_sink(lint_source):
    # ``Optional[str]`` is a scalar string -- its serialization is deterministic.
    # The wrapper must be unwrapped to ``str`` (ordered), so dumping it through a
    # model is the caller's concern, not a contract-boundary sink.
    findings = lint_source(
        """
        from typing import Optional

        class Charm:
            def publish(self, relation, server_cert: Optional[str] = None):
                bag = relation.data[self.app]
                ProviderApplicationData(cert=server_cert).dump(bag)
        """
    )
    assert [f for f in findings if f.kind == "sink"] == []


def test_optional_mapping_param_is_not_a_sink(lint_source):
    # ``Optional[Dict[str, str]]`` -> ``Dict``: a mapping's only sink-side
    # instability is key order, which every databag serializer fixes. Not a
    # contract-boundary sink.
    findings = lint_source(
        """
        from typing import Dict, Optional

        class Charm:
            def publish(self, relation, labels: Optional[Dict[str, str]] = None):
                bag = relation.data[self.app]
                ProviderApplicationData(labels=labels).dump(bag)
        """
    )
    assert [f for f in findings if f.kind == "sink"] == []


def test_optional_set_param_is_still_a_high_sink(lint_source):
    # ``Optional[Set[str]]`` -> ``Set``: the wrapper is transparent, the payload
    # is genuinely unordered, so the high-confidence sink survives unwrapping.
    findings = lint_source(
        """
        from typing import Optional, Set

        class Charm:
            def publish(self, relation, data: Optional[Set[str]] = None):
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
    assert callers[0].sink == "file"


def test_pebble_add_layer_unordered_command_is_a_plan_sink(lint_source):
    # A ``command`` string built by joining an unordered set flaps the pebble plan:
    # pebble compares the command (a string) by value, so a reshuffled command means
    # a "changed" service and a spurious restart on replan(). This is the single most
    # common real pebble flap, and it must survive pebble's structural plan compare.
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
    assert callers[0].sink == "plan"


def test_pebble_add_layer_bare_set_in_mapping_field_is_laundered(lint_source):
    # Pebble compares plans *structurally*, not byte-for-byte: mapping fields
    # (``environment``, ...) are order-insensitive, so a bare set / dict-key-order
    # whose only instability is key order is laundered by the daemon exactly as a
    # key-sorting serializer would. It must NOT be flagged at the plan sink (that
    # would be the over-report a plain byte-diffed file sink produces).
    findings = lint_source(
        """
        class Charm:
            def reconcile(self, container, names):
                layer = {"services": {"app": {"environment": set(names)}}}
                container.add_layer("app", layer)
        """
    )
    assert [f for f in findings if f.sink == "plan"] == []


def test_pebble_add_layer_volatile_value_is_a_plan_sink(lint_source):
    # A nondeterministic value in a layer regenerates every reconcile -> the plan
    # differs every time -> a restart on every replan(). Survives structural compare.
    findings = lint_source(
        """
        import uuid

        class Charm:
            def reconcile(self, container):
                layer = {"services": {"app": {"environment": {"ID": str(uuid.uuid4())}}}}
                container.add_layer("app", layer)
        """
    )
    callers = [f for f in findings if f.kind == "caller" and f.sink == "plan"]
    assert len(callers) == 1
    assert callers[0].rule == "nondeterministic"


def test_secret_set_content_of_unordered_is_a_secret_sink(lint_source):
    # ``secret.set_content({..: json.dumps(<unordered>)})`` -- Juju creates a new
    # revision when the content differs, firing secret-changed on every observer.
    findings = lint_source(
        """
        import json

        class Charm:
            def _publish(self):
                d = {}
                for u in self.rel.units:
                    d[u.name] = 1
                secret = self.model.get_secret(label="x")
                secret.set_content({"keys": json.dumps(d)})
        """
    )
    secrets = [f for f in findings if f.sink == "secret"]
    assert len(secrets) == 1
    assert secrets[0].confidence == "high"


def test_add_secret_of_sorted_content_is_silent(lint_source):
    # Sorted before serialising -> stable secret content -> no revision churn.
    findings = lint_source(
        """
        import json

        class Charm:
            def _publish(self):
                names = sorted(self._names())
                self.app.add_secret({"keys": json.dumps(names)}, label="y")
        """
    )
    assert [f for f in findings if f.sink == "secret"] == []


def test_param_reaching_both_databag_and_secret_yields_both(lint_source):
    # The traefik shape: a helper writes its parameter into *both* a databag and a
    # secret. A caller passing an unstable value must get one finding per store --
    # each is a distinct churn source (relation-changed vs secret-changed).
    findings = lint_source(
        """
        import json

        class Charm:
            def _publish(self, certs):
                pub = {h: v for h, v in certs.items()}
                self.model.get_relation("peers").data[self.app]["c"] = json.dumps(pub)
                self.model.get_secret(label="s").set_content({"k": json.dumps(pub)})
            def _sync(self):
                certs = {}
                for u in self.rel.units:
                    certs[u.name] = 1
                self._publish(certs)
        """
    )
    sinks = {f.sink for f in findings if f.kind == "caller"}
    assert "databag" in sinks
    assert "secret" in sinks


# -- Set-typed attribute inference (generic, no hardcoded class/attr names) ------


def test_set_attribute_via_init_param_reads_as_unordered(lint_source):
    # ``event.certs`` where the class stores a ``Set``-annotated __init__ param on
    # self -- joining it into a file bakes set order into bytes. The class name is
    # arbitrary: resolution is by the receiver's declared type, not a name match.
    findings = lint_source(
        """
        from pathlib import Path
        from typing import Set

        class WidgetEvent:
            def __init__(self, handle, certs: Set[str], n: int):
                self.certs = certs
                self.n = n

        class Charm:
            def _on_event(self, event: WidgetEvent):
                Path("/etc/ca.crt").write_text("\\n".join(event.certs))
        """
    )
    files = [f for f in findings if f.sink == "file"]
    assert len(files) == 1
    assert files[0].variable == "event.certs"


def test_set_attribute_via_class_body_annotation_reads_as_unordered(lint_source):
    # The class-body ``hosts: Set[str]`` shape (dataclass / pydantic), likewise
    # resolved by declared type.
    findings = lint_source(
        """
        from pathlib import Path
        from typing import Set

        class Config:
            hosts: Set[str]

        class Charm:
            def render(self, cfg: Config):
                Path("/etc/app.conf").write_text(",".join(cfg.hosts))
        """
    )
    assert any(f.sink == "file" and f.variable == "cfg.hosts" for f in findings)


def test_non_set_attribute_is_not_flagged(lint_source):
    # A ``list``-typed attribute is caller-ordered, not unordered -- no false finding.
    findings = lint_source(
        """
        from pathlib import Path
        from typing import List

        class Ev:
            def __init__(self, items: List[str]):
                self.items = items

        class Charm:
            def _on(self, event: Ev):
                Path("/etc/app.conf").write_text("\\n".join(event.items))
        """
    )
    assert [f for f in findings if f.sink == "file"] == []


def test_set_attribute_on_untyped_receiver_is_not_flagged(lint_source):
    # Without a declared type for the receiver, flaplint can't know the attribute is
    # a set -- it stays conservative (no finding), exactly the pre-inference behaviour.
    findings = lint_source(
        """
        from pathlib import Path

        class Charm:
            def _on(self, event):
                Path("/etc/app.conf").write_text("\\n".join(event.certs))
        """
    )
    assert [f for f in findings if f.sink == "file"] == []


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


def test_file_handle_write_of_unordered_is_a_file_sink(lint_source):
    # ``open(...).write(content)`` -- the open file handle's ``.write`` carries
    # the content as its first positional argument.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self, names):
                with open("/etc/app.conf", "w") as f:
                    f.write(str(set(names)))
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].sink == "file"


def test_file_handle_writelines_of_unordered_is_a_file_sink(lint_source):
    findings = lint_source(
        """
        class Charm:
            def reconcile(self, names):
                with open("/etc/app.conf", "w") as f:
                    f.writelines(set(names))
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].sink == "file"


def test_os_write_of_unordered_is_a_file_sink(lint_source):
    # ``os.write(fd, data)`` -- content is the SECOND positional argument; it must
    # not be confused with a path/handle ``.write(data)`` (content first).
    findings = lint_source(
        """
        import os

        class Charm:
            def reconcile(self, fd, names):
                os.write(fd, str(set(names)).encode())
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].sink == "file"


def test_pathops_write_bytes_of_unordered_is_a_file_sink(lint_source):
    # charmlibs.pathops ContainerPath/LocalPath share write_text/write_bytes with
    # the content as the first positional argument, like pathlib.Path.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self, root, names):
                (root / "app.conf").write_bytes(str(set(names)).encode())
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].sink == "file"


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
    # A ``return yaml.dump(cfg)`` is a config-render boundary, not a proven file
    # write -- flaplint can't see which consumer diffs the blob, so it reports the
    # honest ``render`` family rather than claiming an on-disk file.
    assert callers[0].sink == "render"


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





def test_container_list_files_is_an_unordered_source(lint_source):
    # ops Container.list_files is a directory listing (unspecified order), the
    # workload-container analogue of os.listdir. A config built by iterating it and
    # pushed to a file flaps -- the traefik dynamic-TLS-config shape.
    findings = lint_source(
        """
        import yaml

        class Traefik:
            def update_tls(self):
                cert_files = [f.path for f in self._container.list_files("/certs")]
                config = yaml.safe_dump({"certs": [{"f": c} for c in cert_files]})
                self._container.push("/dynamic.yml", config)
        """
    )
    assert any(f.sink == "file" for f in findings)


# --- file param-contracts (a helper writes a parameter to an on-disk file) -----
# The ``render_file(path, content)`` / ``write_text(content)`` wrapper idiom: a
# helper writes one of its parameters to a config file a workload diffs. Like a
# databag/secret write, this is a contract boundary -- an unordered caller flaps
# the file -- so it folds into the parameter summary (the postgresql render_file
# case), rather than being only a --explain-gaps blind spot.


def test_helper_writing_param_to_file_is_a_contract_sink(lint_source):
    # An unannotated parameter written to a file is a medium contract-boundary sink.
    findings = lint_source(
        """
        class Charm:
            def _write(self, container, data):
                container.push("/etc/app.conf", data)
        """
    )
    sinks = [f for f in findings if f.kind == "sink" and f.sink == "file"]
    assert len(sinks) == 1
    assert sinks[0].confidence == "medium"
    assert sinks[0].variable == "data"


def test_helper_writing_set_annotated_param_to_file_is_high(lint_source):
    # A Set-annotated file-content parameter is a high-confidence contract sink.
    findings = lint_source(
        """
        from typing import Set

        class Charm:
            def _write(self, path, content: Set[str]):
                with open(path, "w") as fh:
                    fh.write("\\n".join(content))
        """
    )
    sinks = [f for f in findings if f.kind == "sink" and f.sink == "file"]
    assert len(sinks) == 1
    assert sinks[0].confidence == "high"


def test_str_annotated_file_content_param_is_not_a_helper_sink(lint_source):
    # A ``content: str`` parameter is the caller's responsibility to keep ordered,
    # so the helper itself is not flagged (mirrors the databag/secret grading).
    findings = lint_source(
        """
        class Charm:
            def render_file(self, path, content: str, mode):
                with open(path, "w") as fh:
                    fh.write(content)
        """
    )
    assert [f for f in findings if f.kind == "sink"] == []


def test_unordered_caller_into_file_wrapper_is_flagged(lint_source):
    # The end-to-end postgresql shape: a caller serialises an unordered collection
    # and hands it to a ``render_file`` wrapper that writes it to disk. Even with a
    # ``content: str`` annotation (no helper-side sink finding), the caller's
    # unstable argument is a confirmed finding pointing at the helper's write.
    findings = lint_source(
        """
        class Charm:
            def render_file(self, path, content: str, mode):
                with open(path, "w") as fh:
                    fh.write(content)

            def reconcile(self):
                self.render_file("/x", ",".join(list({"a", "b"})), 0o600)
        """
    )
    callers = [f for f in findings if f.kind == "caller" and f.sink == "file"]
    assert len(callers) == 1
    assert callers[0].confidence == "high"
    # points the fix at the caller's materialization, and the write at the helper.
    assert callers[0].sink_line  # a distinct downstream write location was recorded


def test_stable_caller_into_file_wrapper_is_not_flagged(lint_source):
    # A caller passing an already-ordered value to the same wrapper is clean -- the
    # contract only fires when the actual argument is demonstrably unstable.
    findings = lint_source(
        """
        class Charm:
            def render_file(self, path, content: str, mode):
                with open(path, "w") as fh:
                    fh.write(content)

            def reconcile(self):
                self.render_file("/x", ",".join(sorted({"a", "b"})), 0o600)
        """
    )
    assert [f for f in findings if f.sink == "file"] == []


def test_plan_param_still_gets_no_contract_sink(lint_source):
    # Only databag/secret/file fold into parameter summaries; a plan write does not
    # (it is structurally compared), so a param written to a plan is not a sink.
    findings = lint_source(
        """
        class Charm:
            def _plan(self, container, layer):
                container.add_layer("l", layer, combine=True)
        """
    )
    assert [f for f in findings if f.kind == "sink" and f.sink == "plan"] == []


# --- return-type inference (a ``-> set`` accessor is trusted as unordered) ------
# A function/property annotated ``-> set[str]`` promises an unordered collection,
# so a caller that materialises/serialises its result without ``sorted()`` flaps --
# even when the body is opaque (a cross-object call). This is the postgresql
# ``_peer_members_ips -> set[str]`` case, generalised to the annotation.


def test_set_returning_property_is_trusted_unordered(lint_source):
    findings = lint_source(
        """
        class Charm:
            @property
            def addrs(self) -> set:
                return self._opaque()

            def reconcile(self):
                self.relation.data[self.app]["v"] = ",".join(self.addrs)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].confidence == "high"


def test_set_returning_method_materialized_to_file_is_flagged(lint_source):
    findings = lint_source(
        """
        class Charm:
            def get_addrs(self) -> set[str]:
                return self._opaque()

            def render_file(self, path, content):
                open(path, "w").write(content)

            def reconcile(self):
                self.render_file("/x", ",".join(self.get_addrs()))
        """
    )
    callers = [f for f in findings if f.kind == "caller" and f.sink == "file"]
    assert len(callers) == 1


def test_frozenset_return_annotation_is_trusted(lint_source):
    findings = lint_source(
        """
        from typing import FrozenSet

        class Charm:
            def names(self) -> FrozenSet[str]:
                return self._opaque()

            def reconcile(self):
                self.relation.data[self.app]["v"] = ",".join(self.names())
        """
    )
    assert [f for f in findings if f.kind == "caller"]


def test_list_return_annotation_is_not_trusted_unordered(lint_source):
    # A ``-> list[str]`` accessor is ordered by contract: an opaque body is trusted
    # to be stable, so no finding (only a genuine set/frozenset return is unordered).
    findings = lint_source(
        """
        class Charm:
            def get_addrs(self) -> list[str]:
                return self._opaque()

            def reconcile(self):
                self.relation.data[self.app]["v"] = ",".join(self.get_addrs())
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_iterable_return_annotation_is_not_trusted_unordered(lint_source):
    # ``-> Iterable`` as a *return* type is usually an ordered generator/view, so it
    # is deliberately excluded from return-type inference (unlike a parameter).
    findings = lint_source(
        """
        from typing import Iterable

        class Charm:
            def get_addrs(self) -> Iterable[str]:
                return self._opaque()

            def reconcile(self):
                self.relation.data[self.app]["v"] = ",".join(self.get_addrs())
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


# --- x509 certificate SAN ordering (set -> DER SEQUENCE -> bytes) --------------
# The classic TLS flap: SubjectAlternativeName is an order-significant DER SEQUENCE,
# so building one from a set bakes the set's hash-seeded order into the CSR/cert
# bytes. A charm passing a sorted/frozenset can't fix it -- the lib re-set()s -- so
# it surfaces as a (usually dependency) finding when flaplint traces the emit.


def test_x509_san_from_set_to_databag_is_flagged(lint_source):
    findings = lint_source(
        """
        from cryptography import x509
        class Charm:
            def publish(self, sans_dns):
                san = x509.SubjectAlternativeName(set(sans_dns))
                self.relation.data[self.app]["san"] = san.public_bytes(0)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].rule == "unordered-iteration"
    assert callers[0].confidence == "high"


def test_x509_csr_builder_chain_to_databag_is_flagged(lint_source):
    # The full v4 tls_certificates shape: a SAN materialised from set(_sans), added
    # to a builder (fluent reassignment), signed, and emitted as PEM to the databag.
    findings = lint_source(
        """
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        class Charm:
            def publish(self, signing_key, sans_dns):
                _sans = []
                _sans.extend([x509.DNSName(san) for san in sans_dns])
                csr_builder = x509.CertificateSigningRequestBuilder()
                csr_builder = csr_builder.add_extension(
                    x509.SubjectAlternativeName(set(_sans)), critical=False
                )
                csr = csr_builder.sign(signing_key, hashes.SHA256())
                self.relation.data[self.app]["csr"] = csr.public_bytes(
                    serialization.Encoding.PEM
                ).decode()
        """
    )
    assert any(f.kind == "caller" and f.rule == "unordered-iteration" for f in findings)


def test_x509_san_written_to_file_is_flagged(lint_source):
    findings = lint_source(
        """
        from cryptography import x509
        class Charm:
            def write(self, path, sans_dns):
                san = x509.SubjectAlternativeName(set(sans_dns))
                with open(path, "wb") as fh:
                    fh.write(san.public_bytes(0))
        """
    )
    assert any(f.sink == "file" and f.rule == "unordered-iteration" for f in findings)


def test_x509_sorted_san_is_not_flagged(lint_source):
    # Sorting the names before building the SAN gives a stable DER SEQUENCE -- the
    # materializer promotion must not fire on an already-ordered source.
    findings = lint_source(
        """
        from cryptography import x509
        class Charm:
            def publish(self, sans_dns):
                san = x509.SubjectAlternativeName(
                    [x509.DNSName(s) for s in sorted(sans_dns)]
                )
                self.relation.data[self.app]["san"] = san.public_bytes(0)
        """
    )
    assert findings == []


def test_public_bytes_of_stable_object_is_not_flagged(lint_source):
    # public_bytes must only propagate genuine instability, not manufacture it: a
    # cert built from ordered inputs stays clean.
    findings = lint_source(
        """
        from cryptography import x509
        class Charm:
            def publish(self, cert):
                self.relation.data[self.app]["c"] = cert.public_bytes(0)
        """
    )
    assert findings == []
