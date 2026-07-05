"""Interprocedural taint tests: cross-class disambiguation and forwarding.

These exercise the summary fixed point and the receiver-class narrowing that
prevents same-named methods on *different* classes from polluting each other's
call sites (the cross-class collision false-positive fixed during development).
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from flaplint.analyzer import Analyzer


def test_cross_file_pick_is_reattributed_to_the_consuming_charm(tmp_path: Path):
    # A positional pick (``enumerate`` value target) that materialises in *another*
    # file -- a lib the charm consumes -- but reaches a byte-sink (file write) in the
    # charm's own code must anchor at the *consuming* charm site, with ``origin=``
    # pointing upstream at the pick where ``sorted()`` belongs. This mirrors the
    # itercaller cross-file re-attribution; without it the ``unordered-pick`` finding
    # for the file write would point into the lib the author only consumes.
    lib = tmp_path / "lib"
    src = tmp_path / "src"
    lib.mkdir()
    src.mkdir()
    (lib / "endpoints.py").write_text(
        textwrap.dedent(
            """
            import yaml

            class Endpoints:
                def __init__(self, relation):
                    self._relation = relation

                def render(self):
                    sinks = {}
                    eps = []
                    for unit in self._relation.units:
                        eps.append(self._relation.data[unit]["endpoint"])
                    for idx, ep in enumerate(eps):
                        sinks[f"loki-{idx}"] = ep
                    return yaml.safe_dump({"sinks": sinks})
            """
        )
    )
    (src / "charm.py").write_text(
        textwrap.dedent(
            """
            class Charm:
                def _reconcile(self, path):
                    config = self.endpoints.render()
                    with path.open("w") as f:
                        f.write(config)
            """
        )
    )
    findings = Analyzer([str(src), str(lib)], min_confidence="low").run()
    picks = [f for f in findings if f.rule == "unordered-pick"]
    charm_pick = [f for f in picks if Path(f.path).name == "charm.py"]
    assert charm_pick, "the file-write pick must be re-attributed to charm.py"
    f = charm_pick[0]
    assert f.sink == "file"
    assert Path(f.origin_path).name == "endpoints.py"  # fix site preserved upstream
    assert f.variable == "config"


def test_two_distinct_sources_feeding_one_write_are_both_reported(tmp_path: Path):
    # Two independent unordered sources (two helpers) both flow into the *same*
    # rendered file write. Re-attribution anchors both at that write, so without an
    # origin-aware dedup the second would collapse into the first and be hidden
    # (postgresql: ``get_standby_endpoints`` masked by ``_peer_members_ips`` at the
    # patroni.yaml render). Each needs its own sorted(), so both must surface -- one
    # finding per distinct upstream origin.
    lib = tmp_path / "lib"
    src = tmp_path / "src"
    lib.mkdir()
    src.mkdir()
    (lib / "repl.py").write_text(
        textwrap.dedent(
            """
            class Repl:
                def peers(self):
                    rel = self.model.get_relation("p")
                    return [rel.data[u]["ip"] for u in rel.units]

                def standbys(self) -> list:
                    rel = self.model.get_relation("s")
                    return [rel.data[u].get("addr") for u in rel.units]
            """
        )
    )
    (src / "cluster.py").write_text(
        textwrap.dedent(
            """
            class Cluster:
                def render_file(self, path, content):
                    path.write_text(content)

                def build(self, tmpl, path):
                    rendered = tmpl.render(
                        peers=self.repl.peers(),
                        standbys=self.repl.standbys(),
                    )
                    self.render_file(path, rendered)
            """
        )
    )
    findings = Analyzer([str(src), str(lib)], min_confidence="low").run()
    at_write = [
        f for f in findings
        if Path(f.path).name == "cluster.py" and f.rule == "unordered-iteration"
    ]
    origins = {f.origin_line for f in at_write}
    assert len(at_write) == 2, f"both sources must surface, got {at_write}"
    assert len(origins) == 2, "the two findings must point at distinct upstream origins"


def test_constructor_arg_dumped_by_another_method_is_flagged(lint_source):
    # A stateful class stores a constructor argument (``__init__: self._roles =
    # roles``) and a *different* method dumps it to a sink. Constructing it with an
    # unordered arg (``Prov(frozenset(...))``) must reach that dump: the construction
    # site absorbs the arg's instability onto the class attribute (via ``__init__``'s
    # absorb summary), which the dump method reads back. Was a false negative --
    # constructor calls were not wired to the absorb path that setter calls use.
    findings = lint_source(
        """
        import json

        class Prov:
            def __init__(self, roles):
                self._roles = roles
            def dump(self, rel):
                rel.data[self.app]["r"] = json.dumps(list(self._roles))

        class Charm:
            def __init__(self, rc):
                self.cluster = Prov(frozenset(rc.roles))
            def publish(self):
                self.cluster.dump(self.rel)
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_constructor_arg_returned_by_a_method_is_flagged(lint_source):
    # Companion to the dump case: a method *returns* the stored constructor arg and
    # the caller writes it. Keyword construction (``Prov(roles=frozenset(...))``) maps
    # to the field the same way positional does.
    findings = lint_source(
        """
        import json

        class Prov:
            def __init__(self, roles):
                self._roles = roles
            def get_roles(self):
                return list(self._roles)

        class Charm:
            def __init__(self, rc):
                self.cluster = Prov(frozenset(rc.roles))
            def publish(self):
                self.rel.data[self.app]["r"] = json.dumps(self.cluster.get_roles())
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_constructor_arg_not_touched_by_a_method_stays_clean(lint_source):
    # Field-precision guard: the construction absorbs onto the *specific* attribute,
    # so a method that never reads it (``grant_privkey`` -> an unrelated secret id)
    # does not inherit the arg's instability -- unlike a coarse whole-object taint,
    # which was the ``ClusterProvider(frozenset(roles)).grant_privkey()`` false positive.
    findings = lint_source(
        """
        class Prov:
            def __init__(self, roles):
                self._roles = roles
            def grant_privkey(self, label):
                return "secret-id-string"

        class Charm:
            def __init__(self, rc):
                self.cluster = Prov(frozenset(rc.roles))
            def publish(self):
                self.rel.data[self.app]["k"] = self.cluster.grant_privkey("x")
        """
    )
    assert findings == []


def test_external_typed_receiver_does_not_collide_with_same_named_method(lint_source):
    # ``self._krm = KubernetesResourceManager(...)`` -- an external library class we
    # never see defined. A same-named ``reconcile`` on a *local* class that writes a
    # file must NOT be imported for ``self._krm.reconcile(...)``: a precisely-typed but
    # external receiver resolves to nothing, not the same-name union (the tempo
    # ``cluster_apps -> file`` false positive, where ``krm.reconcile`` collided with a
    # vendored ``Nginx.reconcile`` that pushes a TLS key to a file).
    findings = lint_source(
        """
        class Nginx:
            def reconcile(self, cfg: str):
                self.container.push("/etc/nginx.conf", cfg)  # file sink; cfg annotated so it is not itself a contract finding

        class Manager:
            def __init__(self):
                self._krm = KubernetesResourceManager()       # external class

            def reconcile(self, policies):
                self._krm.reconcile(policies)                 # must not resolve to Nginx.reconcile

        class Charm:
            def go(self):
                m = Manager()
                m.reconcile(set(self.x))
        """
    )
    assert findings == []


def test_return_class_inference_types_a_local_from_its_helper(lint_source):
    # ``mgr = get_manager()`` where ``get_manager() -> Manager``: the local is typed
    # from the helper's return annotation, so ``mgr.reconcile(...)`` resolves on
    # ``Manager`` (clean) instead of the same-name union that also holds a file-writing
    # ``Nginx.reconcile`` -- the second collision behind the tempo false positive.
    findings = lint_source(
        """
        class Nginx:
            def reconcile(self, cfg: str):
                self.container.push("/etc/nginx.conf", cfg)

        class Manager:
            def reconcile(self, policies):
                pass

        def get_manager() -> Manager:
            return Manager()

        class Charm:
            def go(self):
                mgr = get_manager()
                mgr.reconcile(set(self.x))
        """
    )
    assert findings == []


def test_interprocedural_forwarding_via_helper(lint_source):
    # A caller passing a local set into a helper that writes it unsorted should be
    # reported at the call site as a "via" forwarding finding.
    findings = lint_source(
        """
        import json

        class Charm:
            def publish(self, values):
                self.relation.data[self.app]["v"] = json.dumps(values)

            def _on_changed(self, event):
                self.publish({"a", "b", "c"})
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert callers, "expected a forwarding finding at the call site"
    assert any(f.rule == "unordered-collection" for f in callers)


def test_cross_class_same_named_method_does_not_overtaint(lint_source):
    # ``Unstable.render`` returns its argument unsorted; ``Stable.render`` sorts it.
    # A ``self.render(<set>)`` call inside ``Stable`` must consult only
    # ``Stable.render`` -- otherwise ``Unstable.render``'s summary would leak in
    # and wrongly flag the (actually-sorted) value.
    findings = lint_source(
        """
        import json

        class Unstable:
            def render(self, data):
                return data

            def go(self):
                self.relation.data[self.app]["x"] = json.dumps(self.render({"a", "b"}))

        class Stable:
            def render(self, data):
                return sorted(data)

            def go(self):
                self.relation.data[self.app]["y"] = json.dumps(self.render({"a", "b"}))
        """
    )
    # Exactly one caller finding, belonging to Unstable.go (the only site that
    # actually serializes an unsorted value); Stable.go must not be flagged.
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1, f"expected exactly 1 caller finding, got {callers}"


def test_returns_unordered_propagates_to_caller(lint_source):
    findings = lint_source(
        """
        import json

        class Charm:
            def _collect(self):
                return {"a", "b", "c"}

            def _on_changed(self, event):
                data = self._collect()
                self.relation.data[self.app]["v"] = json.dumps(data)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].confidence == "high"


# --- cross-object member resolution (n-hop receiver chains) --------------------
# A collaborator object reached through a typed member chain -- the charm idiom
# where a manager holds a ``self.charm`` back-reference and the charm holds the
# manager. Resolving the chain lets a call like
# ``self.charm.async_replication.get_addrs()`` consult the callee's summary.


def test_annotated_back_reference_types_a_member(lint_source):
    # ``self.charm = charm`` where ``charm: TheCharm`` types the attribute from the
    # parameter annotation, so ``self.charm.<set-property>`` resolves cross-object.
    findings = lint_source(
        """
        class Charm:
            @property
            def peer_ips(self) -> set:
                return self._opaque()

        class Replication:
            def __init__(self, charm: "Charm"):
                self.charm = charm

            def go(self):
                self.relation.data[self.app]["v"] = ",".join(self.charm.peer_ips)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].confidence == "high"


def test_two_hop_cross_object_chain_resolves(lint_source):
    # ``self.charm.repl.partner_addrs()`` -- two member hops, both typed (a
    # constructor collaborator and an annotated back-reference) -- resolves to the
    # callee's summary, so its unordered return is traced to the databag write.
    findings = lint_source(
        """
        class Charm:
            def __init__(self):
                self.repl = Replication(self)

            @property
            def peer_ips(self) -> set:
                return self._opaque()

        class Replication:
            def __init__(self, charm: "Charm"):
                self.charm = charm

            def partner_addrs(self):
                return list(self.charm.peer_ips)

        class Cluster:
            def __init__(self, charm: "Charm"):
                self.charm = charm

            def render(self):
                self.relation.data[self.app]["v"] = ",".join(
                    self.charm.repl.partner_addrs()
                )
        """
    )
    assert [f for f in findings if f.kind == "caller"]


def test_unannotated_back_reference_stays_unresolved(lint_source):
    # Without an annotation, ``self.charm``'s class is unknown (a bare parameter),
    # so a cross-object property read off it cannot resolve -- the documented limit.
    findings = lint_source(
        """
        class Charm:
            @property
            def peer_ips(self) -> set:
                return self._opaque()

        class Cluster:
            def __init__(self, charm):          # no annotation
                self.charm = charm

            def render(self):
                self.relation.data[self.app]["v"] = ",".join(self.charm.peer_ips)
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_property_returning_itercaller_taints_reader(lint_source):
    # A property whose body materialises a set into a list (``[dict(t) for t in
    # {...}]`` dedup) returns an ``itercaller``. Reading it must surface that -- not
    # only the ``returns_unordered`` (set) case -- so a reader that serialises it flaps.
    findings = lint_source(
        """
        import json

        class Consumer:
            @property
            def endpoints(self):
                return [dict(t) for t in {tuple(d.items()) for d in self._raw()}]

        class Charm:
            def publish(self):
                consumer = Consumer()
                self.relation.data[self.app]["v"] = json.dumps(consumer.endpoints)
        """
    )
    callers = [f for f in findings if f.kind == "caller"]
    assert len(callers) == 1
    assert callers[0].rule == "unordered-iteration"


# --- tuple unpacking distributes taint per position -----------------------------
# ``rw, ro, _ = self.get_cluster_endpoints(...)`` -- a helper that returns several
# ``",".join(set)`` strings, unpacked and written to a databag. Each name must get
# *its own* position's taint: an unstable slot flags, a stable sibling stays clean
# (``cert, key = ...`` -- the key must not inherit the cert's instability).


def test_tuple_unpack_flags_each_unstable_position(lint_source):
    findings = lint_source(
        """
        class Charm:
            def _endpoints(self):
                rw = set()
                ro = set()
                for u in self.model.get_relation("p").units:
                    rw.add(str(u))
                    ro.add(str(u))
                return ",".join(rw), ",".join(ro)

            def go(self):
                rw, ro = self._endpoints()
                self.relation.data[self.app]["rw"] = rw
                self.relation.data[self.app]["ro"] = ro
        """
    )
    dbs = [f for f in findings if f.sink == "databag"]
    assert len(dbs) == 2
    assert all(f.rule == "unordered-iteration" for f in dbs)


def test_tuple_unpack_keeps_stable_position_clean(lint_source):
    # The ``cert, key = get_assigned_certificate()`` shape: position 0 is unstable
    # (a set-joined string), position 1 is a stable value -- only the first flags.
    findings = lint_source(
        """
        class Charm:
            def _cert(self):
                san = set()
                for u in self.model.get_relation("p").units:
                    san.add(str(u))
                return ",".join(san), "stable-key"

            def go(self):
                cert, key = self._cert()
                self.relation.data[self.app]["c"] = cert
                self.relation.data[self.app]["k"] = key
        """
    )
    dbs = [f for f in findings if f.sink == "databag"]
    assert len(dbs) == 1
    assert dbs[0].variable == "cert" or dbs[0].line  # the cert position, not key


def test_tuple_literal_unpack_is_element_wise(lint_source):
    # ``a, b = json.dumps(set), sorted(x)`` -- unpacked from a literal, so ``b``
    # (sorted) stays clean while ``a`` flaps.
    findings = lint_source(
        """
        import json

        class Charm:
            def go(self):
                a, b = json.dumps([v for v in self.model.get_relation("p").units]), sorted(self.x)
                self.relation.data[self.app]["a"] = a
                self.relation.data[self.app]["b"] = b
        """
    )
    dbs = [f for f in findings if f.sink == "databag"]
    assert len(dbs) == 1


def test_starred_unpack_does_not_smear_taint(lint_source):
    # A starred target has no fixed positions, so no per-position summary applies --
    # the conservative path must not smear the whole taint onto ``rest`` (no FP).
    findings = lint_source(
        """
        class Charm:
            def _pair(self):
                s = set()
                for u in self.model.get_relation("p").units:
                    s.add(str(u))
                return "stable", list(s)

            def go(self):
                first, *rest = self._pair()
                self.relation.data[self.app]["v"] = first
        """
    )
    assert [f for f in findings if f.sink == "databag"] == []


def test_cross_object_builder_absorb_surfaces_at_render(lint_source):
    # The config-builder chain: a setter (``add_component``) stores an unstable value
    # into the *callee* builder's own state (``self._config[...] = config``), and a
    # later state-returning method (``build() -> yaml.safe_dump(self._config)``) on the
    # same collaborator surfaces it. An unstable value born in the manager object and
    # committed to ``self.config`` must reach the file the builder renders to.
    findings = lint_source(
        """
        import yaml

        class ConfigBuilder:
            def __init__(self):
                self._config = {"exporters": {}}
            def add_component(self, comp, name, config):
                self._config[comp][name] = config
            def build(self):
                return yaml.safe_dump(self._config)

        class ConfigManager:
            def __init__(self):
                self.config = ConfigBuilder()
            def add_forwarding(self):
                for idx, endpoint in enumerate(set(self.rel.units)):
                    self.config.add_component("exporters", f"loki/{idx}", {"e": endpoint})
            def render(self, path):
                path.write_text(self.config.build())
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_builder_absorb_of_stable_value_is_clean(lint_source):
    # FP guard: a builder fed only a stable (ordered) value must not flag -- the absorb
    # carries the argument's *own* taint, nothing more.
    findings = lint_source(
        """
        import yaml

        class ConfigBuilder:
            def __init__(self):
                self._config = {}
            def add_component(self, name, config):
                self._config[name] = config
            def build(self):
                return yaml.safe_dump(self._config)

        class ConfigManager:
            def __init__(self):
                self.config = ConfigBuilder()
            def add_forwarding(self, host):
                self.config.add_component("a", {"endpoint": host})
            def render(self, path):
                path.write_text(self.config.build())
        """
    )
    assert findings == []


def test_builder_param_boundary_flags_unstable_caller(lint_source):
    # The full loki-forwarding shape: a helper enumerates a *parameter* into a config
    # component whose key binds to the position (``loki/{idx}``) and whose value is a
    # field of the picked element (``endpoint["url"]``), absorbed into a builder that
    # renders to a file. The parameter is a contract-boundary file sink, so a caller
    # passing a concrete-unstable value (a set) is flagged -- even though the helper's
    # own annotation would call the list ordered.
    findings = lint_source(
        """
        import yaml

        class ConfigBuilder:
            def __init__(self):
                self._config = {"exporters": {}}
            def add_component(self, comp, name, config):
                self._config[comp][name] = config
            def build(self):
                return yaml.safe_dump(self._config)

        class ConfigManager:
            def __init__(self):
                self.config = ConfigBuilder()
            def add_log_forwarding(self, endpoints):
                for idx, endpoint in enumerate(endpoints):
                    self.config.add_component("exporters", f"loki/{idx}", {"e": endpoint["url"]})
            def render(self, path):
                path.write_text(self.config.build())

        class Charm:
            def reconcile(self, path):
                cm = ConfigManager()
                cm.add_log_forwarding(set(self.rel.units))
                cm.render(path)
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_inherited_property_resolves_on_subclass_receiver(lint_source):
    # A property defined on a *base* class (``ConsumerBase.endpoints``) resolves when
    # read off a subclass instance (``LokiConsumer().endpoints``) -- the
    # ``loki_consumer.loki_endpoints`` idiom where the property lives on the base.
    findings = lint_source(
        """
        import json

        class ConsumerBase:
            @property
            def endpoints(self):
                out = []
                for u in self.rel.units:
                    out.append(str(u))
                return out

        class LokiConsumer(ConsumerBase):
            pass

        class Charm:
            def publish(self, relation):
                c = LokiConsumer()
                relation.data[self.app]["v"] = json.dumps(c.endpoints)
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_builder_absorb_of_wrapped_value_and_direct_attr_assign(lint_source):
    # The absorb is not limited to a bare ``= config``: a param nested in a container
    # literal (``= {"w": cfg}``) or stored by a whole-attr setter (``self._c = data``)
    # still carries its instability into the builder's rendered state.
    findings = lint_source(
        """
        import yaml

        class Builder:
            def __init__(self):
                self._c = {"e": {}}
            def add_component(self, comp, name, cfg):
                self._c[comp][name] = {"wrapped": cfg}     # nested in a literal
            def build(self):
                return yaml.safe_dump(self._c)

        class Manager:
            def __init__(self):
                self.b = Builder()
            def go(self):
                for i, e in enumerate(set(self.rel.units)):
                    self.b.add_component("e", f"k{i}", e)
            def render(self, path):
                path.write_text(self.b.build())
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_builder_setter_that_sorts_is_clean(lint_source):
    # FP guard: a setter that ``sorted()``s the value before storing launders it, so the
    # builder's render is stable -- the absorb must not carry a laundered param. Paired
    # with a second builder of the *same* method names to also pin that a ``self.<member>``
    # call resolves to its own class (no cross-contamination between two builders).
    findings = lint_source(
        """
        import yaml

        class SortingBuilder:
            def __init__(self):
                self._c = {"e": {}}
            def add_component(self, comp, name, items):
                self._c[comp][name] = sorted(items)        # laundered
            def build(self):
                return yaml.safe_dump(self._c)

        class WrapBuilder:
            def __init__(self):
                self._c = {"e": {}}
            def add_component(self, comp, name, cfg):
                self._c[comp][name] = {"w": cfg}
            def build(self):
                return yaml.safe_dump(self._c)

        class Manager:
            def __init__(self):
                self.b = SortingBuilder()
            def go(self):
                for i, e in enumerate(set(self.rel.units)):
                    self.b.add_component("e", f"k{i}", e)
            def render(self, path):
                path.write_text(self.b.build())
        """
    )
    assert findings == []


def test_builder_render_via_intermediate_variable(lint_source):
    # The render-write need not be inline: ``rendered = builder.build(); push(path,
    # rendered)`` is recognised via the local that holds the render call's result, so a
    # param absorbed into the builder is still a (file) contract sink.
    findings = lint_source(
        """
        import yaml

        class ConfigBuilder:
            def __init__(self):
                self._config = {"e": {}}
            def add_component(self, comp, name, config):
                self._config[comp][name] = config
            def build(self):
                return yaml.safe_dump(self._config)

        class Manager:
            def __init__(self):
                self.config = ConfigBuilder()
            def add_forwarding(self, endpoints):
                for idx, ep in enumerate(endpoints):
                    self.config.add_component("e", f"k{idx}", {"u": ep["url"]})
            def render(self, container):
                rendered = self.config.build()
                container.push("/etc/otel.yaml", rendered, make_dirs=True)

        class Charm:
            def reconcile(self, container):
                m = Manager()
                m.add_forwarding(set(self.rel.units))
                m.render(container)
        """
    )
    assert any(f.sink == "file" for f in findings)


def test_local_builder_setter_that_sorts_is_clean(lint_source):
    # FP guard for a *locally-constructed* builder (``b = Builder()``), not a
    # ``self.<member>`` one: the blanket local-mutation absorb used to taint ``b``
    # from any unstable argument regardless of what the setter did with it. When the
    # setter launders (``self._c[k] = sorted(v)``), the concrete class's ``absorbs``
    # summary omits that param, so ``b`` stays clean and ``b.build()`` is stable.
    findings = lint_source(
        """
        import yaml

        class SortingBuilder:
            def __init__(self):
                self._c = {}
            def add(self, k, v):
                self._c[k] = sorted(v)
            def build(self):
                return yaml.safe_dump(self._c)

        class Charm:
            def reconcile(self, container):
                b = SortingBuilder()
                b.add("k", set(self.rel.units))
                container.push("/f", b.build())
        """
    )
    assert findings == []


def test_local_builder_absorbing_setter_still_flags(lint_source):
    # Recall guard paired with the FP guard above: a locally-constructed builder whose
    # setter *stores* the param unlaundered (``self._c[k] = v``) must still carry the
    # instability into ``b.build()`` -- the concrete-class summary marks the param
    # absorbed, so the blanket handler contributes it.
    findings = lint_source(
        """
        import yaml

        class KeepBuilder:
            def __init__(self):
                self._c = {}
            def add(self, k, v):
                self._c[k] = v
            def build(self):
                return yaml.safe_dump(self._c)

        class Charm:
            def reconcile(self, container):
                b = KeepBuilder()
                b.add("k", list(set(self.rel.units)))
                container.push("/f", b.build())
        """
    )
    assert findings
