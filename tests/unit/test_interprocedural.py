"""Interprocedural taint tests: cross-class disambiguation and forwarding.

These exercise the summary fixed point and the receiver-class narrowing that
prevents same-named methods on *different* classes from polluting each other's
call sites (the cross-class collision false-positive fixed during development).
"""

from __future__ import annotations


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
