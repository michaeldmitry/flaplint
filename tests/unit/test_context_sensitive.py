"""Context-sensitive re-analysis of inherited methods (the self-pass mixin).

A method is analyzed in its *defining* class, but inherited methods execute with
``self`` bound to the concrete subclass. When a subclass refines an instance
attribute's type via a constructor *self-pass* -- ``class DataPeer(DataPeerData,
DataPeerEventHandlers)`` wiring ``DataPeerEventHandlers.__init__(self, charm, self,
...)`` so ``self.relation_data`` *is* the ``DataPeerData`` (which overrides a property
to be unordered) -- analyzing only in the base class misses the flap. These tests pin
the fact-driven refinement + re-analysis, and its deliberate boundaries.
"""

from __future__ import annotations

_HDR = """
import json
def set_encoded_field(relation, member, field: str, value: list):
    relation.data[member].update({field: json.dumps(value)})
class Data:
    @property
    def secret_fields(self):
        return self._local                      # ordered base
class PeerData(Data):
    @property
    def secret_fields(self):
        return list(set(self._a) | set(self._b))   # unordered override
class Base:
    def __init__(self, rd):
        self.relation_data = rd
"""


def test_inherited_attribute_resolves_across_the_chain(lint_source):
    # Phase 1a: ``self.relation_data`` is typed and stored in a *base* ``__init__`` but
    # read in a subclass method. Resolution must walk the inheritance chain from the
    # subclass to the base, or the type (and thus the flap) is lost.
    findings = lint_source(
        _HDR
        + """
        class TypedBase:
            def __init__(self, rd: "PeerData"):
                self.relation_data = rd
        class Handler(TypedBase):
            def on_created(self, event):
                set_encoded_field(event.relation, self.app, "p", self.relation_data.secret_fields)
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_selfpass_mixin_polymorphic_override_is_caught(lint_source):
    # Phase 1b: the runtime type is fixed by a *self-pass* -- ``Peer`` inherits both the
    # data (``PeerData``) and the handler, and wires the handler's ``relation_data`` to
    # ``self``. Re-analyzing the inherited ``on_created`` with ``self`` bound to ``Peer``
    # resolves ``secret_fields`` to ``PeerData``'s unordered override -> a databag flap.
    findings = lint_source(
        _HDR
        + """
        class Handler(Base):
            def on_created(self, event):
                set_encoded_field(event.relation, self.app, "p", self.relation_data.secret_fields)
        class Peer(PeerData, Handler):
            def __init__(self, charm):
                Handler.__init__(self, self)
        """
    )
    assert any(f.sink == "databag" and f.confidence == "high" for f in findings)


def test_polymorphic_finding_is_labelled_with_subclass_and_scope(lint_source):
    # The finding must explain *why* it reaches the sink: it carries the concrete
    # subclass (``Peer``) and the ``self`` attribute (``relation_data``) that made the
    # flow reachable, and -- since the born value is an anonymous ``list(set|set)``
    # return -- names its enclosing property as the fallback subject instead of
    # ``<anonymous>``.
    findings = lint_source(
        _HDR
        + """
        class Handler(Base):
            def on_created(self, event):
                set_encoded_field(event.relation, self.app, "p", self.relation_data.secret_fields)
        class Peer(PeerData, Handler):
            def __init__(self, charm):
                Handler.__init__(self, self)
        """
    )
    db = [f for f in findings if f.sink == "databag"]
    assert db and any(f.via_subclass == "Peer" and f.via_attr == "relation_data" for f in db)
    # the born site is an anonymous ``list(set|set)`` -> scope names the property.
    poly = next(f for f in db if f.via_subclass == "Peer")
    assert poly.variable == "" and poly.scope == "secret_fields"


def test_delegated_through_self_callee_is_not_flagged(lint_source):
    # Boundary (the Phase-2 seam): if the inherited method delegates through a
    # *self-callee* that reads the refined attribute, that callee's summary was computed
    # context-insensitively (under the base), so re-analysis sees clean. This is a
    # deliberate *miss, not a false positive* -- closing it needs context-sensitive
    # summaries (Phase 2).
    findings = lint_source(
        _HDR
        + """
        class Handler(Base):
            def _fields(self):
                return self.relation_data.secret_fields
            def on_created(self, event):
                set_encoded_field(event.relation, self.app, "p", self._fields())
        class Peer(PeerData, Handler):
            def __init__(self, charm):
                Handler.__init__(self, self)
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_no_self_pass_is_not_refined(lint_source):
    # Safety: without a self-pass the attribute type is *not* refined -- the handler is
    # built with an external object, so there is no fact that it is the overriding
    # subclass. Nothing is flagged (the base type stays clean).
    findings = lint_source(
        _HDR
        + """
        class Handler(Base):
            def on_created(self, event):
                set_encoded_field(event.relation, self.app, "p", self.relation_data.secret_fields)
        class Factory:
            def make(self, x):
                return Handler(x)
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_selfpass_through_super_delegation_chain(lint_source):
    # The self-pass value is threaded through several ``super().__init__`` hops before
    # being stored (the real data_interfaces shape: DataPeer -> DataPeerEventHandlers ->
    # RequirerEventHandlers -> EventHandlers.self.relation_data = relation_data). The
    # forwarding fixpoint must follow it.
    findings = lint_source(
        _HDR
        + """
        class MidHandler(Base):
            def __init__(self, rd):
                super().__init__(rd)
        class Handler(MidHandler):
            def __init__(self, rd):
                super().__init__(rd)
            def on_created(self, event):
                set_encoded_field(event.relation, self.app, "p", self.relation_data.secret_fields)
        class Peer(PeerData, Handler):
            def __init__(self, charm):
                Handler.__init__(self, self)
        """
    )
    assert any(f.sink == "databag" for f in findings)
