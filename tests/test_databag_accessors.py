"""Databag-accessor properties: a write through ``self.<property>`` is a sink.

Charms commonly expose a relation databag via a property
(``@property def unit_databag(self): return self.peers.data[self.unit]``) and write
to it as ``self.unit_databag.update(...)``. The accessor is recognized (its body
returns ``relation.data[entity]`` / ``.data.get(entity)``), so those writes count.
"""

from __future__ import annotations


def test_update_through_databag_property_is_a_sink(lint_source):
    findings = lint_source(
        """
        class Charm:
            @property
            def unit_databag(self):
                return self.peer_relation.data[self.unit]

            def h(self, values):
                self.unit_databag.update({v for v in values})
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_item_assign_through_data_get_accessor_is_a_sink(lint_source):
    # `.data.get(entity)` is recognized like `.data[entity]`.
    findings = lint_source(
        """
        from datetime import datetime

        class Charm:
            @property
            def app_databag(self):
                return self._peers.data.get(self.app, {})

            def h(self):
                self.app_databag["ts"] = str(datetime.now())
        """
    )
    assert any(f.rule == "nondeterministic" and f.sink == "databag" for f in findings)


def test_chained_accessor_is_recognized(lint_source):
    # unit_data -> _peer_data -> relation.data[entity]; the chain must resolve.
    findings = lint_source(
        """
        class Charm:
            def _peer_data(self, entity):
                return self.model.get_relation("peer").data[entity]

            @property
            def unit_data(self):
                return self._peer_data(self.unit)

            def h(self, values):
                self.unit_data.update({v for v in values})
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_local_aliased_to_accessor_is_a_sink(lint_source):
    findings = lint_source(
        """
        class Charm:
            @property
            def unit_databag(self):
                return self.peers.data[self.unit]

            def h(self, values):
                bag = self.unit_databag
                bag.update({v for v in values})
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_bare_data_property_is_not_a_databag(lint_source):
    # A property returning a bare ``.data`` attribute (no [entity]) must NOT be
    # treated as a databag -- ``.data`` is too generic. This is the safety boundary
    # (and why postgresql's ``all_peer_data`` chain is deliberately not caught).
    findings = lint_source(
        """
        class Charm:
            @property
            def client_data(self):
                return self._http_client.data

            def h(self, values):
                self.client_data.update({v for v in values})
        """
    )
    assert [f for f in findings if f.sink == "databag"] == []
