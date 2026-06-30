"""Instance-attribute provenance: taint that survives ``self.<attr>`` across methods.

flaplint tracks taint per local name, so a value parked on ``self`` in one method
(typically ``__init__``) and read back in another used to lose its taint -- the
cross-method instance-attribute barrier. This is the dominant charm idiom (build in
``__init__``, read in a handler), so the miss was a common false negative. These tests
cover the class-level instance-attribute taint that carries an unstable value from a
``self.<attr> = <expr>`` write to a read in a sibling method, while staying
field-sensitive (a clean attribute isn't tainted by a dirty sibling) and respecting a
later ``sorted()`` reassignment.

The two real bugs that motivated it (both previously silent):
* traefik ``self.csrs`` -- a list from a set comprehension, iterated into a dict whose
  key order reaches the peer databag;
* data_platform_libs ``self.upgrade_stack`` -- a list built by iterating the
  ``app_units`` set, ``json.dumps``-ed into the peer databag in another method.
"""

from __future__ import annotations


def test_attr_set_in_init_read_in_method_is_flagged(lint_source):
    # The core idiom: an unstable set parked on self in __init__, read back and joined
    # into a databag in a different method.
    findings = lint_source(
        """
        class Charm:
            def __init__(self):
                self._hosts = set(self.peers)

            def reconcile(self):
                self.relation.data[self.app]["hosts"] = ",".join(self._hosts)
        """
    )
    assert any(f.rule == "unordered-iteration" and f.confidence == "high" for f in findings)


def test_attr_built_by_iterating_a_set_then_written_in_another_method(lint_source):
    # The upgrade_stack shape: a list built by iterating a set into it (unstable element
    # order), stashed on self, json-dumped to a databag in a different method.
    findings = lint_source(
        """
        import json

        class Charm:
            def build(self):
                stack = []
                for unit in set(self.units):
                    stack.append(unit)
                self.stack = stack

            def publish(self):
                self.relation.data[self.app]["stack"] = json.dumps(self.stack)
        """
    )
    assert any(f.kind == "caller" for f in findings)


def test_sorted_attr_read_in_another_method_is_not_flagged(lint_source):
    # An attribute assigned a sorted value carries no instability across the method
    # boundary -- the sanitiser must be respected class-wide, not just locally.
    findings = lint_source(
        """
        class Charm:
            def __init__(self):
                self._hosts = sorted(set(self.peers))

            def reconcile(self):
                self.relation.data[self.app]["hosts"] = ",".join(self._hosts)
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_instance_attrs_are_field_sensitive(lint_source):
    # A clean attribute is not tainted by a dirty sibling on the same object: reading
    # the sorted self._clean must not inherit self._dirty's instability.
    findings = lint_source(
        """
        class Charm:
            def __init__(self):
                self._clean = sorted(set(self.peers))
                self._dirty = set(self.peers)

            def reconcile(self):
                self.relation.data[self.app]["c"] = ",".join(self._clean)
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_dirty_instance_attr_is_flagged_while_clean_sibling_is_not(lint_source):
    # The mirror: reading the *dirty* sibling is flagged.
    findings = lint_source(
        """
        class Charm:
            def __init__(self):
                self._clean = sorted(set(self.peers))
                self._dirty = set(self.peers)

            def reconcile(self):
                self.relation.data[self.app]["d"] = ",".join(self._dirty)
        """
    )
    assert any(f.kind == "caller" for f in findings)


def test_annotated_attr_assignment_carries_across_methods(lint_source):
    # ``self.x: List = set(...)`` (an annotated assignment) is tracked too.
    findings = lint_source(
        """
        from typing import List

        class Charm:
            def __init__(self):
                self._hosts: List = set(self.peers)

            def reconcile(self):
                self.relation.data[self.app]["hosts"] = ",".join(self._hosts)
        """
    )
    assert any(f.kind == "caller" for f in findings)


def test_volatile_attr_read_back_in_another_method_is_flagged(lint_source):
    # Instance-attribute provenance carries volatility too, not just ordering.
    findings = lint_source(
        """
        import uuid

        class Charm:
            def __init__(self):
                self._token = str(uuid.uuid4())

            def reconcile(self):
                self.relation.data[self.app]["token"] = self._token
        """
    )
    assert any(f.rule == "nondeterministic" for f in findings)


def test_clean_scalar_attr_is_not_flapped_by_an_unrelated_dirty_attr(lint_source):
    # Guard against over-approximation: a scalar attribute (an IP string) read into a
    # databag must not be flagged just because some *other* attribute of the class is an
    # unordered collection (the postgresql self._unit_ip false-positive shape).
    findings = lint_source(
        """
        class Charm:
            def __init__(self):
                self._ip = str(self.bind_address)
                self._members = set(self.peers)

            def reconcile(self):
                self.relation.data[self.app]["addr"] = self._ip
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_storedstate_two_level_attr_carries_across_handlers(lint_source):
    # ``self._stored.jobs`` -- the ops StoredState idiom (a *two-level* self attribute)
    # is the standard way charms carry data across event handlers. An unstable value
    # parked there in one handler and published in another must stay tracked (the
    # cos-proxy scrape_jobs / alert_rules pipeline).
    findings = lint_source(
        """
        import json

        class Charm:
            def build(self, relation):
                self._stored.jobs = list(set(relation.units))

            def publish(self, relation):
                relation.data[self.app]["jobs"] = json.dumps(self._stored.jobs)
        """
    )
    assert any(f.kind == "caller" and f.sink == "databag" for f in findings)


def test_storedstate_clean_sibling_attr_is_not_flagged(lint_source):
    # Field-sensitivity across the two-level key: a clean sibling under the same
    # StoredState container must not inherit a dirty sibling's taint.
    findings = lint_source(
        """
        import json

        class Charm:
            def build(self, relation):
                self._stored.jobs = list(set(relation.units))
                self._stored.ready = True

            def publish(self, relation):
                relation.data[self.app]["ready"] = json.dumps(self._stored.ready)
        """
    )
    assert not any(f.sink == "databag" for f in findings)
