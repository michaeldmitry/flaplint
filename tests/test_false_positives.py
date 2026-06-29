"""Regressions for false positives found scanning real charms (postgresql-operator).

* builtin collection methods (``set.update`` / ``dict.update``) must not collide,
  by bare name, with a same-named *user* method that writes a databag;
* PEP 604 unions (``str | None``) must be read as their payload type, like
  ``Optional[str]``, so a scalar string isn't treated as a collection.
"""

from __future__ import annotations


def test_set_update_does_not_collide_with_user_update_method(lint_source):
    # `subnets.update(set(...))` is a builtin set method. It must NOT resolve to the
    # charm's own `update(...)` (which writes a databag) just because they share a
    # name -- that produced a high-confidence false positive. And the value here is
    # sorted before it reaches the databag anyway, so nothing should be flagged.
    findings = lint_source(
        """
        class Charm:
            def update(self, items: dict):
                # a same-named method that DOES write a databag (its own param is a
                # dict, so it raises no finding of its own -- isolating the collision)
                self.relation.data[self.app]["x"] = items

            def build(self, relation):
                subnets = set()
                for unit, rdata in relation.data.items():
                    subnets.update(set(rdata.get("egress", "").split(",")))
                self.relation.data[self.app]["allowed"] = ",".join(sorted(subnets))
        """,
        relations_unordered=True,
    )
    assert findings == []


def test_self_method_call_still_resolves(lint_source):
    # The collision guard must not break a genuine `self.update(...)` self-call:
    # passing a local set into the charm's own databag-writing `update` is a real
    # caller bug and must still be flagged.
    findings = lint_source(
        """
        class Charm:
            def update(self, items):
                self.relation.data[self.app]["x"] = items

            def handler(self, values):
                self.update({v for v in values})
        """
    )
    assert any(f.kind == "caller" for f in findings)


def test_str_or_none_param_written_to_databag_is_not_a_collection(lint_source):
    # `system_identifier: str | None` is a scalar string, not an unordered
    # collection -- writing it to a databag must not raise a contract-boundary sink.
    findings = lint_source(
        """
        class Charm:
            def update(self, system_identifier: str | None = None):
                self.relation.data[self.app]["sysid"] = system_identifier
        """
    )
    assert findings == []


def test_str_or_none_param_iterated_is_not_flagged(lint_source):
    # `extra_roles: str | None` -> `extra_roles.split(",")` is a deterministic list;
    # iterating it must not raise an unordered-iteration finding.
    findings = lint_source(
        """
        class Charm:
            def roles(self, extra_roles: str | None):
                out = [r.lower() for r in extra_roles.split(",")]
                self.relation.data[self.app]["roles"] = ",".join(out)
        """
    )
    assert [f for f in findings if f.rule == "unordered-iteration"] == []


def test_set_comprehension_joined_into_databag_is_still_flagged(lint_source):
    # The genuine bug at db.py:295 must still be caught: a set comprehension joined
    # into a string and written to a databag has non-deterministic word order.
    # ``sep.join(<set>)`` bakes the iteration order into the result string -- that is
    # *iteration* instability (a key-sorting serializer cannot fix in-string order),
    # so the right fix is sorted() before the join.
    findings = lint_source(
        """
        class Charm:
            def h(self, current):
                self.relation.data[self.app]["allowed_units"] = " ".join({
                    unit for unit in current.split() if unit != "x"
                })
        """
    )
    flagged = [f for f in findings if f.rule == "unordered-iteration"]
    assert flagged and flagged[0].confidence == "high"


def test_isinstance_list_guard_makes_param_iteration_safe(lint_source):
    # A normalizer that only iterates a parameter inside `if isinstance(raw, list):`
    # is provably iterating a list there -- a caller passing a set can't reach it --
    # so the precautionary contract-boundary "might be unordered" finding is wrong.
    findings = lint_source(
        """
        from typing import Any

        class Charm:
            def normalize(self, raw: Any):
                if isinstance(raw, list):
                    self.relation.data[self.app]["x"] = [str(x).strip() for x in raw]
        """
    )
    assert findings == []


def test_isinstance_list_guard_still_flags_concrete_instability(lint_source):
    # Safety: `isinstance(x, list)` proves the *type*, not the *order*. A genuinely
    # unstable `list(some_set)` is a list and still flaps, so it must stay flagged
    # even inside the guard -- the narrowing strips only the parameter uncertainty.
    findings = lint_source(
        """
        from typing import Any

        class Charm:
            def normalize(self, raw: Any, names):
                if isinstance(raw, list):
                    self.relation.data[self.app]["x"] = [n for n in list(set(names))]
        """
    )
    assert any(f.rule == "unordered-iteration" for f in findings)


def test_str_split_into_databag_is_deterministic(lint_source):
    # `s.split(",")` returns a list ordered by string content, not by any collection
    # iteration -- iterating it is deterministic, so an `Any`/unannotated source that
    # is split must not raise a contract-boundary iteration finding.
    findings = lint_source(
        """
        from typing import Any

        class Charm:
            def normalize(self, raw: Any):
                s = str(raw).strip()
                self.relation.data[self.app]["x"] = [p.strip() for p in s.split(",")]
        """
    )
    assert findings == []


def test_split_of_volatile_string_still_flagged(lint_source):
    # Splitting launders *ordering*, not *content* volatility: a uuid split into
    # parts and written to a databag still differs every reconcile.
    findings = lint_source(
        """
        import uuid

        class Charm:
            def h(self):
                parts = str(uuid.uuid4()).split("-")
                self.relation.data[self.app]["id"] = parts
        """
    )
    assert any(f.rule == "nondeterministic" for f in findings)
