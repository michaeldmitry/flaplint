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


def test_single_element_set_literal_is_not_unordered(lint_source):
    # ``{x}`` has exactly one element: no iteration-order ambiguity, so serializing
    # it is deterministic. The ``{"auth": {auth_url}}`` idiom must not be flagged.
    findings = lint_source(
        """
        import json

        class Charm:
            def h(self, event):
                self.relation.data[self.app]["u"] = json.dumps({"a": {self.addr}})
        """
    )
    assert findings == []


def test_single_element_set_constructor_is_not_unordered(lint_source):
    # Same for the constructor spellings over a one-element collection literal:
    # ``set([x])`` / ``frozenset((x,))`` build a singleton, not an unordered set.
    findings = lint_source(
        """
        import json

        class Charm:
            def h(self, event):
                self.relation.data[self.app]["a"] = json.dumps(set([self.addr]))
                self.relation.data[self.app]["b"] = json.dumps(frozenset((self.addr,)))
        """
    )
    assert findings == []


def test_single_element_set_comprehension_is_not_unordered(lint_source):
    # A set comp that provably yields one element (single generator, no filter, over a
    # one-element literal) is order-stable like ``{x}``.
    findings = lint_source(
        """
        import json

        class Charm:
            def h(self, event):
                self.relation.data[self.app]["u"] = json.dumps(
                    {p.strip() for p in [self.addr]}
                )
        """
    )
    assert findings == []


def test_multi_element_set_literal_is_still_flagged(lint_source):
    # Two distinct elements: hash-seeded iteration order is unstable, still a bug.
    findings = lint_source(
        """
        import json

        class Charm:
            def h(self, event):
                self.relation.data[self.app]["u"] = json.dumps({self.a, self.b})
        """
    )
    assert len(findings) == 1


def test_single_element_set_of_volatile_still_flagged(lint_source):
    # Dropping set-order ``local`` must not launder the element's own instability: a
    # singleton holding a volatile value still churns.
    findings = lint_source(
        """
        import json, uuid

        class Charm:
            def h(self, event):
                self.relation.data[self.app]["u"] = json.dumps({str(uuid.uuid4())})
        """
    )
    assert len(findings) == 1
    assert findings[0].rule == "nondeterministic"


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


def test_reading_a_file_into_a_databag_is_not_flagged(lint_source):
    # `path.read_text()` returns the file's (deterministic) content -- reading a path
    # parameter is a scalar read, not an ordering source. Writing it to a databag
    # must not be flagged (if the file's content is itself unstable, that's the fault
    # of whatever wrote it).
    findings = lint_source(
        """
        from pathlib import Path

        class Charm:
            def h(self, path: Path):
                self.relation.data[self.app]["cfg"] = path.read_text()
        """
    )
    assert findings == []


def test_dict_get_launders_mapping_order_not_value_taint(lint_source):
    # ``d.get(field)`` extracts ONE value by key -- the method analogue of ``d[key]``
    # -- so it launders the *mapping's own order* while preserving *value* taint. Here
    # the instability lives only in how the dict is built (``for g in list(set(...)):
    # d.update(...)``), i.e. dictionary-order taint, which a keyed lookup does not
    # depend on -- so a single field fetched off it (the data_platform_libs
    # ``fetch_my_relation_field`` -> ``.get(rid, {}).get(field)`` chain returning a TLS
    # key/cert scalar) must NOT inherit that iteration taint. (Value taint is preserved
    # separately -- see the constant-key test below.)
    findings = lint_source(
        """
        class Charm:
            def _build(self):
                d = {}
                for g in list(set(self._raw())):
                    d.update(self._op(g))
                return d
            def h(self):
                self._container.push("/certs", self._build().get(1, {}).get("key"))
        """
    )
    assert not any(f.sink == "file" for f in findings)


def test_dict_get_launders_even_with_a_user_get_method_present(lint_source):
    # A stray user-defined ``get`` must not defeat the laundering. Note the analysis
    # does NOT infer that the receiver is a dict -- it matches on ``get`` being a
    # builtin-collection method name on a *non-self* receiver, so it declines to union
    # a same-named user method's summary (the same cross-class collision guard the
    # views/mutators get). Accepted trade-off: a user class reimplementing ``get`` to
    # return a whole collection would be mis-laundered; in exchange an untyped
    # call-result receiver (the real FP) is handled.
    findings = lint_source(
        """
        class Other:
            def get(self, k):
                return list(self._stuff)
        class Charm:
            def _build(self):
                d = {}
                for g in list(set(self._raw())):
                    d.update(self._op(g))
                return d
            def h(self):
                self._container.push("/p", self._build().get("field"))
        """
    )
    assert not any(f.sink == "file" for f in findings)


def test_dict_get_of_a_constant_key_still_catches_a_buried_unstable_value(lint_source):
    # Laundering must stay field-sensitive: a constant-key ``.get('jobs')`` where that
    # key holds a genuinely unstable value (``list(set(...))``) is still flagged, like
    # the equivalent ``d['jobs']`` subscript.
    findings = lint_source(
        """
        class Charm:
            def h(self):
                d = {"jobs": list(set(self.x)), "name": "fixed"}
                self.relation.data[self.app]["j"] = ",".join(d.get("jobs"))
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_external_typed_receiver_from_helper_does_not_collide_with_same_name_method(
    lint_source,
):
    # `prm.reconcile(policies)` where `prm` is an *external* type, obtained from a
    # helper annotated `-> PolicyResourceManager` (a class we cannot see into). It
    # shares the method name `reconcile` with `Nginx.reconcile`, which writes its
    # parameter to a config file. Resolving `prm.reconcile` by bare name imported
    # nginx's file sink and mis-attributed an unrelated (mesh-policy) unordered list to
    # the nginx write -- a cross-wire false positive (right sink, wrong source). The
    # helper's external return type must type `prm` so the receiver is recognised as
    # external and the same-name union is not applied. (A *direct* external
    # construction already gets this via `ctor_class`; this covers the helper case.)
    findings = lint_source(
        """
        class Nginx:
            def reconcile(self, config: str):
                self._container.push("/etc/nginx.conf", config)

        def _get_prm() -> "PolicyResourceManager":
            return PolicyResourceManager()

        class MeshReconciler:
            def build(self, cluster):
                prm = _get_prm()
                policies = list({app for app in cluster.gather_apps()})
                prm.reconcile(policies)
        """
    )
    assert [f for f in findings if f.sink == "file"] == []
