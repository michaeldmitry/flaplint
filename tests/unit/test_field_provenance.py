"""Value-object field provenance: taint that survives a dataclass / model field.

flaplint tracks taint per local name; storing an unstable collection in an object
attribute used to drop it (the "dataclass-field barrier"). These tests cover the
field-sensitive tracking that carries an unstable field through construction, a
field write, an alias, and a cross-function return, and reads it back on
``obj.field`` access -- while staying field-*sensitive* so a clean field of a
partly-unstable object is not flagged.
"""

from __future__ import annotations


def test_field_read_back_in_function_is_flagged(lint_source):
    # A set stored in a constructor field, read back and joined into a databag.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self):
                ctx = JobContext(targets=set(self.hosts), name="x")
                self.relation.data[self.app]["jobs"] = ",".join(ctx.targets)
        """
    )
    assert any(f.rule == "unordered-iteration" and f.confidence == "high" for f in findings)


def test_field_read_back_across_function_is_flagged(lint_source):
    # The value object is built in one method, returned, and consumed in another:
    # the field taint rides the return summary (returns_field_origins).
    findings = lint_source(
        """
        class Charm:
            def _build(self):
                return JobContext(targets=set(self.hosts), name="x")

            def reconcile(self):
                ctx = self._build()
                self.relation.data[self.app]["jobs"] = ",".join(ctx.targets)
        """
    )
    assert any(f.rule == "unordered-iteration" and f.confidence == "high" for f in findings)


def test_clean_field_of_dirty_object_is_not_flagged(lint_source):
    # Field-*sensitivity*: ``name`` is an unsorted set but ``targets`` is sorted.
    # Reading the clean ``targets`` must not inherit ``name``'s instability (the
    # false positive a field-insensitive "whole object is dirty" model would give).
    findings = lint_source(
        """
        class Charm:
            def reconcile(self):
                ctx = JobContext(targets=sorted(set(self.hosts)), name=set(self.x))
                self.relation.data[self.app]["jobs"] = ",".join(ctx.targets)
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_dirty_field_of_object_is_flagged(lint_source):
    # The mirror of the above: reading the *unstable* field is flagged.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self):
                ctx = JobContext(targets=sorted(set(self.hosts)), name=set(self.x))
                self.relation.data[self.app]["who"] = ",".join(ctx.name)
        """
    )
    assert any(f.kind == "caller" for f in findings)


def test_whole_object_with_unstable_field_written_is_flagged(lint_source):
    # Writing the *whole* object (model dumped into the bag) still flags: the
    # serialization includes the unstable field. (Field keys don't suppress the
    # existing whole-object aggregate taint.)
    findings = lint_source(
        """
        class Charm:
            def reconcile(self):
                ctx = JobContext(targets=set(self.hosts))
                self.relation.data[self.app]["all"] = ctx
        """
    )
    assert any(f.kind == "caller" for f in findings)


def test_field_assignment_then_read_back_is_flagged(lint_source):
    # Taint that enters through a field *write* (not the constructor) is tracked too.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self):
                ctx = JobContext()
                ctx.targets = set(self.hosts)
                self.relation.data[self.app]["jobs"] = ",".join(ctx.targets)
        """
    )
    assert any(f.kind == "caller" for f in findings)


def test_alias_copies_field_taint(lint_source):
    # ``alias = ctx`` carries the field keys, so a read through the alias flags.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self):
                ctx = JobContext(targets=set(self.hosts))
                alias = ctx
                self.relation.data[self.app]["jobs"] = ",".join(alias.targets)
        """
    )
    assert any(f.kind == "caller" for f in findings)


def test_reassigning_field_to_sorted_clears_stale_taint(lint_source):
    # A field overwritten with a sorted value must not keep its old instability.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self):
                ctx = JobContext(targets=set(self.hosts))
                ctx.targets = sorted(ctx.targets)
                self.relation.data[self.app]["jobs"] = ",".join(ctx.targets)
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_volatile_field_read_back_is_flagged(lint_source):
    # Field provenance carries volatility too, not just ordering.
    findings = lint_source(
        """
        import uuid

        class Charm:
            def reconcile(self):
                ctx = JobContext(token=str(uuid.uuid4()))
                self.relation.data[self.app]["token"] = ctx.token
        """
    )
    assert any(f.rule == "nondeterministic" for f in findings)


def test_pydantic_json_of_unstable_list_field_is_still_flagged(lint_source):
    # Regression: a pydantic model whose list field is built from an unordered source,
    # serialised via `.json()` into a databag, DOES flap -- pydantic emits a list in
    # element order, so `.json()` must NOT be treated as laundering it (the cos_agent
    # `_dashboards` shape). The model's *field-name* order is stable; its list field's
    # *element* order is not.
    findings = lint_source(
        """
        import glob

        class Charm:
            def publish(self, relation):
                data = UnitData(dashboards=list(glob.glob("*.json")))
                relation.data[self.app]["d"] = data.json()
        """
    )
    assert any(f.kind == "caller" and f.sink == "databag" for f in findings)


def test_pydantic_model_dump_json_of_unstable_list_field_is_flagged(lint_source):
    # ``model_dump_json()`` (pydantic v2 idiom) launders the model's
    # *field-name* order, but a list field built from an unordered source still
    # flaps -- pydantic emits a list in element order. The dump must inherit the
    # field's concrete content taint, not launder it. (Was a silent false negative;
    # the v1 ``.json()`` spelling above was the only one that caught it.)
    findings = lint_source(
        """
        import glob

        class Charm:
            def publish(self, relation):
                data = UnitData(dashboards=list(glob.glob("*.json")))
                relation.data[self.app]["d"] = data.model_dump_json()
        """
    )
    assert any(f.kind == "caller" and f.sink == "databag" for f in findings)


def test_pydantic_model_dump_of_unstable_list_field_is_flagged(lint_source):
    # Same as above for the dict-producing ``model_dump()`` spelling.
    findings = lint_source(
        """
        import glob

        class Charm:
            def publish(self, relation):
                data = UnitData(dashboards=list(glob.glob("*.json")))
                relation.data[self.app]["d"] = str(data.model_dump())
        """
    )
    assert any(f.kind == "caller" and f.sink == "databag" for f in findings)


def test_positional_ctor_arg_to_a_collaborator_does_not_taint_its_methods(lint_source):
    # A stateful collaborator constructed with an unordered *positional* arg
    # (``ClusterProvider(frozenset(roles), ...)``) is not a value bag: the arg
    # configures it, it does not become its serialised content. So an unrelated
    # method call on it (``.grant_privkey()`` -> a secret id) must NOT inherit the
    # arg's instability. Only *keyword* ctor args (the ``Model(field=...)`` value-
    # object idiom) carry field taint; positional args do not.
    findings = lint_source(
        """
        class Prov:
            def grant_privkey(self, label):
                return "secret-id-string"

        class Charm:
            def __init__(self, rc):
                self.cluster = Prov(frozenset(rc.roles))
            def publish(self):
                self.relation.data[self.app]["k"] = self.cluster.grant_privkey("x")
        """
    )
    assert findings == []


def test_keyword_ctor_field_still_taints_a_dataclass_view_method(lint_source):
    # Counterpart to the positional guard: a dataclass built with a *keyword* field
    # from unordered data, whose view method folds that field into its result, still
    # flaps at the databag (the cos-proxy ``ScrapeJobContext(updated_job=...)`` ->
    # ``get_updated_jobs()`` -> ``json.dumps`` shape). Keyword ctor taint is kept.
    findings = lint_source(
        """
        import json
        from dataclasses import dataclass, field
        from typing import Any, Dict, List

        @dataclass
        class Ctx:
            updated_job: Dict[str, Any] = field(default_factory=dict)
            def get_updated_jobs(self, existing: List) -> List:
                jobs = list(existing)
                jobs.append(self.updated_job)
                return jobs

        class Charm:
            def _targets(self, rel):
                t = {}
                for u in rel.units:
                    t[u.name] = rel.data[u]["host"]
                return t
            def publish(self, rel):
                updated = build_job(self._targets(rel))
                ctx = Ctx(updated_job=updated)
                jobs = ctx.get_updated_jobs([])
                rel.data[self.app]["scrape_jobs"] = json.dumps(jobs)
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_positional_ctor_field_taints_a_known_value_object(lint_source):
    # The value-object idiom works *positionally* too: a ``@dataclass`` field filled
    # by position (``Ctx(updated)``) maps to the declared field the same way the
    # keyword form does, because the class is a known value object (its fields are
    # its constructor's positional params). Distinguishes it from a plain collaborator
    # (previous test), whose positional args are config and stay unabsorbed.
    findings = lint_source(
        """
        import json
        from dataclasses import dataclass, field
        from typing import Any, Dict, List

        @dataclass
        class Ctx:
            updated_job: Dict[str, Any] = field(default_factory=dict)
            def get_updated_jobs(self, existing: List) -> List:
                jobs = list(existing)
                jobs.append(self.updated_job)
                return jobs

        class Charm:
            def _targets(self, rel):
                t = {}
                for u in rel.units:
                    t[u.name] = rel.data[u]["host"]
                return t
            def publish(self, rel):
                updated = build_job(self._targets(rel))
                ctx = Ctx(updated)                       # positional, not keyword
                jobs = ctx.get_updated_jobs([])
                rel.data[self.app]["scrape_jobs"] = json.dumps(jobs)
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_model_dump_of_opaque_param_is_still_laundered(lint_source):
    # Monotonicity guard: a dump of an *opaque model parameter* carries
    # only contract-boundary uncertainty (the model's field-NAME order), which the
    # dump genuinely launders. Filtering concrete content must NOT start flagging
    # this -- it stays a non-write, no databag finding.
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation, model):
                relation.data[self.app]["d"] = model.model_dump_json()
        """
    )
    assert not any(f.sink == "databag" for f in findings)


# -- set coerced into a pydantic sequence field (previously a known gap) --------
# A pydantic ``__init__`` coerces a value into the field's declared type. A bare
# ``set`` handed to a ``list``/``tuple``/``Sequence`` field is turned into a
# positional sequence internally -- so its disorder moves from key order
# (``local``, laundered by a key-sorting serializer) into element order
# (``itercaller``, which survives one). Recognising the field's annotation lets the
# construction site promote ``local`` -> ``itercaller``.


def test_set_into_list_field_dumped_whole_is_flagged(lint_source):
    # The primary shape: a bare set into a ``list``-typed field, then the whole model
    # dumped via the key-sorting ``model_dump_json`` -- caught as element-order (not
    # laundered away as a plain set would be).
    findings = lint_source(
        """
        from pydantic import BaseModel

        class UnitData(BaseModel):
            hosts: list[str]

        class Charm:
            def publish(self, relation, peers):
                data = UnitData(hosts=set(peers))
                relation.data[self.app]["d"] = data.model_dump_json()
        """
    )
    assert any(f.rule == "unordered-iteration" and f.sink == "databag" for f in findings)


def test_set_into_list_field_read_back_and_key_sorted_is_flagged(lint_source):
    # The laundering miss: read the field back and pass it through an explicit
    # key-sorting serializer. Recorded as a plain set it would be laundered; as an
    # element-ordered list (the pydantic coercion) it must survive and be flagged.
    findings = lint_source(
        """
        import json
        from pydantic import BaseModel

        class Cfg(BaseModel):
            hosts: list[str]

        class Charm:
            def publish(self, relation, peers):
                cfg = Cfg(hosts=set(peers))
                relation.data[self.app]["h"] = json.dumps(cfg.hosts, sort_keys=True)
        """
    )
    assert any(f.rule == "unordered-iteration" and f.sink == "databag" for f in findings)


def test_set_into_set_field_is_not_promoted(lint_source):
    # A pydantic ``Set`` field keeps set semantics -- its disorder stays key-order,
    # which a key-sorting serializer legitimately fixes. Must NOT be promoted.
    findings = lint_source(
        """
        import json
        from typing import Set
        from pydantic import BaseModel

        class Cfg(BaseModel):
            hosts: Set[str]

        class Charm:
            def publish(self, relation, peers):
                cfg = Cfg(hosts=set(peers))
                relation.data[self.app]["h"] = json.dumps(cfg.hosts, sort_keys=True)
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_set_into_dataclass_list_field_is_not_promoted(lint_source):
    # A plain dataclass does NOT coerce -- the field holds the set as-is, whose
    # disorder is key-order (``local``), laundered by a key-sorting serializer.
    # Promoting here would be a false positive, so it must stay clean.
    findings = lint_source(
        """
        import json
        from dataclasses import dataclass

        @dataclass
        class Cfg:
            hosts: list

        class Charm:
            def publish(self, relation, peers):
                cfg = Cfg(hosts=set(peers))
                relation.data[self.app]["h"] = json.dumps(cfg.hosts, sort_keys=True)
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_sorted_set_into_list_field_is_clean(lint_source):
    # The fix is honoured: sorting before construction leaves the field stable.
    findings = lint_source(
        """
        from pydantic import BaseModel

        class UnitData(BaseModel):
            hosts: list[str]

        class Charm:
            def publish(self, relation, peers):
                data = UnitData(hosts=sorted(set(peers)))
                relation.data[self.app]["d"] = data.model_dump_json()
        """
    )
    assert not any(f.sink == "databag" for f in findings)


# -- dict-by-fixed-key field provenance -----------------------------------------


def test_unstable_value_extracted_by_dict_key_is_flagged(lint_source):
    # a value buried under a constant dict key, then pulled back out by
    # that key and serialised, still flaps. The fixed-key read must return *that
    # key's* taint, not be treated as an order-independent mapping lookup.
    findings = lint_source(
        """
        import json
        class Charm:
            def publish(self, relation, peers):
                cfg = {"jobs": list(set(peers))}
                relation.data[self.app]["x"] = json.dumps(cfg["jobs"])
        """
    )
    assert any(f.kind == "caller" and f.sink == "databag" for f in findings)


def test_unstable_value_extracted_from_instance_attr_dict_is_flagged(lint_source):
    # The cross-method half: build the dict in __init__, pull the unstable value out
    # by key in a handler. Carried class-wide under the compound attr ``cfg['jobs']``.
    findings = lint_source(
        """
        import json
        class Charm:
            def __init__(self, peers):
                self.cfg = {"jobs": list(set(peers))}
            def reconcile(self, relation):
                relation.data[self.app]["x"] = json.dumps(self.cfg["jobs"])
        """
    )
    assert any(f.kind == "caller" and f.sink == "databag" for f in findings)


def test_clean_sibling_dict_key_is_not_flagged(lint_source):
    # Field-sensitivity guard: extracting a *clean* sibling key from the same dict
    # must NOT be flagged. This is the false positive the conservative whole-container
    # approach was rejected for -- per-key tracking keeps it clean.
    findings = lint_source(
        """
        class Charm:
            def publish(self, relation, peers):
                cfg = {"jobs": list(set(peers)), "name": "fixed"}
                relation.data[self.app]["x"] = cfg["name"]
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_clean_sibling_key_of_instance_attr_dict_is_not_flagged(lint_source):
    # Same field-sensitivity guard across methods.
    findings = lint_source(
        """
        class Charm:
            def __init__(self, peers):
                self.cfg = {"jobs": list(set(peers)), "name": "fixed"}
            def reconcile(self, relation):
                relation.data[self.app]["x"] = self.cfg["name"]
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_whole_container_dump_with_buried_unstable_value_is_flagged(lint_source):
    # Regression: dumping the *whole* dict (not extracting a key) still flaps via the
    # buried list field -- the dominant container-burial shape, which already worked
    # and must keep working alongside the per-key tracking.
    findings = lint_source(
        """
        import json
        class Charm:
            def __init__(self, peers):
                self.cfg = {"jobs": list(set(peers))}
            def reconcile(self, relation):
                relation.data[self.app]["d"] = json.dumps(self.cfg)
        """
    )
    assert any(f.kind == "caller" and f.sink == "databag" for f in findings)


# -- deeper-than-one-level nesting (previously a known gap) ------------------
# The path helpers used to cap at one attribute level (``obj.field``) / two for a
# ``self``-rooted chain (``self._stored.x``). A value buried deeper -- through an
# intermediate value object (``self.ctx.config.targets``) -- was silently dropped.
# The access-path key now spans any depth, symmetric on read and write.


def test_deep_self_field_within_method_is_flagged(lint_source):
    # ``self.ctx.config.targets`` -- three levels from ``self``. Assigned an unstable
    # set and read back (joined into a databag) in the same method.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self):
                self.ctx.config.targets = set(self.hosts)
                self.relation.data[self.app]["t"] = ",".join(self.ctx.config.targets)
        """
    )
    assert any(f.rule == "unordered-iteration" and f.confidence == "high" for f in findings)


def test_deep_self_field_across_methods_is_flagged(lint_source):
    # The charm idiom at depth: parked on a nested self field in one method, read in
    # another. Rides the class-level instance-attribute taint under the full sub-chain.
    findings = lint_source(
        """
        import json
        class Charm:
            def build(self):
                self.ctx.config.targets = list(set(self.hosts))
            def publish(self, relation):
                relation.data[self.app]["t"] = json.dumps(self.ctx.config.targets)
        """
    )
    assert any(f.kind == "caller" and f.sink == "databag" for f in findings)


def test_deep_plain_field_chain_within_method_is_flagged(lint_source):
    # A plain (non-self) ``Name``-rooted chain of depth 3: ``cfg.inner.targets``.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self):
                cfg.inner.targets = set(self.hosts)
                self.relation.data[self.app]["t"] = ",".join(cfg.inner.targets)
        """
    )
    assert any(f.rule == "unordered-iteration" and f.confidence == "high" for f in findings)


def test_deep_self_field_is_field_sensitive(lint_source):
    # A clean sibling under the same nested container must not inherit a dirty
    # sibling's taint: reading ``self.ctx.config.name`` stays clean.
    findings = lint_source(
        """
        class Charm:
            def reconcile(self):
                self.ctx.config.targets = set(self.hosts)
                self.ctx.config.name = "fixed"
                self.relation.data[self.app]["n"] = ",".join(self.ctx.config.name)
        """
    )
    assert not any(f.sink == "databag" for f in findings)


def test_deep_self_field_respects_sorted(lint_source):
    # A ``sorted()`` write to the deep field is honoured -- no finding on read-back.
    findings = lint_source(
        """
        class Charm:
            def build(self):
                self.ctx.config.targets = sorted(set(self.hosts))
            def publish(self, relation):
                relation.data[self.app]["t"] = ",".join(self.ctx.config.targets)
        """
    )
    assert [f for f in findings if f.kind == "caller"] == []


def test_field_mutation_through_inline_getter_is_flagged(lint_source):
    # A value reached through a *pure getter* call: ``self._get_ctx().targets = set(...)``
    # writes into the object the getter returns (``return self._ctx``), so a later read
    # of ``self._ctx.targets`` still sees the instability. Bridges the "value reached
    # through a call" tracking gap for the getter-returns-self-attribute shape.
    findings = lint_source(
        """
        import json

        class Charm:
            def _get_ctx(self):
                return self._ctx
            def go(self, x):
                self._get_ctx().targets = set(x)
                self.relation.data[self.app]["t"] = json.dumps(list(self._ctx.targets))
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_field_mutation_through_getter_aliased_local_is_flagged(lint_source):
    # Same, via a local bound to the getter: ``ctx = self._get_ctx(); ctx.targets =
    # set(...)`` -- the local is treated as an alias of ``self._ctx``, so the mutation
    # is charged to the real attribute and a read of ``self._ctx.targets`` is flagged.
    findings = lint_source(
        """
        import json

        class Charm:
            def _get_ctx(self):
                return self._ctx
            def go(self, x):
                ctx = self._get_ctx()
                ctx.targets = set(x)
                self.relation.data[self.app]["t"] = json.dumps(list(self._ctx.targets))
        """
    )
    assert any(f.sink == "databag" for f in findings)


def test_getter_returning_a_copy_is_not_aliased(lint_source):
    # Strictness guard: a getter that returns a *copy* of an attribute
    # (``return list(self._ctx)``) is NOT an alias of it -- mutating the copy must not
    # be charged back to ``self._ctx``. So writing the copy's field and then reading
    # ``self._ctx.targets`` stays clean (the copy and the attribute are different
    # objects). This is what distinguishes a true getter (``return self._ctx``, aliased
    # in the tests above) from a value-returning method that merely mentions the attr.
    findings = lint_source(
        """
        import json

        class Charm:
            def _get_ctx(self):
                return list(self._ctx)
            def go(self, x):
                ctx = self._get_ctx()
                ctx.targets = set(x)
                self.relation.data[self.app]["t"] = json.dumps(list(self._ctx.targets))
        """
    )
    assert not any(f.sink == "databag" for f in findings)
