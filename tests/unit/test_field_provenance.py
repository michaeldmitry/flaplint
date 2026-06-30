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
