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
