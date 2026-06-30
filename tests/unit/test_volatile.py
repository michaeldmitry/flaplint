"""Tests for nondeterministic-value (``volatile`` origin) detection.

A ``volatile`` value (uuid/time/random) is strictly worse than mere order
instability: it changes on *every* reconcile and ``sorted()`` / ``sort_keys``
cannot rescue it, so the linter must keep flagging it through stringification and
key-sorting wrappers.
"""

from __future__ import annotations

from conftest import details


def test_uuid_written_to_databag_is_flagged(lint_source):
    findings = lint_source(
        """
        import uuid

        class Charm:
            def _on_changed(self, event):
                rel = self.model.get_relation("peers")
                rel.data[self.app]["id"] = str(uuid.uuid4())
        """
    )
    assert len(findings) == 1
    assert findings[0].confidence == "high"
    assert findings[0].rule == "nondeterministic"


def test_uuid_survives_str_wrapper(lint_source):
    findings = lint_source(
        """
        import uuid

        class Charm:
            def _on_changed(self, event):
                value = str(uuid.uuid4())
                self.relation.data[self.app]["id"] = value
        """
    )
    assert len(findings) == 1
    assert "nondeterministic" in details(findings)


def test_uuid_in_dict_survives_sort_keys(lint_source):
    # sort_keys fixes *ordering* but not volatility, so this must still fire.
    findings = lint_source(
        """
        import json
        import uuid

        class Charm:
            def _on_changed(self, event):
                payload = {"uuid": str(uuid.uuid4())}
                self.relation.data[self.app]["x"] = json.dumps(payload, sort_keys=True)
        """
    )
    assert len(findings) == 1
    assert "nondeterministic" in details(findings)


def test_time_value_is_flagged(lint_source):
    findings = lint_source(
        """
        import time

        class Charm:
            def _on_changed(self, event):
                self.relation.data[self.app]["ts"] = str(time.time())
        """
    )
    assert len(findings) == 1
    assert findings[0].confidence == "high"


def test_static_value_is_not_volatile(lint_source):
    findings = lint_source(
        """
        class Charm:
            def _on_changed(self, event):
                self.relation.data[self.app]["v"] = str(self.config["version"])
        """
    )
    assert findings == []
