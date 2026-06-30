"""Import-alias resolution: a renamed import still matches its canonical name.

Name-matching is on the *bound* name a call uses, so without resolution an ``as``
rename would hide a known source or serializer. The collector records each file's
import aliases and the engine normalizes the bound name back before matching.
"""

from __future__ import annotations


def test_module_aliased_serializer(lint_source):
    # `import json as j` -> j.dumps still matches (the final attribute is unchanged,
    # but this pins the behaviour).
    findings = lint_source(
        """
        import json as j

        class Charm:
            def h(self):
                self.relation.data[self.app]["x"] = j.dumps({1, 2})
        """
    )
    assert any(f.rule == "unordered-collection" for f in findings)


def test_renamed_serializer_import(lint_source):
    # `from json import dumps as ddump` -> ddump(...) resolves to dumps, so the set
    # inside is no longer hidden behind an unknown call.
    findings = lint_source(
        """
        from json import dumps as ddump

        class Charm:
            def h(self):
                self.relation.data[self.app]["x"] = ddump({1, 2})
        """
    )
    assert any(f.rule == "unordered-collection" for f in findings)


def test_renamed_volatile_source_import(lint_source):
    # `from uuid import uuid4 as gen_id` -> gen_id() resolves to uuid4.
    findings = lint_source(
        """
        from uuid import uuid4 as gen_id

        class Charm:
            def h(self):
                self.relation.data[self.app]["x"] = gen_id()
        """
    )
    assert any(f.rule == "nondeterministic" for f in findings)


def test_plain_from_import_still_matches(lint_source):
    # `from uuid import uuid4` (no rename) keeps the canonical bound name.
    findings = lint_source(
        """
        from uuid import uuid4

        class Charm:
            def h(self):
                self.relation.data[self.app]["x"] = uuid4()
        """
    )
    assert any(f.rule == "nondeterministic" for f in findings)


def test_aliased_sanitizer_still_clears(lint_source):
    # `from builtins import sorted as srt` -> srt(...) resolves to sorted, so a
    # sorted set is correctly treated as stable (no false positive).
    findings = lint_source(
        """
        import json
        from builtins import sorted as srt

        class Charm:
            def h(self, values):
                self.relation.data[self.app]["x"] = json.dumps(srt(set(values)))
        """
    )
    assert findings == []


def test_alias_does_not_leak_between_files(lint_source):
    # An alias defined in one snippet must not affect another. lint_source writes a
    # fresh file each call, so a `dumps`-shadowing alias here must not change how a
    # later, un-aliased call is treated. (Sanity: the aliased call is still flagged.)
    findings = lint_source(
        """
        from json import dumps as render_cfg

        class Charm:
            def h(self):
                self.relation.data[self.app]["x"] = render_cfg({1, 2})
        """
    )
    assert any(f.rule == "unordered-collection" for f in findings)
    clean = lint_source(
        """
        class Charm:
            def h(self, render_cfg):
                # render_cfg is just a parameter here, no import alias in this file
                self.relation.data[self.app]["x"] = render_cfg
        """
    )
    # a bare unannotated param written to a databag is a medium contract sink,
    # but crucially NOT treated as `json.dumps` via a stale alias.
    assert all(f.rule != "unordered-collection" or f.confidence != "high" for f in clean)
