"""A charm vendors several versions of a library side by side (``.../v0/foo.py``
and ``.../v1/foo.py``), each re-declaring the *same* class and method names. The
function registry keys by bare name and disambiguates only by bare ``class_name``,
so both versions' definitions collide: a clean ``v0`` write must not inherit a
``v1`` method's instability (a cross-version phantom finding / an impossible trace
blaming a function ``v0`` never calls).
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import List

from flaplint.analyzer import Analyzer
from flaplint.model import Finding


_V0 = """
    import json
    from ops import Object

    class SourceConsumer(Object):
        def publish(self):
            self.relation.data[self.app]["x"] = json.dumps(self._payload())

        def _payload(self):
            return ["a", "b"]  # ordered list -- clean
"""

_V1 = """
    import json
    from ops import Object

    class SourceConsumer(Object):
        def publish(self):
            self.relation.data[self.app]["x"] = json.dumps(self._payload())

        def _payload(self):
            return list({"a", "b"})  # unordered set materialised -- a real flap
"""


def _lint_two(tmp_path: Path) -> List[Finding]:
    v0 = tmp_path / "v0" / "foo.py"
    v1 = tmp_path / "v1" / "foo.py"
    v0.parent.mkdir(parents=True)
    v1.parent.mkdir(parents=True)
    v0.write_text(textwrap.dedent(_V0))
    v1.write_text(textwrap.dedent(_V1))
    return Analyzer([str(v0), str(v1)], min_confidence="low").run()


def test_clean_v0_write_does_not_inherit_v1_instability(tmp_path):
    findings = _lint_two(tmp_path)

    # The v1 write is a genuine flap and must be flagged.
    v1_hits = [f for f in findings if "/v1/" in f.path]
    assert v1_hits, "v1's list(set(...)) write should be flagged"

    # The v0 write is clean; its same-named ``_payload`` returns an ordered list,
    # so it must NOT pick up v1's ``_payload`` summary across the version boundary.
    v0_hits = [f for f in findings if "/v0/" in f.path]
    assert v0_hits == [], f"v0 should stay clean, got {[f.format() for f in v0_hits]}"


# -- tier 2: a typed cross-module receiver resolves to the imported version -------

_CLEAN_PROVIDER = """
    class Provider:
        def publish(self, data):
            self._cache = data          # no databag write -- clean
"""

_BUGGY_PROVIDER = """
    import json

    class Provider:
        def publish(self, data):
            self.rel.data[self.app]["y"] = json.dumps(data)   # writes a databag
"""

_CALLER = """
    from a.{ver}.bar import Provider

    class Charm:
        def go(self):
            p = Provider()
            p.publish({{1, 2}})
"""


def _lint_caller(tmp_path: Path, imported: str) -> List[Finding]:
    (tmp_path / "a" / "v0").mkdir(parents=True)
    (tmp_path / "a" / "v1").mkdir(parents=True)
    (tmp_path / "src").mkdir()
    (tmp_path / "a" / "v0" / "bar.py").write_text(textwrap.dedent(_CLEAN_PROVIDER))
    (tmp_path / "a" / "v1" / "bar.py").write_text(textwrap.dedent(_BUGGY_PROVIDER))
    caller = tmp_path / "src" / "charm.py"
    caller.write_text(textwrap.dedent(_CALLER.format(ver=imported)))
    files = [
        str(caller),
        str(tmp_path / "a" / "v0" / "bar.py"),
        str(tmp_path / "a" / "v1" / "bar.py"),
    ]
    return Analyzer(files, min_confidence="low").run()


def test_typed_receiver_pins_to_imported_version(tmp_path):
    # The caller imports the *clean* v0 Provider: its ``publish`` writes no databag,
    # so passing a set into it must NOT be flagged -- resolution must not union in the
    # v1 Provider's dangerous same-named ``publish``.
    findings = _lint_caller(tmp_path, "v0")
    caller_hits = [f for f in findings if "/src/charm.py" in f.path]
    assert caller_hits == [], f"clean-v0 import should not flag, got {caller_hits}"


def test_typed_receiver_flags_when_importing_buggy_version(tmp_path):
    # Import the buggy v1 Provider instead: the same call site now *must* flag,
    # proving the pin follows the import rather than blanket-suppressing.
    findings = _lint_caller(tmp_path, "v1")
    caller_hits = [f for f in findings if "/src/charm.py" in f.path]
    assert caller_hits, "buggy-v1 import must be flagged at the call site"
