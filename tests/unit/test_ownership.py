"""Error-vs-warning classification by *who can fix the bug*.

A finding is an ``error`` (fails CI) only when its fix lives in code the scanned
charm owns -- its ``src/`` or its own ``lib/charms/<charm-name>/`` namespace. A
bug inside a *vendored* copy of someone else's charm library
(``lib/charms/<other-charm>/``) is a real finding, but the charm cannot fix it,
so it is reported as a non-blocking ``warning``.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from flaplint.analyzer import Analyzer

_BUG = """
import json


class Mod:
    def write(self, rel):
        rel.data[self.app]["targets"] = json.dumps({"a", "b", "c"})
"""


def _build_charm(root: Path) -> None:
    (root / "charmcraft.yaml").write_text("name: my-charm\nsummary: t\n")
    (root / "src").mkdir()
    (root / "src" / "charm.py").write_text(textwrap.dedent(_BUG))
    owned = root / "lib" / "charms" / "my_charm" / "v0"
    owned.mkdir(parents=True)
    (owned / "owned.py").write_text(textwrap.dedent(_BUG))
    foreign = root / "lib" / "charms" / "other_charm" / "v0"
    foreign.mkdir(parents=True)
    (foreign / "vendored.py").write_text(textwrap.dedent(_BUG))


def _levels(root: Path) -> dict[str, str]:
    findings = Analyzer(
        [str(root / "src")],
        min_confidence="low",
    ).run()
    # path is relativized; key by the trailing filename for readability.
    return {Path(f.path).name: f.level for f in findings}


def test_src_finding_is_an_error(tmp_path):
    _build_charm(tmp_path)
    assert _levels(tmp_path)["charm.py"] == "error"


def test_owned_lib_finding_is_an_error(tmp_path):
    _build_charm(tmp_path)
    assert _levels(tmp_path)["owned.py"] == "error"


def test_vendored_foreign_lib_finding_is_a_warning(tmp_path):
    _build_charm(tmp_path)
    assert _levels(tmp_path)["vendored.py"] == "warning"
