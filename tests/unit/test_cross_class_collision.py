"""Cross-class name collision: a method call on a *directly referenced class*
(``DashboardPath40UID.generate(...)``, ``PrivateKey.generate()``) resolves its
return-summary by bare name, so it unions the summaries of every same-named
function in the scan -- including methods on *unrelated* classes in other vendored
libs. The reported false positive (issue-name-collision-false-positive.md): a charm
vendoring both ``grafana_agent/v0/cos_agent.py`` and ``tls_certificates_interface``
v4 gets a high-confidence ``data → databag`` finding whose origin is a ``set()`` the
charm never touches, because ``DashboardPath40UID.generate`` (a deterministic hash)
picks up ``CertificateRequest.generate``'s unstable summary.

The scenarios below cover the two colliding receiver shapes that must stay clean --
a receiver imported from a module *outside* the scan, and a receiver naming a class
*defined in the same file* -- plus a companion proving the pin must not
blanket-suppress a genuinely unstable callee.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from typing import List

from conftest import details
from flaplint.analyzer import Analyzer
from flaplint.model import Finding


#: The vendored "tls_certificates v4" stand-in: one genuinely unstable
#: ``generate`` (born-unstable -- the set is materialised inside the method, so
#: only a *summary* can carry it to a distant call site) and one deterministic
#: ``generate`` on another class, plus the module-level delegator the charm uses.
_TAINTED = """
    class CertificateRequest:
        @classmethod
        def generate(cls):
            return list({"a", "b"})  # born-unstable: set materialised unsorted


    class PrivateKey:
        @classmethod
        def generate(cls):
            return "stable-key"  # deterministic


    def generate_private_key():
        return PrivateKey.generate()
"""

#: cos_agent shape: the receiver is a class imported from a module *outside* the
#: scan -- its ``generate`` is a deterministic hash, unrelated to the vendored
#: ``CertificateRequest.generate`` that happens to share the name.
_CHARM_IMPORTED = """
    from cosl import DashboardPath40UID


    class Charm:
        def _on_changed(self, event):
            rel = self.model.get_relation("peer")
            uid = DashboardPath40UID.generate()
            rel.data[self.app]["uid"] = uid
"""

#: cert_handler shape: the charm imports the module-level delegator, whose own
#: body calls ``PrivateKey.generate()`` -- a same-file class reference that must
#: not pick up ``CertificateRequest.generate``'s taint.
_CHARM_DELEGATED = """
    from lib.tainted import generate_private_key


    class Charm:
        def _rotate_key(self, event):
            rel = self.model.get_relation("peer")
            key = generate_private_key()
            rel.data[self.unit]["private_key"] = key
"""

#: Companion: the *genuinely* unstable class, imported from the scanned file --
#: calling it must still flag (the pin resolves to the right class, it does not
#: suppress same-name resolution wholesale).
_CHARM_GENUINE = """
    from lib.tainted import CertificateRequest


    class Charm:
        def _on_changed(self, event):
            rel = self.model.get_relation("peer")
            uid = CertificateRequest.generate()
            rel.data[self.app]["uid"] = uid
"""

#: The same-file collision in one file: a deterministic ``generate`` on one class
#: must not inherit the same-named method's instability from a sibling class.
_SAME_FILE = """
    class Unstable:
        @classmethod
        def generate(cls):
            return list({"a", "b"})


    class Stable:
        @classmethod
        def generate(cls):
            return "stable-value"


    class Charm:
        def _on_changed(self, event):
            rel = self.model.get_relation("peer")
            value = Stable.generate()
            rel.data[self.app]["value"] = value
"""


def _write_scan(tmp_path: Path, charm_src: str) -> List[str]:
    """Materialise the GIVEN scenario: a charm plus the vendored lib on disk."""
    (tmp_path / "lib").mkdir()
    (tmp_path / "src").mkdir()
    lib = tmp_path / "lib" / "tainted.py"
    lib.write_text(textwrap.dedent(_TAINTED))
    charm = tmp_path / "src" / "charm.py"
    charm.write_text(textwrap.dedent(charm_src))
    return [str(charm), str(lib)]


def _charm_findings(findings: List[Finding]) -> List[Finding]:
    """Findings whose site is the charm file (not the vendored lib)."""
    return [f for f in findings if "/src/charm.py" in f.path]


def test_imported_class_receiver_does_not_inherit_same_name_taint(tmp_path):
    # GIVEN a scan holding a vendored lib whose ``CertificateRequest.generate``
    # has a born-unstable summary, and a charm that writes
    # ``DashboardPath40UID.generate()`` -- a class imported from a module *outside*
    # the scan -- to the peer databag.
    files = _write_scan(tmp_path, _CHARM_IMPORTED)

    # WHEN the charm and the vendored lib are linted together.
    findings = Analyzer(files, min_confidence="low").run()

    # THEN the databag write stays clean: the external callee contributes no
    # in-scan summary, so the vendored lib's same-named ``generate`` must not
    # union its instability into the call.
    charm_hits = _charm_findings(findings)
    assert charm_hits == [], (
        f"imported-class call should stay clean, got {[f.format() for f in charm_hits]}"
    )


def test_same_file_class_receiver_does_not_inherit_sibling_class_taint(tmp_path):
    # GIVEN one file with two sibling classes whose ``generate`` methods share a
    # name -- one born-unstable, one deterministic -- and a handler writing
    # ``Stable.generate()`` (the deterministic sibling) to the databag.
    charm = tmp_path / "charm.py"
    charm.write_text(textwrap.dedent(_SAME_FILE))

    # WHEN the file is linted on its own.
    findings = Analyzer([str(charm)], min_confidence="low").run()

    # THEN the write stays clean: the receiver names a class defined in this very
    # file, so the call resolves to ``Stable.generate`` alone -- not to the union
    # with sibling ``Unstable.generate``.
    assert findings == [], f"same-file class call should stay clean, got {details(findings)}"


def test_delegating_free_function_stays_clean_across_files(tmp_path):
    # GIVEN the vendored lib from the issue (both ``generate`` methods plus the
    # ``generate_private_key`` delegator), and a charm that imports the delegator
    # and writes its result to the peer databag.
    files = _write_scan(tmp_path, _CHARM_DELEGATED)

    # WHEN the charm and the vendored lib are linted together.
    findings = Analyzer(files, min_confidence="low").run()

    # THEN the private-key write stays clean: inside the lib, the delegator's
    # ``PrivateKey.generate()`` receiver names a same-file class, so it must not
    # pick up ``CertificateRequest.generate``'s taint -- no phantom origin from a
    # lib the value never touched.
    charm_hits = _charm_findings(findings)
    assert charm_hits == [], (
        f"delegated private key should stay clean, got {[f.format() for f in charm_hits]}"
    )


def test_genuinely_unstable_imported_class_still_flags(tmp_path):
    # GIVEN the same vendored lib, and a charm importing the *genuinely* unstable
    # ``CertificateRequest`` from it, writing its ``generate()`` result to the
    # databag.
    files = _write_scan(tmp_path, _CHARM_GENUINE)

    # WHEN the charm and the vendored lib are linted together.
    findings = Analyzer(files, min_confidence="low").run()

    # THEN the databag write is flagged as unordered iteration: pinning the
    # receiver to its imported class must resolve to that class's own summary,
    # not suppress same-name resolution wholesale.
    charm_hits = _charm_findings(findings)
    assert charm_hits, "calling the genuinely unstable CertificateRequest.generate must flag"
    assert all(f.rule == "unordered-iteration" for f in charm_hits)
