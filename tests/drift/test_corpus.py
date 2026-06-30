"""Two guards over the labelled corpus (``corpus.py``).

* ``test_corpus_verdicts`` -- a **regression net**: flaplint's verdict on each snippet
  must match its label. This runs always (no ops needed) and catches engine edits that
  silently change a verdict. flaplint's verdict is the same on every ops version (it
  reads source as text), so this alone cannot see *ops* drift -- that's the next test.

* ``test_corpus_anchor_oracle`` -- the **ops-drift oracle**: every case names the ops
  semantics its verdict assumes; this asserts those assumptions still hold against the
  *installed* ops, and on failure names the cases whose labels would be invalidated.
  Skipped when ops isn't installed. Run it across an ops version matrix
  ({OPS_FLOOR, latest}) in CI -- see ``docs/ops-version-anchoring.md``.
"""

from __future__ import annotations

import textwrap

import pytest

from corpus import ANCHORS, CORPUS, OPS_FLOOR
from flaplint.analyzer import Analyzer

_ANCHOR_BY_ID = {a.id: a for a in ANCHORS}


def _run(tmp_path, case) -> set:
    path = tmp_path / f"{case.id}.py"
    path.write_text(textwrap.dedent(case.code))
    return Analyzer([str(path)], min_confidence="low").run()


@pytest.mark.parametrize("case", CORPUS, ids=lambda c: c.id)
def test_corpus_verdicts(tmp_path, case):
    findings = _run(tmp_path, case)
    got = "flap" if findings else "clean"
    assert got == case.expect, (
        f"{case.id}: expected {case.expect}, got {got} "
        f"({[f.format() for f in findings]})"
    )
    if case.rule and case.expect == "flap":
        rules = {f.rule for f in findings}
        assert case.rule in rules, f"{case.id}: expected rule {case.rule}, saw {sorted(rules)}"


def test_every_case_anchor_is_registered():
    # An assumption a case relies on must be documented in ANCHORS, so the oracle can
    # check it. A typo'd or undeclared anchor is a silent hole -- fail loudly.
    for case in CORPUS:
        for aid in case.anchors:
            assert aid in _ANCHOR_BY_ID, f"{case.id}: unregistered anchor {aid!r}"


def test_no_dead_anchors():
    # Every registered anchor should be exercised by at least one case (else it's
    # untested documentation that can rot).
    used = {aid for case in CORPUS for aid in case.anchors}
    assert set(_ANCHOR_BY_ID) == used, f"unused anchors: {sorted(set(_ANCHOR_BY_ID) - used)}"


def test_corpus_anchor_oracle():
    """Ops drift detector: assert each case's ops assumptions hold against installed ops.

    A failure means an ops change has invalidated some corpus labels -- the message
    lists exactly which cases now have the wrong verdict, so you know what to re-label
    (or which engine rule to make version-aware). This is the *only* test that can see
    ops semantic drift, because flaplint's own verdict never moves with the ops version.
    """
    ops = pytest.importorskip("ops")
    version = getattr(getattr(ops, "version", None), "version", "?")

    failures = []
    for anchor in ANCHORS:
        if anchor.check is None:
            continue  # frozen stdlib/language assumption -- no runtime check
        try:
            ok = bool(anchor.check(ops))
        except Exception as exc:  # an anchor that can't even be evaluated has drifted
            ok = False
            anchor_err = f" ({type(exc).__name__}: {exc})"
        else:
            anchor_err = ""
        if not ok:
            affected = [c.id for c in CORPUS if anchor.id in c.anchors]
            failures.append(
                f"  - {anchor.id} ({anchor.desc}; {anchor.holds_for}){anchor_err}\n"
                f"    invalidates: {', '.join(affected)}"
            )

    assert not failures, (
        f"ops {version} (floor {OPS_FLOOR}) has drifted from anchored semantics; "
        f"these assumptions no longer hold and the listed cases are now mislabelled:\n"
        + "\n".join(failures)
    )
