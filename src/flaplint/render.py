"""Human-facing rendering of findings: a grouped, colourised terminal report.

The machine-parseable one-line form lives on :meth:`flaplint.model.Finding.format`
(used by editors, ``grep`` and the test suite). This module is the *pretty*
counterpart the CLI prints by default: findings grouped by file, aligned, colour-
coded by who-can-fix-it, and annotated with a plain-English "what / why / fix" so
a reader understands a finding without memorising the rule vocabulary.

Everything degrades gracefully: colour is emitted only to a TTY (honouring the
``NO_COLOR`` / ``FORCE_COLOR`` conventions), and the layout is plain UTF-8 text.
"""

from __future__ import annotations

import os
import shutil
import textwrap
from typing import Dict, List, Sequence

from .model import Finding, Gap

# -- colour ------------------------------------------------------------------


def colour_enabled(stream) -> bool:
    """Decide whether to emit ANSI colour for *stream*.

    Follows the ``NO_COLOR`` (https://no-color.org) and ``FORCE_COLOR``
    conventions, otherwise enables colour only when writing to a real terminal.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return bool(getattr(stream, "isatty", None) and stream.isatty())


class _Palette:
    """Tiny ANSI helper that no-ops when colour is disabled."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def paint(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, s: str) -> str:
        return self.paint("1", s)

    def dim(self, s: str) -> str:
        return self.paint("2", s)

    def red(self, s: str) -> str:
        return self.paint("31", s)

    def green(self, s: str) -> str:
        return self.paint("32", s)

    def yellow(self, s: str) -> str:
        return self.paint("33", s)

    def blue(self, s: str) -> str:
        return self.paint("38;5;39", s)

    def cyan(self, s: str) -> str:
        return self.paint("36", s)

    def underline(self, s: str) -> str:
        return self.paint("4", s)


# -- per-rule plain-English copy ---------------------------------------------

#: Short human title for each failure mode (``rule``).
_RULE_TITLE: Dict[str, str] = {
    "unordered-collection": "unordered collection",
    "unordered-pick": "position-dependent value from unordered data",
    "unordered-iteration": "unsorted iteration into a sequence",
    "nondeterministic": "nondeterministic value",
}

#: Where the unstable value lands, keyed by sink family.
_SINK_TARGET: Dict[str, str] = {
    "databag": "the relation databag",
    "file": "an on-disk file",
    "hash": "a content hash",
    "plan": "a pebble plan",
    "render": "rendered workload config",
    "secret": "a Juju secret",
}



#: Friendly label for the sink family shown inline in the header.
_SINK_LABEL: Dict[str, str] = {
    "databag": "databag",
    "file": "on-disk file",
    "hash": "content hash",
    "plan": "pebble plan",
    "render": "rendered config",
    "secret": "juju secret",
}

#: The exit-code axis (``level``) is about *responsibility*, not severity -- yet
#: "error/warning" reads like a severity that then clashes with the separate
#: confidence axis ("a warning, but high?"). So the UI speaks about ownership
#: instead: an ``error`` is code the charm owns (yours; fails the run), a
#: ``warning`` lives in a dependency (not yours; non-blocking). Per finding this
#: rides the ✖/▲ mark and the footer legend; the summary tally spells it out.
_OWNER_TOTAL: Dict[str, str] = {  # bottom summary tally
    "error": "yours",
    "warning": "in dependencies",
}


def _describe(f: Finding) -> str:
    """A concrete, single-sentence explanation built from *this* finding.

    Names the affected variable and sink, weaves in the born-at/via provenance
    when present, rather than printing a generic per-rule blurb.
    """
    if f.variable:
        subject = f"`{f.variable}`"
    elif f.scope:
        # No nameable variable -- an anonymous ``return list(set(...))``. Name the
        # enclosing function/property instead (that is where the ``sorted()`` goes)
        # rather than the useless ``this variable``.
        subject = f"the value returned by `{f.scope}`"
    else:
        subject = "this variable"
    target = _SINK_TARGET.get(f.sink, "the databag")

    # Weave the sink location straight into the mention of the target -- "written
    # to X at file:line" -- so it reads as one natural clause instead of a
    # trailing "It reaches ..." afterthought. Only when the finding sits at a
    # *fix site* away from the write (a pick / an iteration) does ``sink_line``
    # point somewhere the header doesn't already show; when the finding *is* the
    # write, its own line:col is in the header, so naming it again is just noise.
    if f.sink_line:
        where = (
            f"{_relpath(f.sink_path)}:{f.sink_line}" if f.sink_path
            else f"line {f.sink_line}"
        )
        target_at = f"{target} at {where}"
    else:
        target_at = target

    # A content hash, an on-disk file, a pebble plan and a rendered config blob
    # are all *change-detectors*: the charm diffs them against the previous
    # reconcile to decide whether to do expensive work (restart / replan /
    # re-sync / re-publish / further I/O). If the value behind them has no stable
    # byte-order, the detector differs every reconcile and the gate trips
    # spuriously -- so the *feeding of unstable content into them* is the sink,
    # not any single downstream use.
    is_detector = f.sink in ("hash", "file", "plan", "render")

    if f.rule == "unordered-collection":
        if is_detector:
            core = (
                f"{subject} is an unordered collection written to {target_at} "
                "without first being sorted."
            )
        else:
            core = f"{subject} is an unordered collection written to {target_at}."
    elif f.rule == "unordered-pick":
        if f.origin_path and _relpath(f.origin_path) != _relpath(f.path):
            # Re-attributed downstream of the pick (cross-file): the subject is the
            # value that *carries* the picked element to the sink here, not the pick
            # itself -- so don't claim it "is selected by position". The upstream
            # trail below names where the positional pick actually happens.
            core = (
                f"{subject} carries a value picked by position from an unordered "
                f"collection upstream before reaching {target_at}, so a different "
                f"element may be selected on different runs."
            )
        else:
            # Same-file pick. Two shapes reach here and both must read correctly:
            # a literal subscript (``addrs[0]``) *and* an ``enumerate`` value target
            # (``for idx, e in enumerate(x): d[f"loki-{idx}"] = e``), where each
            # element is bound to a position rather than one being plucked. So don't
            # claim "{subject} is selected by position" (which reads as a single
            # ``subject[N]``); say a value is taken *by position from* {subject},
            # which is true either way. The fix is identical: sort the collection at
            # the source, before it is indexed or enumerated.
            core = (
                f"a value taken by position from {subject} (an unordered collection) "
                f"reaches {target_at}."
            )
    elif f.rule == "unordered-iteration":
        if f.kind == "caller" and f.origin_path and _relpath(f.origin_path) != _relpath(f.path):
            # Cross-file: the born site -- where the disorder is baked in by an
            # unsorted iteration -- is upstream in another file. The subject *here*
            # is not the thing being iterated; it is a *carrier* (typically a
            # rendered string, a ``json.dumps`` result, or a stored-state read-back)
            # that transports the already-ordered-by-accident sequence to this sink.
            # So don't claim it "is an unordered source iterated" at this line (it
            # may not even be a collection -- ``_nginx_config()`` returns a str). The
            # "Fix at the source" trail below names where the iteration truly is.
            # Mirrors the cross-file carrier branch of ``unordered-pick`` above.
            core = (
                f"{subject} carries a value whose element order was baked in by an "
                f"unsorted iteration, before it reaches {target_at}."
            )
        elif f.via_param:
            # Confirmed contract boundary: the iterated value is a *parameter* fed an
            # unordered collection by a caller (there may be several, so no single born
            # site). Don't imply the parameter is intrinsically unordered -- name the
            # caller boundary, which is the "why" a reader can't see from this line,
            # and give both fixes (sort here, or tighten the parameter's type so
            # callers must pass an ordered collection).
            core = (
                f"a caller passes an unordered collection into {subject} (a parameter), "
                f"and iterating it without sorted() bakes that disorder into a sequence "
                f"written to {target_at}. Sort at the iteration (sorted({subject})), or "
                f"annotate {subject} as dict/list so callers must pass an ordered type."
            )
        elif f.kind == "caller":
            # Confirmed *and* born here: an unordered value is iterated at this very
            # line. The subject is the source being looped, not the sequence built
            # from it, so say plainly that iterating it bakes the disorder into
            # element order. Any "Fix at the source" trail below points at where that
            # source is born (a same-file helper, when present).
            core = (
                f"{subject} is an unordered source iterated without sorted() to "
                f"build a sequence written to {target_at}."
            )
        else:
            # Precautionary contract boundary: we cannot see, from this function,
            # whether callers pass an unordered collection -- but if any does, the
            # element order flaps. Say so plainly, and name the escape hatches.
            core = (
                f"{subject} is iterated without sorted() to build a sequence written to {target_at}. "
                f"Sort at the iteration (sorted({subject})), or "
                f"annotate {subject} as dict/list if callers already guarantee order."
            )
    elif f.rule == "nondeterministic":
        if f.sink == "hash" and f.variable == "hash()":
            # Salted builtin hash(): the instability is the hash *call* itself, not
            # any value inside it, so don't name a single subject -- explain that the
            # builtin hash() is nondeterministic across Juju hooks.
            core = (
                "The builtin hash() returns a different value on every Juju hook even "
                "when the hashed content is identical. "
            )
        elif is_detector:
            core = (
                f"{subject} is freshly generated each time this code runs, so when this "
                f"path executes it feeds a different value into {target_at} and any "
                "change-detection built on it trips."
            )
        else:
            core = (
                f"{subject} is freshly generated each time this code runs, so when this "
                f"path executes the value written to {target_at} differs from last time "
                "(sorting cannot fix it). If that write is intentional, suppress it with "
                "`# databag-order: ignore`."
            )
    else:
        core = f"{subject} reaches {target_at} in a nondeterministic form."

    sentence = core

    # Context-sensitive finding: this flow is invisible to a static read of the
    # base class -- it only exists because ``self.<attr>`` is a concrete subclass at
    # runtime (fixed by the constructor), whose override differs from the declared
    # base type. Spell that out so the reader understands *why* it reaches the sink
    # (the polymorphism was the non-obvious step).
    if f.via_subclass:
        attr = f"`self.{f.via_attr}`" if f.via_attr else "the receiver"
        sentence += (
            f" At runtime, {attr} is actually a `{f.via_subclass}`, so the subclass's "
            f"implementation is used here instead of the one defined on the annotated "
            f"base class."
        )

    if f.origin_path:
        origin = f"{_relpath(f.origin_path)}:{f.origin_line}"
        if f.via:
            # The born site is in another function, reached through one or more
            # call/return/attribute hops -- so this is NOT a direct
            # ``subject = via()`` assignment. Say "upstream" and "fix it there" so
            # the reader looks at the source, not for a call next to this write.
            sentence += (
                f" Fix at the source: the instability is created upstream in "
                f"`{f.via}()` ({origin})."
            )
        else:
            sentence += (
                f" The instability is created at {origin}; fix it there."
            )
    return sentence



def _relpath(path: str) -> str:
    try:
        rel = os.path.relpath(path)
    except ValueError:  # e.g. different drive on Windows
        return path
    return rel if not rel.startswith("..") else path


def _wrap(text: str, indent: str, width: int) -> str:
    return textwrap.fill(
        text,
        width=max(width, 40),
        initial_indent=indent,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    )


def render_report(
    findings: Sequence[Finding],
    files_scanned: int,
    *,
    colour: bool = True,
    width: int = 0,
) -> str:
    """Return the full pretty report for *findings* as a single string."""
    p = _Palette(colour)
    if width <= 0:
        width = min(shutil.get_terminal_size(fallback=(90, 24)).columns, 100)

    banner = (
        p.bold("flaplint") + "  " + p.dim("· charm flapping checker")
    )

    if not findings:
        body = (
            "\n"
            + banner
            + "\n\n  "
            + p.green("✔ ")
            + p.bold("No flapping risks found")
            + "  "
            + p.dim(f"· {files_scanned} file(s) scanned")
            + "\n"
        )
        return body

    # Group by file, preserving the (already-sorted) first-appearance order so
    # the chosen --sort (criticality or location) still drives which file leads.
    groups: "Dict[str, List[Finding]]" = {}
    for f in findings:
        groups.setdefault(f.path, []).append(f)

    out: List[str] = ["", banner, ""]

    for path, group in groups.items():
        # Just the filename: ownership and confidence now ride each finding's
        # header line, and a per-file count would only echo them.
        out.append(p.bold(p.underline(_relpath(path))))

        loc_w = max(len(f"{f.line}:{f.col}") for f in group)
        body_indent = " " * (6 + loc_w)

        for f in group:
            is_err = f.level == "error"
            mark = p.red("✖") if is_err else p.yellow("▲")
            loc = f"{f.line}:{f.col}".rjust(loc_w)
            title = _RULE_TITLE.get(f.rule, f.rule)
            # Prefer a named variable; else the enclosing function/property (where the
            # fix goes); only truly anonymous values fall back to ``<anonymous>``.
            if f.variable:
                var = p.cyan(f.variable)
            elif f.scope:
                var = p.cyan(f.scope + "()")
            else:
                var = p.dim("<anonymous>")
            sink = _SINK_LABEL.get(f.sink, f.sink)
            conf_paint = {"high": p.red, "medium": p.yellow, "low": p.blue}.get(
                f.confidence, p.dim
            )

            # Header line ends with the confidence (how sure flaplint is). Ownership
            # (whose job the fix is) rides the ✖/▲ mark and the footer legend, so it
            # isn't repeated here as words that could read like a second severity.
            out.append(
                f"  {mark} {p.dim(loc)}  {p.bold(title)} "
                f"{p.dim('·')} {var} {p.dim('→ ' + sink)}  "
                f"{p.dim('·')} {conf_paint(f'{f.confidence} confidence')}"
            )
            out.append(p.dim(_wrap(_describe(f), body_indent, width)))



        out.append("")

    out.append(_summary(findings, files_scanned, p))
    out.append("")
    return "\n".join(out)


def render_gaps(gaps: Sequence[Gap], *, colour: bool = True, width: int = 0) -> str:
    """Render the blind-spot section for ``--explain-gaps`` as a string.

    Gaps are *not* findings -- they're writes whose content flaplint couldn't fully
    trace, so they're where a missed flap could hide. Grouped by file, marked `?`,
    each with the un-traced expression and a plain reason. Never affects the exit
    code; it's a worklist for auditing the tool's own coverage.
    """
    p = _Palette(colour)
    if width <= 0:
        width = min(shutil.get_terminal_size(fallback=(90, 24)).columns, 100)

    banner = p.bold("flaplint") + "  " + p.dim("· blind spots (writes it couldn't fully trace)")
    if not gaps:
        return (
            "\n" + banner + "\n\n  " + p.green("✔ ")
            + "Every write's content was fully traced" + "\n"
        )

    groups: "Dict[str, List[Gap]]" = {}
    for g in gaps:
        groups.setdefault(g.path, []).append(g)

    out: List[str] = ["", banner, ""]
    for path, group in groups.items():
        out.append(p.bold(p.underline(_relpath(path))))
        loc_w = max(len(f"{g.line}:{g.col}") for g in group)
        body_indent = " " * (6 + loc_w)
        for g in group:
            loc = f"{g.line}:{g.col}".rjust(loc_w)
            out.append(
                f"  {p.yellow('?')} {p.dim(loc)}  {p.bold(g.sink + ' write')} "
                f"{p.dim('· ' + (g.snippet or ''))}"
            )
            out.append(p.dim(_wrap(g.reason, body_indent, width)))
        out.append("")

    out.append(p.dim("─" * 56))
    out.append(
        "  " + p.yellow(f"? {len(gaps)} blind spot(s)")
        + p.dim("   · not failures — places a missed flap could hide, review each")
    )
    out.append("")
    return "\n".join(out)


def _summary(findings: Sequence[Finding], files_scanned: int, p: _Palette) -> str:
    errors = sum(1 for f in findings if f.level == "error")
    warnings = len(findings) - errors
    rule = p.dim("─" * 56)

    parts = [p.red("✖") + f" {len(findings)} flap risk(s)"]
    if errors:
        parts.append(p.red(f"{errors} {_OWNER_TOTAL['error']}"))
    if warnings:
        parts.append(p.yellow(f"{warnings} {_OWNER_TOTAL['warning']}"))
    parts.append(p.dim(f"· {files_scanned} file(s) scanned"))
    summary = "  " + "   ".join(parts)

    # Spell out the two marks so the ownership axis is never read as severity:
    # confidence (how sure) is a separate word on each finding's meta line.
    legend = (
        "  " + p.red("✖") + p.dim(" yours — fails the run     ")
        + p.yellow("▲") + p.dim(" in a dependency — non-blocking")
    )
    return rule + "\n" + summary + "\n" + legend + "\n"
