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

from .model import Finding

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
    "unordered-pick": "positional pick from unordered data",
    "nondeterministic": "nondeterministic value",
}

#: Where the unstable value lands, keyed by sink family.
_SINK_TARGET: Dict[str, str] = {
    "databag": "the relation databag",
    "file": "an on-disk file",
    "hash": "a content hash",
}



#: Friendly label for the sink family shown inline in the header.
_SINK_LABEL: Dict[str, str] = {
    "databag": "databag",
    "file": "on-disk file",
    "hash": "content hash",
}


def _describe(f: Finding) -> str:
    """A concrete, single-sentence explanation built from *this* finding.

    Names the affected variable and sink, weaves in the born-at/via provenance
    when present, rather than printing a generic per-rule blurb.
    """
    subject = f"`{f.variable}`" if f.variable else "this variable"
    target = _SINK_TARGET.get(f.sink, "the databag")

    # A content hash and an on-disk file are both *change-detectors*: the charm
    # diffs them against the previous reconcile to decide whether to do expensive
    # work (restart / replan / re-sync / re-publish / further I/O). If the value
    # behind them has no stable byte-order, the detector differs every reconcile
    # and the gate trips spuriously -- so the *feeding of unstable content into
    # them* is the sink, not any single downstream use.
    is_detector = f.sink in ("hash", "file")

    if f.rule == "unordered-collection":
        if is_detector:
            core = (
                f"{subject} is an unordered data structure fed into {target} "
                "without sorted(), so any change-detection built on it trips."
            )
        else:
            core = (
                f"{subject} is an unordered data structure serialised into {target} "
                "without sorted()."
            )
    elif f.rule == "unordered-pick":
        core = (
            f"{subject} is selected by position from unordered data structure before it "
            f"reaches {target}, so the selected element may vary between runs."
        )
    elif f.rule == "nondeterministic":
        if is_detector:
            core = (
                f"{subject} is regenerated every hook execution before it is fed into "
                f"{target}, so any change-detection built on it trips."
            )
        else:
            core = (
                f"{subject} is regenerated every hook execution before it reaches {target}."
            )
    else:
        core = f"{subject} reaches {target} in a nondeterministic form."

    sentence = core

    if f.origin_path:
        origin = f"{_relpath(f.origin_path)}:{f.origin_line}"
        if f.via:
            sentence += (
                f" The value assigned to {subject} originates from "
                f"`{f.via}()` at {origin}."
            )
        else:
            sentence += (
                f" The value assigned to {subject} originates at {origin}."
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
        n_err = sum(1 for f in group if f.level == "error")
        n_warn = len(group) - n_err
        counts = []
        if n_err:
            counts.append(p.red(f"{n_err} error(s)"))
        if n_warn:
            counts.append(p.yellow(f"{n_warn} warning(s)"))
        header = p.bold(p.underline(_relpath(path))) + "  " + p.dim(
            "· " + ", ".join(counts)
        )
        out.append(header)

        loc_w = max(len(f"{f.line}:{f.col}") for f in group)
        body_indent = " " * (6 + loc_w)

        for f in group:
            is_err = f.level == "error"
            mark = p.red("✖") if is_err else p.yellow("▲")
            loc = f"{f.line}:{f.col}".rjust(loc_w)
            title = _RULE_TITLE.get(f.rule, f.rule)
            var = p.cyan(f.variable) if f.variable else p.dim("<anonymous>")
            sink = _SINK_LABEL.get(f.sink, f.sink)
            conf_paint = {"high": p.red, "medium": p.yellow, "low": p.blue}.get(
                f.confidence, p.dim
            )
            conf_tag = conf_paint(f"[{f.confidence}]")

            out.append(
                f"  {mark} {p.dim(loc)}  {p.bold(title)} "
                f"{p.dim('·')} {var} {p.dim('→ ' + sink)}  {conf_tag}"
            )

            out.append(p.dim(_wrap(_describe(f), body_indent, width)))



        out.append("")

    out.append(_summary(findings, files_scanned, p))
    out.append("")
    return "\n".join(out)


def _summary(findings: Sequence[Finding], files_scanned: int, p: _Palette) -> str:
    errors = sum(1 for f in findings if f.level == "error")
    warnings = len(findings) - errors
    rule = p.dim("─" * 56)

    parts = [p.red("✖") + f" {len(findings)} problem(s)"]
    parts.append(p.red(f"{errors} error(s)"))
    if warnings:
        parts.append(p.yellow(f"{warnings} warning(s)"))
    parts.append(p.dim(f"· {files_scanned} file(s) scanned"))
    summary = "  " + "   ".join(parts)

    # legend = "  " + p.dim(
    #     "✖ you own this code     ▲ in a dependency — non-blocking"
    # )
    return rule + "\n" + summary + "\n"
