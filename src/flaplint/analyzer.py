"""High-level orchestration: paths in, findings out.

:class:`Analyzer` ties the passes together -- discovery, collection, summary
fixed point, reporting, confidence filtering -- behind a small, importable API.
A fresh :class:`~flaplint.taint.TaintEngine` is built per run, so two
analyses with different options never share state.
"""

from __future__ import annotations

import ast
import os
import sys
from typing import Dict, List, Sequence, Set

from .collector import Collector
from .constants import CONFIDENCE_RANK, KIND_RANK, SUPPRESS_COMMENT
from .discovery import (
    auto_interpreter,
    candidate_venvs,
    discover_site_packages,
    filter_sink_roots,
    gather_py_files,
    imported_top_levels,
    interpreter_module_paths,
    owned_lib_dirs,
    read_source,
    sibling_libs,
    sink_dep_roots,
)
from .model import FileImports, Finding, FuncInfo, Registry
from .report import report
from .summary import compute_summaries, mark_databag_accessors
from .taint import TaintEngine
from .traversal import FunctionAnalyzer


class Analyzer:
    """Configurable, reusable charm relation-databag ordering analyzer.

    Parameters mirror the command-line flags. After :meth:`run`, the
    ``primary_files`` and ``secondary_files`` attributes report what was scanned
    (useful for a summary line).
    """

    def __init__(
        self,
        paths: Sequence[str],
        *,
        deps: Sequence[str] = (),
        venvs: Sequence[str] = (),
        resolve_deps: bool = True,
        python: str = "",
        report_deps: bool = True,
        relations_unordered: bool = False,
        min_confidence: str = "medium",
        sort: str = "criticality",
        explain_gaps: bool = False,
    ) -> None:
        self.paths = list(paths)
        self.deps = list(deps)
        self.venvs = list(venvs)
        #: automatically discover the charm's dependency environment (a sibling
        #: ``.venv`` interpreter, else its site-packages) and trace the deps that
        #: write relation data. On by default; disabled with ``--no-deps``.
        self.resolve_deps = resolve_deps
        self.python = python
        self.report_deps = report_deps
        self.relations_unordered = relations_unordered
        self.min_confidence = min_confidence
        self.sort = sort
        self.explain_gaps = explain_gaps
        self.primary_files: List[str] = []
        self.secondary_files: List[str] = []
        self.gaps: List = []

    def run(self) -> List[Finding]:
        """Execute every pass and return the filtered, sorted findings."""
        primary_roots = list(self.paths) + list(self.deps)
        primary_roots += sibling_libs(self.paths)  # always include sibling lib/
        primary_files = set(gather_py_files(primary_roots, include_tests=False))
        self.primary_files = sorted(primary_files)

        secondary_roots = discover_site_packages(self.venvs)  # explicit --venv
        if self.resolve_deps:
            imported = imported_top_levels(self.primary_files)
            # Prefer an interpreter (explicit --python, else an auto-picked sibling
            # .venv's bin/python): it follows PEP 420 namespace packages that a bare
            # folder scan misses. Fall back to folder-scanning the sibling venv's
            # site-packages when no interpreter is available (e.g. an unpacked .charm).
            python = self.python or auto_interpreter(self.paths)
            if python:
                resolved = interpreter_module_paths(python, imported)
                secondary_roots = sorted(
                    set(secondary_roots) | set(filter_sink_roots(resolved))
                )
            else:
                site_packages = secondary_roots or discover_site_packages(
                    candidate_venvs(self.paths)
                )
                secondary_roots = sink_dep_roots(site_packages, imported)

        secondary_files = set(gather_py_files(secondary_roots, include_tests=False))
        # Drop any secondary file that is really a primary file reached under a
        # different path spelling -- an *editable* install (``pip install -e``)
        # resolves a package back to the charm's own ``src``, so the interpreter
        # returns absolute paths that string-differ from the relative primary
        # paths. Compare by ``realpath`` so those are not analysed (and reported)
        # twice.
        primary_real = {os.path.realpath(p) for p in primary_files}
        secondary_files = {
            f for f in secondary_files if os.path.realpath(f) not in primary_real
        }
        self.secondary_files = sorted(secondary_files)

        registry: Registry = {}
        class_attr_types: Dict[str, Dict[str, str]] = {}
        model_seq_fields: Dict[str, Set[str]] = {}
        class_set_fields: Dict[str, Set[str]] = {}
        file_imports: Dict[str, FileImports] = {}
        functions: List[FuncInfo] = []
        suppressed: Dict[str, Set[int]] = {}

        for path in self.primary_files:
            self._ingest(
                path, True, registry, class_attr_types, model_seq_fields,
                class_set_fields, file_imports, functions, suppressed,
            )
        for path in self.secondary_files:
            self._ingest(
                path, False, registry, class_attr_types, model_seq_fields,
                class_set_fields, file_imports, functions, suppressed,
            )

        engine = TaintEngine(
            registry,
            class_attr_types,
            relations_unordered=self.relations_unordered,
            file_imports=file_imports,
            model_seq_fields=model_seq_fields,
            class_set_fields=class_set_fields,
        )
        analyzer = FunctionAnalyzer(engine)
        mark_databag_accessors(functions, registry)
        compute_summaries(functions, analyzer)
        findings, gaps = report(functions, analyzer, suppressed, self.explain_gaps)

        threshold = CONFIDENCE_RANK[self.min_confidence]
        findings = [f for f in findings if CONFIDENCE_RANK[f.confidence] >= threshold]
        if self.sort == "location":
            findings.sort(key=lambda f: (f.path, f.line, f.col))
        else:  # "criticality": most severe first, location as a stable tie-break.
            findings.sort(
                key=lambda f: (
                    f.level != "error",  # actionable (charm-owned) errors first
                    -CONFIDENCE_RANK[f.confidence],
                    KIND_RANK.get(f.kind, 99),
                    f.path,
                    f.line,
                    f.col,
                )
            )
        self._classify_levels(findings)
        self._relativize(findings)
        cwd = os.getcwd()
        for g in gaps:
            g.path = os.path.relpath(os.path.abspath(g.path), cwd)
        self.gaps = gaps
        return findings

    def _classify_levels(self, findings: List[Finding]) -> None:
        """Tag each finding ``error`` (charm-owned fix) or ``warning`` (dependency).

        A finding is an **error** when its fix lives in code the charm owns -- a
        file/directory the user explicitly pointed at (a positional ``paths``
        argument) or the charm's own ``lib/charms/<name>/`` namespace. Everything
        else -- a *vendored* copy of another charm's library (whether reached via
        the auto-included sibling ``lib/`` or an explicit ``--dep``), or an
        installed dependency reported by default (unless ``--no-report-deps``) -- is
        a **warning**: real, but not the charm's to fix, so it must not fail CI.

        ``--dep`` only adds a root to *analyze and report*; it never changes a
        finding's level. Ownership is decided purely by location (own ``src`` or
        own charm-lib namespace), so a vendored lib reported via ``--dep`` stays a
        warning, while the charm's own lib stays an error.

        Runs before :meth:`_relativize`, while ``f.path`` is still absolute.
        """
        owned_roots: Set[str] = set()
        for p in list(self.paths):
            ap = os.path.abspath(p)
            if os.path.isfile(ap):
                owned_roots.add(os.path.dirname(ap))
            elif os.path.basename(ap) != "src" and os.path.isdir(
                os.path.join(ap, "src")
            ):
                # A charm root was pointed at: only its own src/ is owned, not the
                # vendored lib/ that sits beside it.
                owned_roots.add(os.path.join(ap, "src"))
            else:
                owned_roots.add(ap)
        owned_libs = [os.path.abspath(d) for d in owned_lib_dirs(self.paths)]

        def _under(ap: str, root: str) -> bool:
            return ap == root or ap.startswith(root + os.sep)

        for f in findings:
            ap = os.path.abspath(f.path)
            owned = any(_under(ap, r) for r in owned_roots) or any(
                _under(ap, d) for d in owned_libs
            )
            f.level = "error" if owned else "warning"

    def _relativize(self, findings: List[Finding]) -> None:
        """Rewrite every finding's path relative to the current directory.

        One consistent, click-to-navigate style for *all* findings -- a charm's
        own ``src/coordinator/src/mimir_config.py`` reads the same way as a
        vendored ``.../lib/charms/foo/v0/foo.py`` -- so the path always points
        somewhere you can open from where you ran the linter.
        """
        cwd = os.getcwd()
        for f in findings:
            f.path = os.path.relpath(os.path.abspath(f.path), cwd)
            if f.origin_path:
                f.origin_path = os.path.relpath(os.path.abspath(f.origin_path), cwd)
            if f.sink_path:
                f.sink_path = os.path.relpath(os.path.abspath(f.sink_path), cwd)

    def _ingest(
        self,
        path: str,
        primary: bool,
        registry: Registry,
        class_attr_types: Dict[str, Dict[str, str]],
        model_seq_fields: Dict[str, Set[str]],
        class_set_fields: Dict[str, Set[str]],
        file_imports: Dict[str, FileImports],
        functions: List[FuncInfo],
        suppressed: Dict[str, Set[int]],
    ) -> None:
        source = read_source(path)
        if source is None:
            return
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError as exc:
            print(f"warning: skipping {path}: {exc}", file=sys.stderr)
            return
        suppressed[path] = {
            i + 1
            for i, line in enumerate(source.splitlines())
            if SUPPRESS_COMMENT in line
        }
        report_here = primary or self.report_deps
        collector = Collector(
            path, report_here, registry, class_attr_types, file_imports,
            model_seq_fields=model_seq_fields,
            class_set_fields=class_set_fields,
        )
        collector.visit(tree)
        functions.extend(collector.functions)
        # Module-level code is its own (parameterless) scope.
        functions.append(
            FuncInfo(name="<module>", path=path, node=tree, primary=report_here)
        )


def analyze_paths(
    paths: Sequence[str],
    *,
    deps: Sequence[str] = (),
    venvs: Sequence[str] = (),
    resolve_deps: bool = True,
    python: str = "",
    report_deps: bool = True,
    relations_unordered: bool = False,
    min_confidence: str = "medium",
    sort: str = "criticality",
) -> List[Finding]:
    """Convenience wrapper: build an :class:`Analyzer`, run it, return findings."""
    return Analyzer(
        paths,
        deps=deps,
        venvs=venvs,
        resolve_deps=resolve_deps,
        python=python,
        report_deps=report_deps,
        relations_unordered=relations_unordered,
        min_confidence=min_confidence,
        sort=sort,
    ).run()
