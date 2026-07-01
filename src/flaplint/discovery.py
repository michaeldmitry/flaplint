"""Filesystem discovery: turn user-supplied paths into source files to scan.

These helpers locate the charm sources, their sibling ``lib/`` directories, and
optional dependency site-packages, and read files defensively (a single
unreadable or syntactically-broken file must not abort the whole run).
"""

from __future__ import annotations

import ast
import glob
import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Optional, Set

from .astutils import (
    databag_mutation_args,
    databag_save_content,
    is_databag_target,
)


#: A top-level ``name: <charm>`` line in charmcraft.yaml / metadata.yaml.
_CHARM_NAME_RE = re.compile(r"^name:\s*([A-Za-z0-9_.-]+)", re.MULTILINE)


def gather_py_files(roots: List[str], include_tests: bool) -> List[str]:
    """All ``*.py`` under ``roots`` (files or dirs), test files optionally pruned."""
    files: List[str] = []
    for path in roots:
        if os.path.isfile(path) and path.endswith(".py"):
            files.append(path)
            continue
        if not os.path.isdir(path):
            continue
        for root, _, names in os.walk(path):
            for name in names:
                if name.endswith(".py"):
                    files.append(os.path.join(root, name))
    if not include_tests:
        files = [
            f
            for f in files
            if "/tests/" not in f.replace(os.sep, "/")
            and not os.path.basename(f).startswith("test_")
            and os.path.basename(f) != "conftest.py"
        ]
    return sorted(set(files))


def sibling_libs(paths: List[str]) -> List[str]:
    """For a charm ``src`` (or charm root), include its ``lib`` directory too."""
    extra: List[str] = []
    for path in paths:
        norm = os.path.normpath(path)
        if os.path.basename(norm) == "src":
            sib = os.path.join(os.path.dirname(norm), "lib")
        else:
            sib = os.path.join(norm, "lib")
        if os.path.isdir(sib):
            extra.append(sib)
    return extra


def charm_root(path: str) -> str:
    """Best-effort charm directory for a scanned ``path``.

    ``charm/src`` and ``charm/src/foo.py`` both resolve to ``charm/``; a bare
    charm directory resolves to itself. Used to locate the charm's metadata and
    its owned ``lib/`` namespace.
    """
    norm = os.path.normpath(os.path.abspath(path))
    if os.path.isfile(norm):
        norm = os.path.dirname(norm)
    if os.path.basename(norm) == "src":
        return os.path.dirname(norm)
    return norm


def charm_name(root: str) -> Optional[str]:
    """The charm's declared name, from charmcraft.yaml or metadata.yaml."""
    for fname in ("charmcraft.yaml", "metadata.yaml"):
        meta = os.path.join(root, fname)
        if not os.path.isfile(meta):
            continue
        source = read_source(meta)
        if source is None:
            continue
        match = _CHARM_NAME_RE.search(source)
        if match:
            return match.group(1)
    return None


def owned_lib_dirs(paths: List[str]) -> List[str]:
    """The ``lib/charms/<own-namespace>`` directory each scanned charm owns.

    A charm owns the charm-lib namespace matching its own name (``mimir-coord``
    -> ``lib/charms/mimir_coord/``); every *other* ``lib/charms/<x>/`` is a
    *vendored* copy of someone else's library, which the charm cannot fix.
    """
    dirs: List[str] = []
    for path in paths:
        root = charm_root(path)
        name = charm_name(root)
        if not name:
            continue
        owned = os.path.join(root, "lib", "charms", name.replace("-", "_"))
        if os.path.isdir(owned) and owned not in dirs:
            dirs.append(owned)
    return dirs


def discover_site_packages(venv_paths: List[str]) -> List[str]:
    """Resolve ``--venv`` arguments to concrete ``site-packages`` directories."""
    out: List[str] = []
    for venv in venv_paths:
        norm = os.path.normpath(venv)
        if os.path.basename(norm) == "site-packages":
            out.append(norm)
            continue
        out.extend(glob.glob(os.path.join(norm, "lib", "python*", "site-packages")))
        out.extend(
            glob.glob(os.path.join(norm, "**", "site-packages"), recursive=True)
        )
    return sorted(set(out))


def read_source(path: str) -> Optional[str]:
    """Read a file as UTF-8, warning (not raising) on I/O error."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError as exc:
        print(f"warning: cannot read {path}: {exc}", file=sys.stderr)
        return None


def candidate_venvs(paths: List[str]) -> List[str]:
    """Best-effort guess of virtualenvs sitting beside the charm being scanned.

    For each scanned path we look for a conventional ``.venv`` or ``venv``
    directory in the path itself and in its parent (so both ``charm/`` and the
    usual ``charm/src`` invocation find a ``charm/.venv``). Used by the default
    automatic dependency resolution (and :func:`auto_interpreter`) when no explicit
    ``--venv``/``--python`` is given, so the common case ``flaplint src`` just works.
    """
    out: List[str] = []
    for path in paths:
        norm = os.path.normpath(path)
        if os.path.isfile(norm):
            norm = os.path.dirname(norm)
        for root in (norm, os.path.dirname(norm)):
            for name in (".venv", "venv"):
                cand = os.path.join(root, name)
                if os.path.isdir(cand) and cand not in out:
                    out.append(cand)
    return out


def auto_interpreter(paths: List[str]) -> str:
    """Best-effort path to a sibling virtualenv's interpreter, or ``""``.

    Looks inside each candidate ``.venv``/``venv`` (see :func:`candidate_venvs`)
    for a real interpreter -- ``bin/python`` on POSIX, ``Scripts\\python.exe`` on
    Windows -- and returns the first that exists. Used to auto-pick ``--python``
    so the common ``flaplint src`` invocation resolves dependencies through the
    charm's own environment (PEP 420 namespace packages included) without the user
    naming the interpreter. Returns ``""`` when no sibling interpreter is found, so
    the caller falls back to folder-scanning the site-packages.
    """
    for venv in candidate_venvs(paths):
        for rel in (
            os.path.join("bin", "python"),
            os.path.join("bin", "python3"),
            os.path.join("Scripts", "python.exe"),
        ):
            cand = os.path.join(venv, rel)
            if os.path.isfile(cand):
                return cand
    return ""


def imported_top_levels(files: List[str]) -> Set[str]:
    """The set of top-level module names imported anywhere in ``files``.

    ``import cosl.coordinated_workers`` and ``from cosl import ...`` both
    contribute ``cosl``. Relative imports (``from . import x``) are ignored --
    they resolve within the charm, not into a dependency.
    """
    roots: Set[str] = set()
    for path in files:
        source = read_source(path)
        if source is None:
            continue
        try:
            tree = ast.parse(source, filename=path)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    roots.add(alias.name.split(".", 1)[0])
            elif isinstance(node, ast.ImportFrom):
                if node.level == 0 and node.module:
                    roots.add(node.module.split(".", 1)[0])
    return roots


def _has_databag_sink(path: str) -> bool:
    """True if ``path`` writes to a relation databag in any recognised shape.

    These are the same sink shapes the taint engine reports on -- a subscript
    assignment ``<expr>.data[<entity>][k] = v``, an ``ops`` typed write
    ``relation.save(obj, entity)``, or a mapping mutation ``bag.update(...)`` /
    ``setdefault(...)`` on a ``<expr>.data[<entity>]`` receiver -- so a package
    that matches is one whose code can write relation data, exactly the deps
    worth tracing into for interprocedural resolution.
    """
    source = read_source(path)
    if source is None:
        return False
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError:
        return False
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            if any(is_databag_target(t) for t in node.targets):
                return True
        elif isinstance(node, (ast.AnnAssign, ast.AugAssign)):
            if is_databag_target(node.target):
                return True
        elif isinstance(node, ast.Call):
            if databag_save_content(node) is not None:
                return True
            if databag_mutation_args(node) is not None:
                return True
    return False


def sink_dep_roots(
    site_packages: List[str], imported_roots: Optional[Set[str]] = None
) -> List[str]:
    """Top-level package roots under ``site_packages`` that write to relation data.

    A dependency is *relevant* to this linter only if its code actually writes a
    relation databag (directly, or via a helper that a charm forwards a value
    into). We answer "does this dep touch relation data?" by cheaply AST-scanning
    each candidate package for the databag sink shape and keeping only the
    matches. When ``imported_roots`` is given, packages the charm never imports
    are skipped first, so the scan stays small.

    Returns whole package directories (or single-module files), suitable to feed
    in as *secondary* (trace-only) roots.
    """
    found: Dict[str, str] = {}
    for site in site_packages:
        try:
            entries = sorted(os.listdir(site))
        except OSError:
            continue
        for entry in entries:
            top = entry[:-3] if entry.endswith(".py") else entry
            if imported_roots is not None and top not in imported_roots:
                continue
            if top in found:
                continue
            full = os.path.join(site, entry)
            if os.path.isfile(full) and full.endswith(".py"):
                pkg_files = [full]
            elif os.path.isdir(full):
                pkg_files = [
                    os.path.join(root, name)
                    for root, _, names in os.walk(full)
                    for name in names
                    if name.endswith(".py")
                ]
            else:
                continue
            if any(_has_databag_sink(f) for f in pkg_files):
                found[top] = full
    return sorted(found.values())


def interpreter_module_paths(interpreter: str, roots: Set[str]) -> List[str]:
    """Resolve imported top-level names to on-disk locations via an interpreter.

    Runs ``interpreter`` and asks *its own* import system where each name in
    ``roots`` lives (``importlib.util.find_spec``), returning each package's
    search locations -- correctly following PEP 420 **namespace packages** such
    as ``charmlibs.interfaces.otlp`` -- or a single-module file's path.
    Standard-library names are skipped.

    This decouples dependency resolution from a fixed ``.venv`` location beside
    the charm: point at *any* environment that has the charm's dependencies
    installed (e.g. a ``uv sync``-created ``.venv``'s ``bin/python``), and that
    environment's exact installed versions are what gets scanned. It installs
    nothing -- the deps must already be present in that interpreter's env.
    """
    names = sorted(name for name in roots if name)
    if not names:
        return []
    script = (
        "import importlib.util, json, sys\n"
        "stdlib = getattr(sys, 'stdlib_module_names', frozenset())\n"
        "out = []\n"
        "for name in json.loads(sys.argv[1]):\n"
        "    if name in stdlib:\n"
        "        continue\n"
        "    try:\n"
        "        spec = importlib.util.find_spec(name)\n"
        "    except Exception:\n"
        "        continue\n"
        "    if spec is None:\n"
        "        continue\n"
        "    locs = list(spec.submodule_search_locations or [])\n"
        "    if locs:\n"
        "        out.extend(locs)\n"
        "    elif spec.origin and spec.origin not in ('built-in', 'frozen'):\n"
        "        out.append(spec.origin)\n"
        "print(json.dumps(out))\n"
    )
    try:
        proc = subprocess.run(
            [interpreter, "-c", script, json.dumps(names)],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"warning: cannot run interpreter {interpreter}: {exc}", file=sys.stderr)
        return []
    if proc.returncode != 0:
        print(
            f"warning: interpreter {interpreter} failed to resolve modules: "
            f"{proc.stderr.strip()}",
            file=sys.stderr,
        )
        return []
    try:
        paths = json.loads(proc.stdout.strip() or "[]")
    except json.JSONDecodeError:
        return []
    out: List[str] = []
    for path in paths:
        if isinstance(path, str) and os.path.exists(path) and path not in out:
            out.append(path)
    return out


def filter_sink_roots(package_roots: List[str]) -> List[str]:
    """Keep only resolved package dirs / module files that write a relation databag.

    The interpreter-resolved roots cover every imported third-party top level;
    this narrows them to the ones whose code actually writes relation data --
    the same sink filter :func:`sink_dep_roots` applies to a ``--venv`` listing,
    so interpreter-resolved deps stay *trace-only* and proportionate.
    """
    out: List[str] = []
    for root in package_roots:
        if os.path.isfile(root) and root.endswith(".py"):
            files = [root]
        elif os.path.isdir(root):
            files = [
                os.path.join(sub, name)
                for sub, _, names in os.walk(root)
                for name in names
                if name.endswith(".py")
            ]
        else:
            continue
        if root not in out and any(_has_databag_sink(f) for f in files):
            out.append(root)
    return sorted(set(out))
