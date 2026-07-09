"""Report the git version of the *scanned source* so a run is reproducible.

A finding set is only meaningful against a specific revision of the charm it was
produced from: "23 flaps on alertmanager-k8s" reproduces only if you know which
commit was scanned. For each scanned path this resolves the git repo it lives in
and stamps ``<branch>@<short-commit>[-dirty]`` (the ``dirty`` marker flags an
uncommitted tree, which is inherently non-reproducible). A run spanning several
repos (a fleet scan) reports each distinct repo once, in first-seen order.
"""

from __future__ import annotations

import os
import subprocess
from typing import List, Sequence, Tuple


def _git(cwd: str, *args: str) -> str:
    try:
        r = subprocess.run(
            ["git", "-C", cwd, *args],
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return r.stdout.strip() if r.returncode == 0 else ""


def _repo_dir(path: str) -> str:
    """The directory to root git at: the path itself, or its parent for a file."""
    ap = os.path.abspath(path)
    return ap if os.path.isdir(ap) else os.path.dirname(ap)


def source_versions(paths: Sequence[str]) -> List[Tuple[str, str]]:
    """``[(repo-name, "<branch>@<commit>[-dirty]"), ...]`` for the scanned paths.

    Deduplicated by repository top-level so a fleet run over one monorepo reports
    once; paths not under any git repo are skipped (nothing reproducible to stamp).
    """
    seen: set = set()
    out: List[Tuple[str, str]] = []
    for path in paths:
        cwd = _repo_dir(path)
        if not os.path.isdir(cwd):
            continue
        top = _git(cwd, "rev-parse", "--show-toplevel")
        if not top or top in seen:
            continue
        seen.add(top)
        commit = _git(cwd, "rev-parse", "--short", "HEAD")
        if not commit:
            continue
        # An uncommitted tree can't be reproduced from the commit alone -- flag it.
        if _git(cwd, "status", "--porcelain"):
            commit += "-dirty"
        branch = _git(cwd, "rev-parse", "--abbrev-ref", "HEAD")
        describe = f"{branch}@{commit}" if branch else commit
        out.append((os.path.basename(top), describe))
    return out
