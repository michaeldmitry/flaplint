#!/usr/bin/env python3
"""Emit every supported ops minor release as a JSON array, for the drift matrix.

"Supported" == the newest final patch of each ops *minor* from ``OPS_FLOOR`` (env,
default 2.23) up to the latest release. One entry per minor -- testing every *patch*
would be a dozen near-identical runs; a minor is the granularity at which the ops API
surface flaplint anchors on actually moves.

Enumerating from PyPI (rather than hardcoding a list in the workflow) is the whole
point: the drift suite must track a newly released ops automatically, since a silently
stale list is exactly the blind spot ops-drift.yml exists to prevent. Prints a
``versions=[...]`` line for ``$GITHUB_OUTPUT``; on any network/parse failure it falls
back to just the floor so the matrix still runs one leg instead of erroring the job.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request


def _minor_floor(spec: str) -> tuple:
    parts = spec.split(".")
    return (int(parts[0]), int(parts[1]))


def supported_versions(floor_spec: str) -> list:
    floor = _minor_floor(floor_spec)
    with urllib.request.urlopen("https://pypi.org/pypi/ops/json", timeout=30) as fh:
        data = json.load(fh)

    newest_per_minor: dict = {}
    for version, files in data["releases"].items():
        # Skip versions with no (or only yanked) artifacts and any pre-release
        # (an ``a``/``b``/``rc``/``dev`` suffix contains a letter).
        if not files or all(f.get("yanked") for f in files):
            continue
        if any(ch.isalpha() for ch in version):
            continue
        try:
            parsed = tuple(int(x) for x in version.split("."))
        except ValueError:
            continue
        if len(parsed) < 2 or (parsed[0], parsed[1]) < floor:
            continue
        key = (parsed[0], parsed[1])
        if key not in newest_per_minor or parsed > newest_per_minor[key][0]:
            newest_per_minor[key] = (parsed, version)

    return [ver for _, ver in sorted(newest_per_minor.values())]


def main() -> None:
    floor = os.environ.get("OPS_FLOOR", "2.23")
    try:
        versions = supported_versions(floor)
    except Exception as exc:  # network hiccup / PyPI format change
        print(f"warning: could not enumerate ops versions ({exc}); "
              f"falling back to floor only", file=sys.stderr)
        versions = [floor]
    if not versions:
        versions = [floor]
    print("versions=" + json.dumps(versions))


if __name__ == "__main__":
    main()
