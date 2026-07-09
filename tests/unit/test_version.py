"""Tests for scanned-source git provenance (reproducible runs)."""

from __future__ import annotations

import subprocess

from flaplint.version import source_versions


def _git(cwd, *args):
    subprocess.run(["git", "-C", str(cwd), *args], check=True, capture_output=True)


def _init_repo(root, branch="main"):
    _git(root, "init", "-q", "-b", branch)
    _git(root, "config", "user.email", "t@t")
    _git(root, "config", "user.name", "t")
    (root / "f.py").write_text("x = 1\n")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "init")


def test_source_version_reports_branch_and_commit(tmp_path):
    repo = tmp_path / "my-charm"
    repo.mkdir()
    _init_repo(repo, branch="feature")

    versions = source_versions([str(repo / "f.py")])
    assert len(versions) == 1
    name, describe = versions[0]
    assert name == "my-charm"
    assert describe.startswith("feature@")


def test_dirty_tree_is_flagged(tmp_path):
    repo = tmp_path / "charm"
    repo.mkdir()
    _init_repo(repo)
    (repo / "f.py").write_text("x = 2  # uncommitted\n")

    (_name, describe) = source_versions([str(repo)])[0]
    assert describe.endswith("-dirty")


def test_same_repo_reported_once(tmp_path):
    repo = tmp_path / "charm"
    repo.mkdir()
    _init_repo(repo)
    (repo / "src").mkdir()

    versions = source_versions([str(repo / "src"), str(repo / "f.py")])
    assert len(versions) == 1


def test_non_git_path_is_skipped(tmp_path):
    plain = tmp_path / "loose"
    plain.mkdir()
    (plain / "f.py").write_text("x = 1\n")
    assert source_versions([str(plain / "f.py")]) == []
