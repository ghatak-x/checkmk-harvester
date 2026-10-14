# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

from __future__ import annotations

import json
import py_compile
import subprocess
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = "harvester"


def test_required_project_files_exist() -> None:
    for rel in [
        "README.md",
        "LICENSE",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "CHANGELOG.md",
        "AUTHORS.md",
        "manifest.json",
        "tools/build_mkp.py",
        "docs/harvester_rbac.yaml",
        "docs/harvester_node_collector.yaml",
    ]:
        assert (ROOT / rel).exists(), rel


def test_manifest_matches_source_tree() -> None:
    manifest = json.loads((ROOT / "manifest.json").read_text())
    assert manifest["name"] == PLUGIN
    assert (ROOT / "cmk_addons" / "plugins" / PLUGIN).is_dir()


def test_python_sources_compile() -> None:
    plugin_root = ROOT / "cmk_addons" / "plugins" / PLUGIN
    candidates = [*plugin_root.rglob("*.py"), plugin_root / "libexec" / f"agent_{PLUGIN}"]
    for path in candidates:
        assert path.exists(), path
        py_compile.compile(str(path), doraise=True)


def test_build_mkp_creates_expected_archive() -> None:
    result = subprocess.run(["python", "tools/build_mkp.py"], cwd=ROOT, text=True, capture_output=True, check=True)
    mkp = Path(result.stdout.strip())
    assert mkp.exists()
    with tarfile.open(mkp, "r:gz") as tar:
        names = set(tar.getnames())
    assert {"info", "info.json", "cmk_addons_plugins.tar"} <= names
