#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""Build a Checkmk MKP from this repository."""

from __future__ import annotations

import json
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "manifest.json"
PLUGIN_ROOT = ROOT / "cmk_addons" / "plugins"
DIST = ROOT / "dist"


def _plugin_files(plugin_name: str) -> list[str]:
    base = PLUGIN_ROOT / plugin_name
    return sorted(
        str(path.relative_to(PLUGIN_ROOT))
        for path in base.rglob("*")
        if path.is_file()
        and "__pycache__" not in path.parts
        and path.suffix not in {".pyc", ".pyo"}
    )


def build() -> Path:
    manifest = json.loads(MANIFEST.read_text())
    name = manifest["name"]
    version = manifest["version"]
    files = {"cmk_addons_plugins": _plugin_files(name)}

    info = {
        "author": manifest.get("author", ""),
        "description": manifest.get("description", ""),
        "download_url": manifest.get("download_url", ""),
        "files": files,
        "name": name,
        "title": manifest["title"],
        "version": version,
        "version.min_required": manifest.get("version.min_required", "2.5.0"),
        "version.packaged": manifest.get("version.packaged", "manual"),
        "version.usable_until": manifest.get("version.usable_until"),
    }

    DIST.mkdir(exist_ok=True)
    payload = DIST / "cmk_addons_plugins.tar"
    with tarfile.open(payload, "w") as tar:
        for rel in files["cmk_addons_plugins"]:
            tar.add(PLUGIN_ROOT / rel, arcname=rel)

    info_json = DIST / "info.json"
    info_py = DIST / "info"
    info_json.write_text(json.dumps(info, indent=2, sort_keys=False) + "\n")
    info_py.write_text(repr(info))

    mkp = DIST / f"{name}-{version}.mkp"
    if mkp.exists():
        mkp.unlink()
    with tarfile.open(mkp, "w:gz") as tar:
        tar.add(info_py, arcname="info")
        tar.add(info_json, arcname="info.json")
        tar.add(payload, arcname="cmk_addons_plugins.tar")
    return mkp


if __name__ == "__main__":
    print(build())
