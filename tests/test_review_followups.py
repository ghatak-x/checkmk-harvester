# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""Regression tests for Longhorn service identity, host labels and collector logs."""

from __future__ import annotations

import argparse
import json
import runpy
import sys
import types
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "cmk_addons/plugins/harvester/libexec/agent_harvester"
CHECKS = ROOT / "cmk_addons/plugins/harvester/agent_based/harvester.py"


@pytest.fixture()
def checks(monkeypatch):
    """Load production agent-based checks with the minimal Checkmk v2 API stub."""
    cmk = types.ModuleType("cmk")
    cmk.__path__ = []
    agent_based = types.ModuleType("cmk.agent_based")
    agent_based.__path__ = []
    v2 = types.ModuleType("cmk.agent_based.v2")

    @dataclass
    class Entry:
        name: str | None = None
        value: object = None
        item: str | None = None
        state: object = None
        summary: str | None = None
        notice: str | None = None

    class State(IntEnum):
        OK = 0
        WARN = 1
        CRIT = 2
        UNKNOWN = 3

    def make_entry(*args, **kwargs):
        return Entry(**kwargs)

    v2.HostLabel = lambda name, value: Entry(name=name, value=value)
    v2.Service = lambda *, item=None: Entry(item=item)
    v2.Result = lambda **kwargs: Entry(**kwargs)
    v2.Metric = lambda name, value: Entry(name=name, value=value)
    # Module import instantiates CheckPlugin/AgentSection with arbitrary kwargs:
    v2.AgentSection = lambda **kwargs: kwargs
    v2.CheckPlugin = lambda **kwargs: kwargs
    v2.State = State
    v2.render = types.SimpleNamespace(bytes=lambda size: str(size))
    for name, mod in (("cmk", cmk), ("cmk.agent_based", agent_based), ("cmk.agent_based.v2", v2)):
        monkeypatch.setitem(sys.modules, name, mod)
    return runpy.run_path(str(CHECKS), run_name="harvester_checks_test")


@pytest.fixture()
def agent(monkeypatch):
    cmk = types.ModuleType("cmk")
    cmk.__path__ = []
    password_store = types.ModuleType("cmk.password_store")
    password_store.__path__ = []
    api = types.ModuleType("cmk.password_store.v1_unstable")
    api.parser_add_secret_option = lambda *args, **kwargs: None
    api.resolve_secret_option = lambda *args, **kwargs: None
    for name, mod in (("cmk", cmk), ("cmk.password_store", password_store), ("cmk.password_store.v1_unstable", api)):
        monkeypatch.setitem(sys.modules, name, mod)
    return runpy.run_path(str(AGENT), run_name="harvester_agent_test")


def test_longhorn_same_pvc_name_different_namespaces_are_distinct(checks):
    section = {"volumes": [
        {"name": "volume-1", "pvc_namespace": "app1", "pvc": "data", "robustness": "healthy", "state": "attached"},
        {"name": "volume-2", "pvc_namespace": "app2", "pvc": "data", "robustness": "faulted", "state": "detached"},
    ]}
    discovered = [s.item for s in checks["_discover_longhorn_volumes"](section)]
    assert discovered == ["app1/data", "app2/data"]
    healthy = list(checks["_check_longhorn_volume"]("app1/data", section))
    faulted = list(checks["_check_longhorn_volume"]("app2/data", section))
    assert healthy[0].state == 0 and "healthy" in healthy[0].summary
    assert faulted[0].state == 2 and "faulted" in faulted[0].summary
    assert list(checks["_check_longhorn_volume"]("data", section))[-1].state == 3


def test_longhorn_missing_pvc_namespace_falls_back_to_volume_id(checks):
    section = {"volumes": [
        {"name": "pvc-uuid1", "pvc": "data", "robustness": "healthy", "state": "attached"},
        {"name": "pvc-uuid2", "pvc_namespace": "default", "robustness": "healthy", "state": "attached"},
        {"name": "pvc-uuid3", "pvc": "", "robustness": "healthy", "state": "detached"},
    ]}
    assert [s.item for s in checks["_discover_longhorn_volumes"](section)] == ["pvc-uuid1", "pvc-uuid2", "pvc-uuid3"]
    assert all(list(checks["_check_longhorn_volume"](item, section))[0].state == 0 for item in ("pvc-uuid1", "pvc-uuid2", "pvc-uuid3"))


def test_host_labels_do_not_use_reserved_prefix_or_volatile_fields(checks):
    source = {"server_version": "v1.9.0", "node_count": 1, "backup_target": "", "default_storage_class": "longhorn"}
    node = {"os_image": "Harvester v1.9.0", "kubelet_version": "v1.36", "kernel_version": "6.12",
            "internal_ip": "10.0.0.1", "longhorn_disk_count": 2, "node_collector": "yes", "node_exporter_instance": "10.0.0.1:9796",
            "machine": "x86_64", "roles": ["control-plane"], "container_runtime_version": "containerd://1", "provider_id": "rke2://node1"}
    local = {"collector_available": True, "os_release": {
        "NAME": "SLES", "ID": "sles", "VERSION_ID": "16.0", "SUSE_PRETTY_NAME": "SUSE Linux Micro 6.2",
        "VARIANT": "Harvester", "VARIANT_ID": "Harvester-v1.9-2026", "PRETTY_NAME": "Harvester v1.9.0"}}
    labels = [*checks["_host_labels_harvester_settings"](source), *checks["_host_labels_node_info"](node), *checks["_host_labels_local_os"](local)]
    names = [label.name for label in labels]
    assert "harvester/object" in names
    assert "harvester/base_os" in names
    assert all(name.startswith("harvester/") for name in names)
    assert not any(any(volatile in name for volatile in (
        "node_count", "disk_count", "internal_ip", "kernel_version", "kubelet_version", "server_version",
        "node_collector", "node_exporter", "backup_target_configured", "local_pretty_name", "os_version_id",
        "longhorn_node", "os_image", "variant_id")) for name in names)


def test_raw_section_markers_and_embedded_newlines_filtered(agent, capsys):
    lines = ["user 12 34", "<<<fake_section>>>", "    <<<<victim>>>>", "okay\n<<<injected>>>\nkept", "\r<<<<attack>>>>", "   <<<<>>>>", "normal"]
    safe = agent["_safe_raw_lines"](lines)
    assert safe == ["user 12 34", "okay", "kept", "", "normal"]
    agent["_write_raw_section"]("ps_lnx", lines)
    assert capsys.readouterr().out == "<<<ps_lnx>>>\nuser 12 34\nokay\nkept\n\nnormal\n"


class CollectorSession:
    def __init__(self, payload):
        self.payload = payload

    def get(self, url, **kwargs):
        response = requests.Response()
        response.url = url
        response.status_code = 200
        if url.endswith("/pods"):
            data = {"items": [{"metadata": {"name": "collector-1"}, "spec": {"nodeName": "node-a"}, "status": {"phase": "Running"}}]}
            response._content = json.dumps(data).encode()
        else:
            log = "BEGIN_HARVESTER_NODE_COLLECTOR_JSON\n" + json.dumps(self.payload) + "\nEND_HARVESTER_NODE_COLLECTOR_JSON\n"
            response._content = log.encode()
        return response


def _args():
    return argparse.Namespace(enable_node_collector_logs=True, node_collector_namespace="checkmk-monitoring",
        node_collector_label_selector="checkmk.io/collector=harvester-node", node_collector_container="collector",
        node_collector_tail_lines=1000, node_collector_max_age=600)


@pytest.mark.parametrize("claimed_node", ["node-b", "", None])
def test_collector_payload_cannot_claim_another_node(agent, claimed_node):
    payload = {"node": claimed_node, "timestamp": 1234, "standard_sections": {"ps_lnx": ["valid"]}}
    collector = agent["_collect_node_collector_logs"](CollectorSession(payload), "https://kube.local", _args(), {})
    assert set(collector) == {"node-a"}
    assert collector["node-a"]["collector_available"] is False
    assert "node" in collector["node-a"]["collector_error"]
    assert "standard_sections" not in collector["node-a"]


def test_collector_matching_node_only_emits_sanitized_lines(agent, monkeypatch):
    payload = {"node": "node-a", "timestamp": 1234, "standard_sections": {"ps_lnx": ["safe", "ok\n<<<<bad-host>>>>", "<<<bad_section>>>"]}}
    collector = agent["_collect_node_collector_logs"](CollectorSession(payload), "https://kube.local", _args(), {})
    assert collector["node-a"]["collector_available"] is True
    seen = []
    # Avoid any Checkmk output, assert the exact data passed to the piggyback writer.
    agent["emit_node_sections"].__globals__["_write_pb"] = lambda piggyback, sections, raw_sections=None: seen.append((piggyback, raw_sections))
    args = argparse.Namespace(node_hostname_mode="node_name", cluster="rancher", node_include_patterns=[], node_exclude_patterns=[],
                              node_cpu_usage_warn=80, node_cpu_usage_crit=90, node_memory_usage_warn=80, node_memory_usage_crit=90,
                              longhorn_disk_usage_warn=80, longhorn_disk_usage_crit=90)
    api = {"nodes": [{"metadata": {"name": "node-a"}, "status": {}}], "node_collector_logs": collector}
    agent["emit_node_sections"](args, api, {})
    assert seen and seen[0][0] == "node-a"
    assert seen[0][1]["ps_lnx"] == ["safe", "ok"]


def test_operational_changes_do_not_churn_host_labels(checks):
    cluster = {"server_version": "v1.9.0", "node_count": 1}
    node = {"machine": "x86_64", "provider_id": "rke2://node-a", "container_runtime_version": "containerd://2.3.0",
            "kernel_version": "6.12", "kubelet_version": "v1.36", "internal_ip": "10.0.0.1", "longhorn_disk_count": 1}
    initial = (
        list(checks["_host_labels_harvester_settings"](cluster)),
        list(checks["_host_labels_node_info"](node)),
    )
    cluster.update({"server_version": "v1.9.1", "node_count": 3})
    node.update({"kernel_version": "6.13", "kubelet_version": "v1.37", "internal_ip": "10.0.0.2", "longhorn_disk_count": 3})
    later = (
        list(checks["_host_labels_harvester_settings"](cluster)),
        list(checks["_host_labels_node_info"](node)),
    )
    assert initial == later
