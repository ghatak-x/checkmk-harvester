#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""Agent based checks for Harvester / SUSE Virtualization Layer 2."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from typing import Any

from cmk.agent_based.v2 import (
    AgentSection,
    CheckPlugin,
    HostLabel,
    Metric,
    Result,
    Service,
    State,
    render,
)


def _parse_json_section(string_table: list[list[str]]) -> dict[str, Any]:
    if not string_table:
        return {}
    return json.loads("".join("".join(row) for row in string_table))


def _discover_single(section: Mapping[str, Any]) -> Iterable[Service]:
    if section:
        yield Service()


def _as_float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except Exception:
        return default


def _as_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _status_is_true(value: Any) -> bool:
    return value is True or str(value).lower() == "true" or value == 1 or value == 1.0


def _condition(conditions: Iterable[Mapping[str, Any]], ctype: str) -> Mapping[str, Any] | None:
    for cond in conditions:
        if str(cond.get("type", "")).lower() == ctype.lower():
            return cond
    return None


def _condition_status(conditions: Iterable[Mapping[str, Any]], ctype: str) -> str | None:
    cond = _condition(conditions, ctype)
    if cond is None:
        return None
    return str(cond.get("status"))


def _render_percent(value: float) -> str:
    return f"{value * 100:.1f}%"


def _configured_state(name: Any, default: State = State.WARN) -> State:
    match str(name or "").lower():
        case "ok":
            return State.OK
        case "warn":
            return State.WARN
        case "crit" | "critical":
            return State.CRIT
    return default


def _state_name(state: State) -> str:
    if state is State.OK:
        return "OK"
    if state is State.WARN:
        return "WARN"
    if state is State.CRIT:
        return "CRIT"
    return "UNKNOWN"


def _label_value(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text if text else None


def _host_labels_harvester_settings(section: Mapping[str, Any]) -> Iterable[HostLabel]:
    """Expose stable classification labels, not operational metrics.

    Node counts, settings, health, and release versions belong in services: they
    change during normal operation and should not churn discovered host labels.
    """
    yield HostLabel("harvester/object", "cluster")


def _host_labels_node_info(section: Mapping[str, Any]) -> Iterable[HostLabel]:
    yield HostLabel("harvester/object", "node")
    if runtime := _label_value(section.get("container_runtime_version")):
        yield HostLabel("harvester/container_runtime", runtime.split("://", 1)[0])
    if machine := _label_value(section.get("machine") or section.get("architecture")):
        yield HostLabel("harvester/architecture", machine)
    if provider_id := _label_value(section.get("provider_id")):
        yield HostLabel("harvester/provider", provider_id.split("://", 1)[0])
    # Node roles are intentionally discoverable classification data for rules.
    roles = section.get("roles")
    if isinstance(roles, list) and roles:
        for role in roles:
            if role and _label_value(role):
                yield HostLabel(f"harvester/node_role/{role}", "yes")


# Cluster/source host checks

def _check_harvester_version(section: Mapping[str, Any]) -> Iterable[Result]:
    version = section.get("server_version")
    if version:
        yield Result(state=State.OK, summary=f"Harvester version: {version}")
    else:
        yield Result(state=State.WARN, summary="Harvester version setting not found")


def _check_harvester_settings(section: Mapping[str, Any]) -> Iterable[Result]:
    count = _as_int(section.get("count"))
    storage = section.get("default_storage_class") or "unknown"
    yield Result(state=State.OK, summary=f"Settings: {count}, default storage class: {storage}")
    for setting in section.get("important_settings", []) or []:
        name = setting.get("name", "unknown")
        value = setting.get("value")
        if value not in (None, ""):
            yield Result(state=State.OK, notice=f"{name}: {value}")
        for cond in setting.get("conditions", []) or []:
            yield Result(state=State.OK, notice=f"{name} condition {cond.get('type')}: {cond.get('status')} {cond.get('reason', '')}")


def _check_prometheus_status(section: Mapping[str, Any]) -> Iterable[Result]:
    failed = _as_int(section.get("failed_query_count"))
    successful = _as_int(section.get("successful_query_count"))
    total = _as_int(section.get("query_count"))
    empty = _as_int(section.get("empty_query_count"))
    available = bool(section.get("available"))
    if not available:
        yield Result(state=State.CRIT, summary=f"Prometheus unavailable or all queries failed ({successful}/{total} successful)")
    elif failed:
        yield Result(state=State.WARN, summary=f"Prometheus reachable, {failed}/{total} queries failed")
    else:
        yield Result(state=State.OK, summary=f"Prometheus reachable, {successful}/{total} queries successful")
    if empty:
        yield Result(state=State.OK, notice=f"Empty successful queries: {empty}")
    if section.get("endpoint"):
        yield Result(state=State.OK, notice=f"Endpoint: {section.get('endpoint')}")
    for failure in section.get("failures", []) or []:
        yield Result(state=State.WARN, notice=f"{failure.get('query')}: {failure.get('error')}")


def _discover_vm_images(section: Mapping[str, Any]) -> Iterable[Service]:
    for image in section.get("images", []) or []:
        name = image.get("display_name") or image.get("name")
        namespace = image.get("namespace") or "default"
        if name:
            yield Service(item=f"{namespace}/{name}")


def _image_item(image: Mapping[str, Any]) -> str:
    return f"{image.get('namespace') or 'default'}/{image.get('display_name') or image.get('name')}"


def _check_vm_image(item: str, section: Mapping[str, Any]) -> Iterable[Result]:
    for image in section.get("images", []) or []:
        if _image_item(image) != item:
            continue
        conditions = image.get("conditions", []) or []
        imported = _condition_status(conditions, "Imported")
        initialized = _condition_status(conditions, "Initialized")
        retry_exceeded = _condition_status(conditions, "RetryLimitExceeded")
        progress = _as_float(image.get("progress"), -1.0)
        failed = _as_int(image.get("failed"))
        if retry_exceeded == "True" or failed > 0:
            state = State.CRIT
        elif imported == "True" and progress >= 100:
            state = State.OK
        elif initialized == "True":
            state = State.WARN
        else:
            state = State.UNKNOWN
        summary = f"Progress: {progress:g}%"
        if imported is not None:
            summary += f", imported: {imported}"
        yield Result(state=state, summary=summary)
        if image.get("size") is not None:
            yield Metric("harvester_vm_image_size", _as_float(image.get("size")))
            yield Result(state=State.OK, notice=f"Size: {render.bytes(_as_float(image.get('size')))}")
        if image.get("virtual_size") is not None:
            yield Result(state=State.OK, notice=f"Virtual size: {render.bytes(_as_float(image.get('virtual_size')))}")
        if image.get("storage_class"):
            yield Result(state=State.OK, notice=f"Storage class: {image.get('storage_class')}")
        return
    yield Result(state=State.UNKNOWN, summary="Image disappeared")


def _check_platform_pods(section: Mapping[str, Any]) -> Iterable[Result]:
    problems = section.get("problem_pods", []) or []
    namespaces = section.get("namespaces", {}) or {}
    if problems:
        yield Result(state=State.CRIT, summary=f"Problem pods: {len(problems)}")
    else:
        total = sum(sum(states.values()) for states in namespaces.values()) if namespaces else 0
        yield Result(state=State.OK, summary=f"Platform pods OK: {total}")
    for ns, states in namespaces.items():
        text = ", ".join(f"{state}: {count}" for state, count in states.items())
        yield Result(state=State.OK, notice=f"{ns}: {text}")
    for pod in problems[:10]:
        yield Result(state=State.CRIT, notice=f"{pod.get('namespace')}/{pod.get('name')}: {pod.get('phase')}")


def _discover_backup_targets(section: Mapping[str, Any]) -> Iterable[Service]:
    for target in section.get("targets", []) or []:
        if name := target.get("name"):
            yield Service(item=str(name))


def _check_backup_target(item: str, section: Mapping[str, Any]) -> Iterable[Result]:
    for target in section.get("targets", []) or []:
        if target.get("name") != item:
            continue
        url = target.get("url") or ""
        available = target.get("available")
        policy = section.get("policy", {}) or {}
        not_configured_state = _configured_state(policy.get("backup_target_not_configured_state"), State.WARN)
        if not url:
            yield Result(state=not_configured_state, summary=f"Backup target not configured ({_state_name(not_configured_state)})")
        elif available is True:
            yield Result(state=State.OK, summary="Backup target available")
        else:
            yield Result(state=State.CRIT, summary="Backup target unavailable")
        for cond in target.get("conditions", []) or []:
            is_unavailable = str(cond.get("type")).lower() == "unavailable" and str(cond.get("status")).lower() == "true"
            # An empty URL is a deliberate unconfigured state. Keep the service WARN
            # from the summary, but do not add an extra CRIT notice for the condition.
            state = State.CRIT if is_unavailable and url else State.OK
            yield Result(state=state, notice=f"{cond.get('type')}: {cond.get('status')} {cond.get('reason', '')} {cond.get('message', '')}".strip())
        return
    yield Result(state=State.UNKNOWN, summary="Backup target disappeared")


def _check_longhorn_volume_summary(section: Mapping[str, Any]) -> Iterable[Result]:
    summary = section.get("summary", {}) or {}
    count = _as_int(section.get("count"))
    faulted = _as_int(summary.get("robustness_faulted"))
    degraded = _as_int(summary.get("robustness_degraded"))
    healthy = _as_int(summary.get("robustness_healthy"))
    policy = section.get("policy", {}) or {}
    node_count = _as_int(section.get("node_count"))
    if faulted:
        state = State.CRIT
    elif degraded:
        if node_count <= 1:
            state = _configured_state(policy.get("longhorn_degraded_volume_single_node_state"), State.WARN)
        else:
            state = _configured_state(policy.get("longhorn_degraded_volume_state"), State.WARN)
    else:
        state = State.OK
    yield Result(state=state, summary=f"Volumes: {count}, healthy: {healthy}, degraded: {degraded}, faulted: {faulted}")
    if degraded and node_count <= 1:
        yield Result(state=State.OK, notice="Single-node Harvester cluster: replicated Longhorn volumes may stay degraded because replicas cannot be scheduled on other nodes")
    yield Metric("longhorn_volumes", count)
    yield Metric("longhorn_volumes_degraded", degraded)
    yield Metric("longhorn_volumes_faulted", faulted)


def _longhorn_volume_item(volume: Mapping[str, Any]) -> str | None:
    """Identify PVC-bound Longhorn volumes by namespace/PVC; otherwise use volume ID.

    A bare PVC name is not globally unique.  When Kubernetes PVC metadata is
    absent (e.g. an unattached/orphaned volume), the Longhorn volume name is
    already cluster-unique and makes a suitable fallback.
    """
    pvc = _label_value(volume.get("pvc"))
    namespace = _label_value(volume.get("pvc_namespace"))
    if pvc and namespace:
        return f"{namespace}/{pvc}"
    return _label_value(volume.get("name"))


def _discover_longhorn_volumes(section: Mapping[str, Any]) -> Iterable[Service]:
    for volume in section.get("volumes", []) or []:
        if item := _longhorn_volume_item(volume):
            yield Service(item=item)


def _check_longhorn_volume(item: str, section: Mapping[str, Any]) -> Iterable[Result]:
    for volume in section.get("volumes", []) or []:
        if item != _longhorn_volume_item(volume):
            continue
        robustness = str(volume.get("robustness") or "unknown")
        state = str(volume.get("state") or "unknown")
        policy = section.get("policy", {}) or {}
        if robustness == "healthy":
            check_state = State.OK
        elif robustness == "degraded":
            if volume.get("expected_single_node_degraded"):
                check_state = _configured_state(policy.get("longhorn_degraded_volume_single_node_state"), State.WARN)
            else:
                check_state = _configured_state(policy.get("longhorn_degraded_volume_state"), State.WARN)
        elif robustness == "faulted":
            check_state = State.CRIT
        else:
            check_state = State.UNKNOWN
        summary = f"{robustness}, {state}"
        if volume.get("expected_single_node_degraded"):
            summary += " (single-node replica scheduling)"
        yield Result(state=check_state, summary=summary)
        if volume.get("expected_single_node_degraded"):
            yield Result(state=State.OK, notice=f"Requested replicas: {volume.get('replicas')}, cluster nodes: {volume.get('node_count')}")
        if volume.get("actual_size") is not None:
            yield Metric("longhorn_volume_actual_size", _as_float(volume.get("actual_size")))
            yield Result(state=State.OK, notice=f"Actual size: {render.bytes(_as_float(volume.get('actual_size')))}")
        if volume.get("size") is not None:
            yield Metric("longhorn_volume_capacity", _as_float(volume.get("size")))
            yield Result(state=State.OK, notice=f"Capacity: {render.bytes(_as_float(volume.get('size')))}")
        if volume.get("node"):
            yield Result(state=State.OK, notice=f"Node: {volume.get('node')}")
        for workload in volume.get("workloads", []) or []:
            yield Result(state=State.OK, notice=f"Workload: {workload.get('workloadType')} {workload.get('workloadName')} ({workload.get('podStatus')})")
        return
    yield Result(state=State.UNKNOWN, summary="Volume disappeared")


def _check_longhorn_replicas(section: Mapping[str, Any]) -> Iterable[Result]:
    summary = section.get("summary", {}) or {}
    total = sum(_as_int(v) for v in summary.values())
    running = _as_int(summary.get("running"))
    stopped = _as_int(summary.get("stopped"))
    problems = section.get("problems", []) or []
    state = State.WARN if problems else State.OK
    yield Result(state=state, summary=f"Replicas: {total}, running: {running}, stopped: {stopped}, problems: {len(problems)}")
    yield Metric("longhorn_replicas", total)
    yield Metric("longhorn_replicas_running", running)
    for replica in problems[:10]:
        yield Result(state=State.WARN, notice=f"{replica.get('name')}: {replica.get('state')} on {replica.get('node')}")


# Node piggyback checks

def _check_node_info(section: Mapping[str, Any]) -> Iterable[Result]:
    node = section.get("node") or "unknown"
    os_image = section.get("os_image") or "unknown OS"
    kernel = section.get("kernel_version") or section.get("release") or "unknown kernel"
    yield Result(state=State.OK, summary=f"{node}: {os_image}, kernel {kernel}")
    if section.get("internal_ip"):
        yield Result(state=State.OK, notice=f"Internal IP: {section.get('internal_ip')}")
    if section.get("kubelet_version"):
        yield Result(state=State.OK, notice=f"Kubelet: {section.get('kubelet_version')}")
    if section.get("container_runtime_version"):
        yield Result(state=State.OK, notice=f"Runtime: {section.get('container_runtime_version')}")
    if section.get("provider_id"):
        yield Result(state=State.OK, notice=f"Provider ID: {section.get('provider_id')}")


def _check_node_conditions(section: Mapping[str, Any]) -> Iterable[Result]:
    conditions = section.get("conditions", {}) or {}
    expected = {
        "Ready": "true",
        "MemoryPressure": "false",
        "DiskPressure": "false",
        "PIDPressure": "false",
        "NetworkUnavailable": "false",
    }
    bad = []
    for condition, wanted in expected.items():
        actual = str(conditions.get(condition, "unknown")).lower()
        if actual != wanted:
            bad.append(f"{condition}={actual}")
    if bad:
        yield Result(state=State.CRIT, summary=", ".join(bad))
    else:
        yield Result(state=State.OK, summary="Node conditions OK")
    for condition, status in sorted(conditions.items()):
        yield Result(state=State.OK, notice=f"{condition}: {status}")


def _check_node_metrics(section: Mapping[str, Any]) -> Iterable[Result]:
    parts = []
    states = []
    thresholds = section.get("thresholds", {}) or {}
    if section.get("cpu_usage") is not None:
        cpu = _as_float(section.get("cpu_usage"))
        warn = _as_float(thresholds.get("cpu_usage_warn"), 0.80)
        crit = _as_float(thresholds.get("cpu_usage_crit"), 0.90)
        state = State.CRIT if cpu >= crit else State.WARN if cpu >= warn else State.OK
        states.append(state)
        parts.append(f"CPU: {_render_percent(cpu)}")
        yield Metric("harvester_node_cpu_usage", cpu, levels=(warn, crit))
        if state is not State.OK:
            yield Result(state=state, notice=f"CPU usage {_render_percent(cpu)} exceeds configured levels {_render_percent(warn)}/{_render_percent(crit)}")
    if section.get("memory_usage") is not None:
        mem = _as_float(section.get("memory_usage"))
        warn = _as_float(thresholds.get("memory_usage_warn"), 0.80)
        crit = _as_float(thresholds.get("memory_usage_crit"), 0.90)
        state = State.CRIT if mem >= crit else State.WARN if mem >= warn else State.OK
        states.append(state)
        parts.append(f"Memory: {_render_percent(mem)}")
        yield Metric("harvester_node_memory_usage", mem, levels=(warn, crit))
        if state is not State.OK:
            yield Result(state=state, notice=f"Memory usage {_render_percent(mem)} exceeds configured levels {_render_percent(warn)}/{_render_percent(crit)}")
    if not parts:
        yield Result(state=State.OK, summary="No node CPU/memory metrics")
        return
    final = State.CRIT if State.CRIT in states else State.WARN if State.WARN in states else State.OK
    yield Result(state=final, summary=", ".join(parts))



def _check_nodeconfig(section: Mapping[str, Any]) -> Iterable[Result]:
    ntp = section.get("ntp_configs", {}) or {}
    conditions = section.get("ntp_conditions", []) or []
    applied = _condition_status(conditions, "Applied")
    modified = _condition_status(conditions, "Modified")
    if applied == "True":
        state = State.OK
    elif modified == "False":
        state = State.WARN
    else:
        state = State.UNKNOWN if conditions else State.OK
    ntp_servers = ntp.get("ntpServers") or "not configured"
    yield Result(state=state, summary=f"NTP servers: {ntp_servers}")
    for cond in conditions:
        yield Result(state=State.OK, notice=f"NTP {cond.get('type')}: {cond.get('status')} {cond.get('reason', '')} {cond.get('message', '')}")


def _discover_blockdevices(section: Mapping[str, Any]) -> Iterable[Service]:
    for dev in section.get("devices", []) or []:
        item = dev.get("dev_path") or dev.get("name")
        if item:
            yield Service(item=str(item))


def _check_blockdevice(item: str, section: Mapping[str, Any]) -> Iterable[Result]:
    for dev in section.get("devices", []) or []:
        if item not in {dev.get("dev_path"), dev.get("name")}:
            continue
        state = str(dev.get("state") or "unknown")
        phase = str(dev.get("provision_phase") or "unknown")
        check_state = State.OK if state == "Active" else State.WARN
        yield Result(state=check_state, summary=f"{state}, {phase}")
        if dev.get("size") is not None:
            yield Result(state=State.OK, notice=f"Size: {render.bytes(_as_float(dev.get('size')))}")
        details = ", ".join(str(x) for x in [dev.get("vendor"), dev.get("model"), dev.get("drive_type")] if x)
        if details:
            yield Result(state=State.OK, notice=details)
        return
    yield Result(state=State.UNKNOWN, summary="Block device disappeared")


def _check_longhorn_node_status(section: Mapping[str, Any]) -> Iterable[Result]:
    prom = section.get("prometheus_status", {}) or {}
    conditions = section.get("conditions", []) or []
    bad = []
    for key in ["ready", "schedulable", "allowScheduling", "kernelmodulesloaded", "mountpropagation", "nfsclientinstalled"]:
        if key in prom and _as_float(prom.get(key)) != 1.0:
            bad.append(key)
    for cond in conditions:
        if str(cond.get("status", "")).lower() != "true":
            bad.append(str(cond.get("type")))
    if bad:
        yield Result(state=State.CRIT, summary="Bad conditions: " + ", ".join(sorted(set(bad))))
    else:
        yield Result(state=State.OK, summary="Longhorn node OK")
    for cond in conditions:
        yield Result(state=State.OK, notice=f"{cond.get('type')}: {cond.get('status')} {cond.get('message', '')}")


def _discover_longhorn_disks(section: Mapping[str, Any]) -> Iterable[Service]:
    names = set()
    for disk in section.get("disks", []) or []:
        if name := disk.get("name"):
            names.add(str(name))
    for name in (section.get("prometheus_status", {}) or {}).keys():
        names.add(str(name))
    for name in sorted(names):
        yield Service(item=name)


def _find_lh_disk(section: Mapping[str, Any], item: str) -> Mapping[str, Any] | None:
    for disk in section.get("disks", []) or []:
        if disk.get("name") == item:
            return disk
    return None


def _check_longhorn_disk_status(item: str, section: Mapping[str, Any]) -> Iterable[Result]:
    prom = (section.get("prometheus_status", {}) or {}).get(item, {}) or {}
    disk = _find_lh_disk(section, item) or {}
    bad = []
    for key in ["ready", "schedulable"]:
        if key in prom and _as_float(prom.get(key)) != 1.0:
            bad.append(key)
    for cond in disk.get("conditions", []) or []:
        if str(cond.get("status", "")).lower() != "true":
            bad.append(str(cond.get("type")))
    if bad:
        yield Result(state=State.CRIT, summary="Bad conditions: " + ", ".join(sorted(set(bad))))
    else:
        yield Result(state=State.OK, summary="Disk ready and schedulable")
    if disk.get("path"):
        yield Result(state=State.OK, notice=f"Path: {disk.get('path')}")


def _check_longhorn_disk_usage(item: str, section: Mapping[str, Any]) -> Iterable[Result]:
    usage = (section.get("prometheus_usage", {}) or {}).get(item, {}) or {}
    disk = _find_lh_disk(section, item) or {}
    capacity = _as_float(usage.get("capacity", disk.get("storage_maximum")))
    used = _as_float(usage.get("usage"))
    scheduled = _as_float(disk.get("storage_scheduled"))
    available = _as_float(disk.get("storage_available"))
    pct = used / capacity if capacity else 0.0
    thresholds = section.get("thresholds", {}) or {}
    warn = _as_float(thresholds.get("usage_warn"), 0.80)
    crit = _as_float(thresholds.get("usage_crit"), 0.90)
    state = State.CRIT if pct >= crit else State.WARN if pct >= warn else State.OK
    yield Result(state=state, summary=f"Used: {render.bytes(used)} of {render.bytes(capacity)} ({_render_percent(pct)})")
    if capacity:
        yield Metric("longhorn_disk_usage", used, levels=(capacity * warn, capacity * crit))
    else:
        yield Metric("longhorn_disk_usage", used)
    yield Metric("longhorn_disk_capacity", capacity)
    if scheduled:
        yield Metric("longhorn_disk_scheduled", scheduled)
        yield Result(state=State.OK, notice=f"Scheduled: {render.bytes(scheduled)}")
    if available:
        yield Result(state=State.OK, notice=f"Available according to Longhorn: {render.bytes(available)}")




# Optional local Harvester node collector checks

def _host_labels_local_os(section: Mapping[str, Any]) -> Iterable[HostLabel]:
    """Stable OS-family labels only; keep version/build details in node checks."""
    os_release = section.get("os_release") or {}
    if not isinstance(os_release, Mapping):
        return
    if suse_pretty := _label_value(os_release.get("SUSE_PRETTY_NAME")):
        if "micro" in suse_pretty.lower():
            yield HostLabel("harvester/base_os", "suse-linux-micro")
    if name := _label_value(os_release.get("NAME")):
        yield HostLabel("harvester/os_name", name)
    if os_id := _label_value(os_release.get("ID")):
        yield HostLabel("harvester/os_id", os_id)
    if variant_name := _label_value(os_release.get("VARIANT")):
        yield HostLabel("harvester/variant", variant_name)
    variant_id = str(os_release.get("VARIANT_ID") or "")
    if "harvester" in variant_id.lower() or "micro" in str(os_release.get("SUSE_PRETTY_NAME") or "").lower():
        yield HostLabel("harvester/transactional", "yes")


def _check_node_local_os(section: Mapping[str, Any]) -> Iterable[Result]:
    if not section.get("collector_available"):
        yield Result(state=State.UNKNOWN, summary=f"Node collector unavailable: {section.get('collector_error') or 'no data'}")
        return
    age = section.get("collector_age_seconds")
    max_age = _as_float(section.get("collector_max_age_seconds"), 600.0)
    state = State.OK
    age_text = "unknown age"
    if age is not None:
        age_f = _as_float(age)
        age_text = render.timespan(age_f)
        if age_f > max_age:
            state = State.WARN
    os_release = section.get("os_release", {}) or {}
    kernel = section.get("kernel", {}) or {}
    pretty = os_release.get("PRETTY_NAME") or os_release.get("NAME") or "unknown OS"
    suse_pretty = os_release.get("SUSE_PRETTY_NAME") or ""
    name = os_release.get("NAME") or ""
    version_id = os_release.get("VERSION_ID") or ""
    variant = os_release.get("VARIANT") or ""
    variant_id = os_release.get("VARIANT_ID") or ""
    release = kernel.get("release") or "unknown kernel"
    uptime = section.get("uptime_seconds")
    base_os = suse_pretty or (f"{name} {version_id}".strip() if name or version_id else "unknown base OS")
    transactional = "yes" if ("micro" in base_os.lower() or "harvester" in variant_id.lower()) else "unknown"
    summary = f"{pretty} on {base_os}, kernel {release}, collector age {age_text}"
    yield Result(state=state, summary=summary)
    yield Result(state=State.OK, notice=f"Base OS: {base_os}")
    if name or version_id:
        yield Result(state=State.OK, notice=f"Compatibility OS identity: {name or 'unknown'} {version_id or ''}".strip())
    if variant or variant_id:
        yield Result(state=State.OK, notice=f"Variant: {variant or 'unknown'} ({variant_id or 'no variant id'})")
    yield Result(state=State.OK, notice=f"Transactional/appliance-style OS: {transactional}")
    if uptime is not None:
        yield Metric("harvester_node_local_uptime", _as_float(uptime))
        yield Result(state=State.OK, notice=f"Uptime: {render.timespan(_as_float(uptime))}")
    loadavg = section.get("loadavg", {}) or {}
    if loadavg:
        yield Result(state=State.OK, notice="Load average: " + ", ".join(f"{k}={v}" for k, v in loadavg.items()))
    native = section.get("native_sections", {}) or {}
    if native:
        enabled = ", ".join(sorted(k for k, v in native.items() if v))
        yield Result(state=State.OK, notice=f"Native Checkmk sections emitted by node collector: {enabled}")
    if section.get("collector_pod"):
        yield Result(state=State.OK, notice=f"Collector pod: {section.get('collector_namespace')}/{section.get('collector_pod')}")


def _check_node_local_processes(section: Mapping[str, Any]) -> Iterable[Result]:
    if not section.get("collector_available"):
        yield Result(state=State.UNKNOWN, summary=f"Node collector unavailable: {section.get('collector_error') or 'no data'}")
        return
    required = section.get("required_processes", {}) or {}
    missing = sorted(name for name, present in required.items() if not present)
    if missing:
        yield Result(state=State.CRIT, summary="Missing required processes: " + ", ".join(missing))
    else:
        yield Result(state=State.OK, summary="Required Harvester node processes are present")
    processes = section.get("processes", {}) or {}
    for name in sorted(processes):
        entries = processes.get(name) or []
        yield Result(state=State.OK, notice=f"{name}: {len(entries)} matching process(es)")
        for proc in entries[:3]:
            cmdline = str(proc.get("cmdline") or proc.get("comm") or "")
            if cmdline:
                yield Result(state=State.OK, notice=f"{name} pid {proc.get('pid')}: {cmdline[:180]}")


def _check_node_local_mounts(section: Mapping[str, Any]) -> Iterable[Result]:
    if not section.get("collector_available"):
        yield Result(state=State.UNKNOWN, summary=f"Node collector unavailable: {section.get('collector_error') or 'no data'}")
        return
    mounts = section.get("mounts", []) or []
    modules = section.get("kernel_modules", {}) or {}
    by_mount = {str(m.get("mountpoint")): m for m in mounts if isinstance(m, Mapping)}
    problems: list[str] = []
    defaultdisk = by_mount.get("/var/lib/harvester/defaultdisk")
    if not defaultdisk:
        problems.append("/var/lib/harvester/defaultdisk not seen in host mount table")
    elif not defaultdisk.get("rw"):
        problems.append("/var/lib/harvester/defaultdisk is not writable")

    # Keep the node-local collector conservative. Missing optional kernel modules
    # should not create noise on healthy Harvester nodes. In particular, NFS can
    # be loaded on demand and is already represented by Longhorn node conditions.
    required_modules = {"dm_crypt"}
    for module in sorted(required_modules):
        if module in modules and not modules.get(module):
            problems.append(f"Kernel module {module} is not loaded")

    storage_transport_modules = [name for name in ("iscsi_tcp", "nvme_tcp") if name in modules]
    if storage_transport_modules and not any(modules.get(name) for name in storage_transport_modules):
        problems.append("No tracked storage transport kernel module is loaded")

    state = State.WARN if problems else State.OK
    yield Result(state=state, summary=f"Local mounts: {len(mounts)}, kernel modules tracked: {len(modules)}")
    for problem in problems:
        yield Result(state=State.WARN, notice=problem)

    for module, loaded in sorted(modules.items()):
        if module in required_modules:
            module_state = State.OK if loaded else State.WARN
            suffix = "required"
        elif module in ("iscsi_tcp", "nvme_tcp"):
            module_state = State.OK
            suffix = "storage transport"
        else:
            module_state = State.OK
            suffix = "optional"
        yield Result(
            state=module_state,
            notice=f"Kernel module {module}: {'loaded' if loaded else 'not loaded'} ({suffix})",
        )
    for mount in mounts:
        if isinstance(mount, Mapping):
            mode = "rw" if mount.get("rw") else "ro"
            yield Result(state=State.OK, notice=f"{mount.get('mountpoint')}: {mount.get('fstype')} {mode} from {mount.get('source')}")

# Cluster/source host sections
agent_section_harvester_settings = AgentSection(name="harvester_settings_v1", parse_function=_parse_json_section, host_label_function=_host_labels_harvester_settings)
check_plugin_harvester_version = CheckPlugin(name="harvester_version", service_name="Harvester version", sections=["harvester_settings_v1"], discovery_function=_discover_single, check_function=_check_harvester_version)
check_plugin_harvester_settings = CheckPlugin(name="harvester_settings", service_name="Harvester settings", sections=["harvester_settings_v1"], discovery_function=_discover_single, check_function=_check_harvester_settings)

agent_section_harvester_prometheus_status = AgentSection(name="harvester_prometheus_status_v1", parse_function=_parse_json_section)
check_plugin_harvester_prometheus_status = CheckPlugin(name="harvester_prometheus_status", service_name="Harvester Prometheus connection", sections=["harvester_prometheus_status_v1"], discovery_function=_discover_single, check_function=_check_prometheus_status)

agent_section_harvester_vm_images = AgentSection(name="harvester_vm_images_v1", parse_function=_parse_json_section)
check_plugin_harvester_vm_image = CheckPlugin(name="harvester_vm_image", service_name="Harvester VM image %s", sections=["harvester_vm_images_v1"], discovery_function=_discover_vm_images, check_function=_check_vm_image)

agent_section_harvester_platform_pods = AgentSection(name="harvester_platform_pods_v1", parse_function=_parse_json_section)
check_plugin_harvester_platform_pods = CheckPlugin(name="harvester_platform_pods", service_name="Harvester platform pods", sections=["harvester_platform_pods_v1"], discovery_function=_discover_single, check_function=_check_platform_pods)

agent_section_harvester_backup_targets = AgentSection(name="harvester_backup_targets_v1", parse_function=_parse_json_section)
check_plugin_harvester_backup_target = CheckPlugin(name="harvester_backup_target", service_name="Harvester backup target %s", sections=["harvester_backup_targets_v1"], discovery_function=_discover_backup_targets, check_function=_check_backup_target)

agent_section_longhorn_volume_summary = AgentSection(name="longhorn_volume_summary_v1", parse_function=_parse_json_section)
check_plugin_longhorn_volume_summary = CheckPlugin(name="longhorn_volume_summary", service_name="Longhorn volumes summary", sections=["longhorn_volume_summary_v1"], discovery_function=_discover_single, check_function=_check_longhorn_volume_summary)

agent_section_longhorn_volumes = AgentSection(name="longhorn_volumes_v1", parse_function=_parse_json_section)
check_plugin_longhorn_volume = CheckPlugin(name="longhorn_volume", service_name="Longhorn volume %s", sections=["longhorn_volumes_v1"], discovery_function=_discover_longhorn_volumes, check_function=_check_longhorn_volume)

agent_section_longhorn_replicas = AgentSection(name="longhorn_replicas_v1", parse_function=_parse_json_section)
check_plugin_longhorn_replicas = CheckPlugin(name="longhorn_replicas", service_name="Longhorn replicas", sections=["longhorn_replicas_v1"], discovery_function=_discover_single, check_function=_check_longhorn_replicas)

# Node piggyback sections
agent_section_harvester_node_info = AgentSection(name="harvester_node_info_v1", parse_function=_parse_json_section, host_label_function=_host_labels_node_info)
check_plugin_harvester_node_info = CheckPlugin(name="harvester_node_info", service_name="Harvester node info", sections=["harvester_node_info_v1"], discovery_function=_discover_single, check_function=_check_node_info)

agent_section_harvester_node_conditions = AgentSection(name="harvester_node_conditions_v1", parse_function=_parse_json_section)
check_plugin_harvester_node_conditions = CheckPlugin(name="harvester_node_conditions", service_name="Harvester node conditions", sections=["harvester_node_conditions_v1"], discovery_function=_discover_single, check_function=_check_node_conditions)

agent_section_harvester_node_metrics = AgentSection(name="harvester_node_metrics_v1", parse_function=_parse_json_section)
check_plugin_harvester_node_metrics = CheckPlugin(name="harvester_node_metrics", service_name="Harvester node metrics", sections=["harvester_node_metrics_v1"], discovery_function=_discover_single, check_function=_check_node_metrics)

agent_section_harvester_nodeconfig = AgentSection(name="harvester_nodeconfig_v1", parse_function=_parse_json_section)
check_plugin_harvester_nodeconfig = CheckPlugin(name="harvester_nodeconfig", service_name="Harvester node configuration", sections=["harvester_nodeconfig_v1"], discovery_function=_discover_single, check_function=_check_nodeconfig)

agent_section_harvester_blockdevices = AgentSection(name="harvester_blockdevices_v1", parse_function=_parse_json_section)
check_plugin_harvester_blockdevice = CheckPlugin(name="harvester_blockdevice", service_name="Harvester block device %s", sections=["harvester_blockdevices_v1"], discovery_function=_discover_blockdevices, check_function=_check_blockdevice)

agent_section_longhorn_node_status = AgentSection(name="longhorn_node_status_v1", parse_function=_parse_json_section)
check_plugin_longhorn_node_status = CheckPlugin(name="longhorn_node_status", service_name="Longhorn node status", sections=["longhorn_node_status_v1"], discovery_function=_discover_single, check_function=_check_longhorn_node_status)

agent_section_longhorn_disk_status = AgentSection(name="longhorn_disk_status_v1", parse_function=_parse_json_section)
check_plugin_longhorn_disk_status = CheckPlugin(name="longhorn_disk_status", service_name="Longhorn disk status %s", sections=["longhorn_disk_status_v1"], discovery_function=_discover_longhorn_disks, check_function=_check_longhorn_disk_status)

agent_section_longhorn_disk_usage = AgentSection(name="longhorn_disk_usage_v1", parse_function=_parse_json_section)
check_plugin_longhorn_disk_usage = CheckPlugin(name="longhorn_disk_usage", service_name="Longhorn disk usage %s", sections=["longhorn_disk_usage_v1"], discovery_function=_discover_longhorn_disks, check_function=_check_longhorn_disk_usage)


agent_section_harvester_node_local_os = AgentSection(name="harvester_node_local_os_v1", parse_function=_parse_json_section, host_label_function=_host_labels_local_os)
check_plugin_harvester_node_local_os = CheckPlugin(name="harvester_node_local_os", service_name="Harvester node local OS context", sections=["harvester_node_local_os_v1"], discovery_function=_discover_single, check_function=_check_node_local_os)

agent_section_harvester_node_local_processes = AgentSection(name="harvester_node_local_processes_v1", parse_function=_parse_json_section)
check_plugin_harvester_node_local_processes = CheckPlugin(name="harvester_node_local_processes", service_name="Harvester node local processes", sections=["harvester_node_local_processes_v1"], discovery_function=_discover_single, check_function=_check_node_local_processes)

agent_section_harvester_node_local_mounts = AgentSection(name="harvester_node_local_mounts_v1", parse_function=_parse_json_section)
check_plugin_harvester_node_local_mounts = CheckPlugin(name="harvester_node_local_mounts", service_name="Harvester node local mounts", sections=["harvester_node_local_mounts_v1"], discovery_function=_discover_single, check_function=_check_node_local_mounts)
