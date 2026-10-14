#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""Server-side call for the Harvester special agent."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from cmk.server_side_calls.v1 import HostConfig, SpecialAgentCommand, SpecialAgentConfig


def _parse_params(params: object) -> dict[str, Any]:
    if isinstance(params, dict):
        return params
    raise TypeError(params)


def _endpoint_value(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    raise TypeError(value)


def _agent_arguments(params: dict[str, Any], host_config: HostConfig) -> Iterable[SpecialAgentCommand]:
    api = _endpoint_value(params["kubernetes_api_server"])
    prom = _endpoint_value(params["prometheus"])
    args: list[str] = [
        "--cluster", str(params["cluster_name"]),
        "--kubernetes-cluster-hostname", host_config.name,
        "--token-id", params["token"],
        "--api-server-endpoint", str(api["endpoint_v2"]),
        "--prometheus-endpoint", str(prom["endpoint_v2"]),
    ]
    if api.get("verify_cert"):
        args.append("--verify-cert-api")
    if proxy := api.get("proxy"):
        args.extend(["--api-server-proxy", str(proxy)])
    if timeout := api.get("timeout"):
        if timeout.get("connect") is not None:
            args.extend(["--k8s-api-connect-timeout", str(timeout["connect"])])
        if timeout.get("read") is not None:
            args.extend(["--k8s-api-read-timeout", str(timeout["read"])])

    if prom.get("token") is not None:
        args.extend(["--prometheus-token-id", prom["token"]])
    if prom.get("verify_cert"):
        args.append("--usage-verify-cert")
    if proxy := prom.get("proxy"):
        args.extend(["--usage-proxy", str(proxy)])
    if timeout := prom.get("timeout"):
        if timeout.get("connect") is not None:
            args.extend(["--usage-connect-timeout", str(timeout["connect"])])
        if timeout.get("read") is not None:
            args.extend(["--usage-read-timeout", str(timeout["read"])])

    if mode := params.get("node_hostname_mode"):
        args.extend(["--node-hostname-mode", str(mode)])

    match params.get("nodes"):
        case ("node_include_patterns", patterns):
            for pattern in patterns:
                args.extend(["--node-include-patterns", pattern])
        case ("node_exclude_patterns", patterns):
            for pattern in patterns:
                args.extend(["--node-exclude-patterns", pattern])

    if thresholds := params.get("thresholds"):
        if isinstance(thresholds, dict):
            threshold_map = {
                "node_cpu_usage_warn": "--node-cpu-usage-warn",
                "node_cpu_usage_crit": "--node-cpu-usage-crit",
                "node_memory_usage_warn": "--node-memory-usage-warn",
                "node_memory_usage_crit": "--node-memory-usage-crit",
                "longhorn_disk_usage_warn": "--longhorn-disk-usage-warn",
                "longhorn_disk_usage_crit": "--longhorn-disk-usage-crit",
                "backup_target_not_configured_state": "--backup-target-not-configured-state",
                "longhorn_degraded_volume_state": "--longhorn-degraded-volume-state",
                "longhorn_degraded_volume_single_node_state": "--longhorn-degraded-volume-single-node-state",
            }
            for key, option in threshold_map.items():
                if thresholds.get(key) is not None:
                    args.extend([option, str(thresholds[key])])

    if collector := params.get("node_collector"):
        if isinstance(collector, dict) and collector.get("enabled"):
            args.append("--enable-node-collector-logs")
            if namespace := collector.get("namespace"):
                args.extend(["--node-collector-namespace", str(namespace)])
            if selector := collector.get("label_selector"):
                args.extend(["--node-collector-label-selector", str(selector)])
            if container := collector.get("container"):
                args.extend(["--node-collector-container", str(container)])
            if max_age := collector.get("max_age"):
                args.extend(["--node-collector-max-age", str(max_age)])

    yield SpecialAgentCommand(command_arguments=args)


special_agent_harvester = SpecialAgentConfig(
    name="harvester",
    parameter_parser=_parse_params,
    commands_function=_agent_arguments,
)
