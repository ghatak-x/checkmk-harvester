#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""Ruleset for the Harvester special agent."""

from __future__ import annotations

from cmk.rulesets.v1 import Help, Label, Title
from cmk.rulesets.v1.form_specs import (
    BooleanChoice,
    CascadingSingleChoice,
    CascadingSingleChoiceElement,
    DefaultValue,
    DictElement,
    Dictionary,
    InputHint,
    Integer,
    List,
    MatchingScope,
    Password,
    RegularExpression,
    SingleChoice,
    SingleChoiceElement,
    String,
    validators,
    migrate_to_password,
)
from cmk.rulesets.v1.rule_specs import SpecialAgent, Topic


def _migrate_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise TypeError(value)
    return {k.replace("-", "_"): v for k, v in value.items()}


def _timeout_form() -> Dictionary:
    return Dictionary(
        title=Title("TCP timeouts"),
        elements={
            "connect": DictElement(required=False, parameter_form=Integer(title=Title("Connect timeout"), prefill=DefaultValue(10))),
            "read": DictElement(required=False, parameter_form=Integer(title=Title("Read timeout"), prefill=DefaultValue(20))),
        },
    )


def _node_collector_form() -> Dictionary:
    return Dictionary(
        title=Title("Optional Harvester node collector"),
        help_text=Help("Optional DaemonSet-based collector for node-local OS context, selected mounts, processes and standard Linux-style Checkmk sections."),
        elements={
            "enabled": DictElement(required=True, parameter_form=BooleanChoice(title=Title("Enable node collector log ingestion"), label=Label("Read node collector DaemonSet pod logs"), prefill=DefaultValue(False))),
            "namespace": DictElement(required=False, parameter_form=String(title=Title("Collector namespace"), prefill=InputHint("checkmk-monitoring"))),
            "label_selector": DictElement(required=False, parameter_form=String(title=Title("Collector pod label selector"), prefill=InputHint("checkmk.io/collector=harvester-node"))),
            "container": DictElement(required=False, parameter_form=String(title=Title("Collector container name"), prefill=InputHint("collector"))),
            "max_age": DictElement(required=False, parameter_form=Integer(title=Title("Maximum collector payload age in seconds"), prefill=DefaultValue(600))),
        },
    )


def _state_choice(title: str, default: str) -> SingleChoice:
    return SingleChoice(
        title=Title(title),
        prefill=DefaultValue(default),
        elements=[
            SingleChoiceElement(name="ok", title=Title("OK")),
            SingleChoiceElement(name="warn", title=Title("WARN")),
            SingleChoiceElement(name="crit", title=Title("CRIT")),
        ],
    )


def _thresholds_form() -> Dictionary:
    return Dictionary(
        title=Title("Thresholds and state handling"),
        help_text=Help("Harvester and Longhorn custom checks only. Standard Checkmk services such as filesystems, interfaces, memory, CPU load and process discovery use the built-in Checkmk rules."),
        elements={
            "node_cpu_usage_warn": DictElement(required=False, parameter_form=Integer(title=Title("Node CPU usage WARN percent"), prefill=DefaultValue(80))),
            "node_cpu_usage_crit": DictElement(required=False, parameter_form=Integer(title=Title("Node CPU usage CRIT percent"), prefill=DefaultValue(90))),
            "node_memory_usage_warn": DictElement(required=False, parameter_form=Integer(title=Title("Node memory usage WARN percent"), prefill=DefaultValue(80))),
            "node_memory_usage_crit": DictElement(required=False, parameter_form=Integer(title=Title("Node memory usage CRIT percent"), prefill=DefaultValue(90))),
            "longhorn_disk_usage_warn": DictElement(required=False, parameter_form=Integer(title=Title("Longhorn disk usage WARN percent"), prefill=DefaultValue(80))),
            "longhorn_disk_usage_crit": DictElement(required=False, parameter_form=Integer(title=Title("Longhorn disk usage CRIT percent"), prefill=DefaultValue(90))),
            "backup_target_not_configured_state": DictElement(required=False, parameter_form=_state_choice("State if backup target is not configured", "warn")),
            "longhorn_degraded_volume_state": DictElement(required=False, parameter_form=_state_choice("State for degraded Longhorn volumes", "warn")),
            "longhorn_degraded_volume_single_node_state": DictElement(required=False, parameter_form=_state_choice("State for degraded Longhorn volumes in single-node clusters", "warn")),
        },
    )


def _endpoint_form(title: str, help_text: str, hint: str, *, optional_auth: bool = False) -> Dictionary:
    elements = {
        "endpoint_v2": DictElement(required=True, parameter_form=String(title=Title("Endpoint"), prefill=InputHint(hint), custom_validate=(validators.LengthInRange(min_value=1),), help_text=Help(help_text))),
        "verify_cert": DictElement(required=True, parameter_form=BooleanChoice(title=Title("SSL certificate verification"), label=Label("Verify certificate"), prefill=DefaultValue(True))),
        "proxy": DictElement(required=False, parameter_form=String(title=Title("Proxy"), help_text=Help("Use FROM_ENVIRONMENT, NO_PROXY, or a proxy URL."), prefill=InputHint("FROM_ENVIRONMENT"))),
        "timeout": DictElement(required=False, parameter_form=_timeout_form()),
    }
    if optional_auth:
        elements["token"] = DictElement(
            required=False,
            parameter_form=Password(
                title=Title("Prometheus bearer token (optional)"),
                help_text=Help("Independent Prometheus credential. The Kubernetes API token is not automatically sent to Prometheus. Remote authenticated endpoints require verified HTTPS."),
                migrate=migrate_to_password,
            ),
        )
    return Dictionary(title=Title(title), migrate=_migrate_dict, elements=elements)


def _migrate_nodes(value: object) -> tuple[str, object]:
    match value:
        case (str(name), patterns):
            return (name.replace("-", "_"), patterns)
    raise TypeError(value)


def _parameter_form() -> Dictionary:
    return Dictionary(
        title=Title("Harvester"),
        migrate=_migrate_dict,
        elements={
            "cluster_name": DictElement(required=True, parameter_form=String(title=Title("Cluster name"), custom_validate=(validators.LengthInRange(min_value=1),), help_text=Help("Used to make node piggyback host names unique."))),
            "token": DictElement(required=True, parameter_form=Password(title=Title("Bearer token"), custom_validate=(validators.LengthInRange(min_value=1),), migrate=migrate_to_password)),
            "kubernetes_api_server": DictElement(required=True, parameter_form=_endpoint_form("Kubernetes API server", "Endpoint used to query Harvester, Kubernetes and Longhorn API resources.", "https://api.example:6443")),
            "prometheus": DictElement(required=True, parameter_form=_endpoint_form("Prometheus endpoint", "Prometheus base URL used for node_*, kube_node_* and longhorn_* metrics. Do not append /api/v1/query.", "https://prometheus.example:9090", optional_auth=True)),
            "node_hostname_mode": DictElement(required=False, parameter_form=SingleChoice(
                title=Title("Node piggyback host name"),
                prefill=DefaultValue("prefixed"),
                elements=[
                    SingleChoiceElement(name="prefixed", title=Title("Prefix with cluster name, e.g. harvester_node_<cluster>_<node>")),
                    SingleChoiceElement(name="node_name", title=Title("Use Kubernetes node name directly")),
                ],
            )),
            "nodes": DictElement(required=False, parameter_form=CascadingSingleChoice(
                title=Title("Nodes"), migrate=_migrate_nodes,
                elements=[
                    CascadingSingleChoiceElement(name="node_include_patterns", title=Title("Monitor nodes matching"), parameter_form=List(element_template=RegularExpression(predefined_help_text=MatchingScope.INFIX, custom_validate=(validators.LengthInRange(min_value=1),)), add_element_label=Label("Add pattern"))),
                    CascadingSingleChoiceElement(name="node_exclude_patterns", title=Title("Exclude nodes matching"), parameter_form=List(element_template=RegularExpression(predefined_help_text=MatchingScope.INFIX, custom_validate=(validators.LengthInRange(min_value=1),)), add_element_label=Label("Add pattern"))),
                ],
            )),
            "thresholds": DictElement(required=False, parameter_form=_thresholds_form()),
            "node_collector": DictElement(required=False, parameter_form=_node_collector_form()),
        },
    )


rule_spec_special_agent_harvester = SpecialAgent(
    name="harvester",
    title=Title("Harvester"),
    topic=Topic.VIRTUALIZATION,
    parameter_form=_parameter_form,
)
