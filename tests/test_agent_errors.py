# SPDX-License-Identifier: GPL-2.0-only
# Copyright (C) 2026 Sudhir Chauhan

"""Network/credential regression tests without a full Checkmk site."""

from __future__ import annotations

import argparse
import runpy
import sys
import types
from pathlib import Path

import pytest
import requests

AGENT_PATH = Path(__file__).resolve().parents[1] / "cmk_addons/plugins/harvester/libexec/agent_harvester"


@pytest.fixture()
def agent(monkeypatch):
    # The agent has one Checkmk-only import; stub it so HTTP handling can be
    # tested with plain pytest outside an OMD site.
    cmk = types.ModuleType("cmk")
    cmk.__path__ = []
    password_store = types.ModuleType("cmk.password_store")
    password_store.__path__ = []
    api = types.ModuleType("cmk.password_store.v1_unstable")
    api.parser_add_secret_option = lambda *args, **kwargs: None
    api.resolve_secret_option = lambda *args, **kwargs: None
    monkeypatch.setitem(sys.modules, "cmk", cmk)
    monkeypatch.setitem(sys.modules, "cmk.password_store", password_store)
    monkeypatch.setitem(sys.modules, "cmk.password_store.v1_unstable", api)
    return runpy.run_path(str(AGENT_PATH), run_name="harvester_test")


class FakeSession:
    def __init__(self, status=200, payload=None, error=None):
        self.status = status
        self.payload = payload if payload is not None else {"items": []}
        self.error = error
        self.headers = {}
        self.urls = []
        self.kwargs = []

    def get(self, url, **kwargs):
        self.urls.append(url)
        self.kwargs.append(kwargs)
        if self.error is not None:
            raise self.error
        resp = requests.Response()
        resp.url = url
        resp.status_code = self.status
        resp._content = __import__("json").dumps(self.payload).encode()
        return resp

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


@pytest.mark.parametrize("status", [401, 403, 404, 429, 500, 503])
def test_nonoptional_http_errors_fail(agent, status):
    with pytest.raises(requests.HTTPError) as excinfo:
        agent["_list_items"](FakeSession(status=status), "https://api.example", "/api/v1/nodes")
    assert excinfo.value.response.status_code == status


@pytest.mark.parametrize("status", [401, 403, 429, 500, 503])
def test_optional_crd_does_not_hide_other_http_errors(agent, status):
    with pytest.raises(requests.HTTPError):
        agent["_list_items"](FakeSession(status=status), "https://api.example", "/apis/longhorn.io/v1beta2/volumes", optional=True)


def test_optional_crd_404_is_empty(agent):
    assert agent["_list_items"](FakeSession(status=404), "https://api.example", "/apis/longhorn.io/v1beta2/volumes", optional=True) == []


@pytest.mark.parametrize("exc", [requests.ConnectionError("offline"), requests.Timeout("timed out")])
def test_network_errors_are_fatal(agent, exc):
    with pytest.raises(requests.RequestException):
        agent["_list_items"](FakeSession(error=exc), "https://api.example", "/api/v1/nodes", optional=True)


def test_legitimate_empty_list_and_resources(agent):
    assert agent["_list_items"](FakeSession(payload={"items": []}), "https://api.example", "/api/v1/nodes") == []
    payload = {"items": [{"metadata": {"name": "node-a"}}, "invalid item"]}
    assert agent["_list_items"](FakeSession(payload=payload), "https://api.example", "/api/v1/nodes") == [payload["items"][0]]


@pytest.mark.parametrize("payload", [{}, {"items": None}, {"items": {}}, {"kind": "Status", "message": "failed"}])
def test_malformed_list_is_not_empty_cluster(agent, payload):
    with pytest.raises(RuntimeError, match="Invalid Kubernetes list response"):
        agent["_list_items"](FakeSession(payload=payload), "https://api.example", "/api/v1/nodes")


def test_redirect_rejected_without_following_it(agent):
    session = FakeSession(status=302)
    with pytest.raises(requests.HTTPError, match="Refusing HTTP redirect"):
        agent["_list_items"](session, "https://api.example", "/api/v1/nodes")
    assert len(session.urls) == 1
    assert session.kwargs[0]["allow_redirects"] is False


def _args():
    return argparse.Namespace(
        verify_cert_api=True, api_server_endpoint="https://api.example", api_server_proxy="NO_PROXY",
        k8s_api_connect_timeout=10, k8s_api_read_timeout=20,
        enable_node_collector_logs=False,
        prometheus_endpoint="http://localhost:9090", usage_verify_cert=False, usage_proxy="NO_PROXY",
        usage_connect_timeout=10, usage_read_timeout=20,
    )


def test_collect_api_404_only_for_optional_crds(agent, monkeypatch):
    sess = FakeSession()
    optional_suffix = "/apis/node.harvesterhci.io/v1beta1/nodeconfigs"
    def get_with_optional_missing(url, **kwargs):
        if url.endswith(optional_suffix):
            return FakeSession(status=404).get(url, **kwargs)
        return FakeSession(status=200).get(url, **kwargs)
    sess.get = get_with_optional_missing
    monkeypatch.setattr(agent["collect_api"].__globals__["requests"], "Session", lambda: sess)
    result = agent["collect_api"](_args(), "api-only-token")
    assert result["nodes"] == [] and result["harvester_nodeconfigs"] == []
    assert sess.headers["Authorization"] == "Bearer api-only-token"


def test_collect_api_fails_when_core_nodes_unavailable(agent, monkeypatch):
    sess = FakeSession(status=403)
    monkeypatch.setattr(agent["collect_api"].__globals__["requests"], "Session", lambda: sess)
    with pytest.raises(requests.HTTPError):
        agent["collect_api"](_args(), "api-only-token")


def test_prometheus_never_implicitly_uses_kubernetes_token(agent, monkeypatch):
    sess = FakeSession()
    monkeypatch.setattr(agent["collect_prometheus"].__globals__["requests"], "Session", lambda: sess)
    observed = []
    def fake_query(session, endpoint, query, **kwargs):
        observed.append(session.headers.get("Authorization"))
        return [], True, None
    agent["collect_prometheus"].__globals__["_prom_query_with_status"] = fake_query
    samples, status = agent["collect_prometheus"](_args())
    assert observed and all(value is None for value in observed)
    assert status["failed_query_count"] == 0


def test_prometheus_explicit_token_only(agent, monkeypatch):
    sess = FakeSession()
    monkeypatch.setattr(agent["collect_prometheus"].__globals__["requests"], "Session", lambda: sess)
    observed = []
    def fake_query(session, endpoint, query, **kwargs):
        observed.append(session.headers.get("Authorization"))
        return [], True, None
    agent["collect_prometheus"].__globals__["_prom_query_with_status"] = fake_query
    agent["collect_prometheus"](_args(), "prometheus-only-token")
    assert set(observed) == {"Bearer prometheus-only-token"}


@pytest.mark.parametrize("endpoint,verify,accepted", [
    ("http://prometheus.example:9090", False, False),
    ("https://prometheus.example:9090", False, False),
    ("https://prometheus.example:9090", True, True),
    ("http://127.0.0.1:9090", False, True),
    ("https://localhost:9090", False, True),
])
def test_explicit_prometheus_token_transport(agent, endpoint, verify, accepted):
    if accepted:
        agent["_validate_prometheus_token_transport"](endpoint, verify)
    else:
        with pytest.raises(ValueError, match="verified HTTPS"):
            agent["_validate_prometheus_token_transport"](endpoint, verify)


def test_main_returns_nonzero_on_api_failure(agent, monkeypatch, capsys):
    main = agent["main"]
    env = main.__globals__
    args = _args()
    args.verbose = 0
    args.debug = False
    env["parse_args"] = lambda argv: args
    env["_resolve_token"] = lambda args: "token"
    env["collect_api"] = lambda args, token: agent["_list_items"](FakeSession(status=401), "https://api.example", "/api/v1/nodes")
    assert main([]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "401" in captured.err
