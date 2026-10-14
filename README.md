# checkmk-harvester

Checkmk special agent for Harvester clusters.

The integration monitors Harvester platform objects, Longhorn storage, Kubernetes node information and optional node-local context collected by a DaemonSet.

## Status

Initial community release. The package has been validated in a lab environment; test it in your own Checkmk site before production rollout.

## Target platforms

- Harvester
- Harvester-based SUSE Virtualization environments

## Features

- Harvester version, settings, backup target, VM images and platform pod health
- Longhorn volume, replica, node, disk status and usage checks
- Harvester node piggyback hosts with labels for SUSE Linux Micro / SLES identity
- Optional DaemonSet node collector that emits native Checkmk sections for CPU/load, memory, uptime, filesystems, disk I/O, interfaces and process discovery
- No SSH and no full Checkmk OS agent required on Harvester nodes for the optional node-collector path

## Repository layout

```text
cmk_addons/plugins/harvester/   Checkmk add-on source tree
docs/                           Kubernetes RBAC and node-collector manifests
tools/build_mkp.py              MKP packaging helper
tests/                          Static packaging and syntax tests
dist/                           Build output, created locally
```

## Installation

Build the MKP locally or download it from a GitHub release / Checkmk Exchange page:

```bash
python tools/build_mkp.py
mkp add dist/harvester-0.1.2.mkp
mkp enable harvester 0.1.2
cmk -R
```

The package can also be uploaded through the Checkmk GUI under **Setup > Extension packages**.

## Kubernetes manifests

This repository contains two manifest files under `docs/`.

### `docs/harvester_rbac.yaml`

Creates the `checkmk-monitoring` namespace, the `checkmk-harvester` ServiceAccount and read-only RBAC for the Kubernetes, Harvester and Longhorn resources that the special agent reads.

Apply it before configuring the Checkmk rule:

```bash
kubectl apply -f docs/harvester_rbac.yaml
kubectl -n checkmk-monitoring create token checkmk-harvester
```

Store the generated token in the Checkmk password store and reference it from the Harvester special agent rule. The token is used **only** for the Kubernetes API. Expired tokens (401), forbidden resources (403), API failures and connection errors cause the special agent to fail visibly rather than silently dropping host services. The special agent skips HTTP 404 only for explicitly optional Harvester/Longhorn resources; the nodes, pods and Harvester settings lists are mandatory.

### `docs/harvester_node_collector.yaml`

Optional. Deploy this only when you enable **Read node collector DaemonSet pod logs** in the Harvester special agent rule.

The node collector DaemonSet reads selected node-local files through read-only host mounts and writes a small JSON payload to its pod log. The Checkmk special agent then reads those pod logs through the Kubernetes API and converts the data into piggyback sections for the Harvester node host. This is why it is needed for node-local checks such as native Checkmk CPU/load, memory, uptime, disk I/O, interfaces and process discovery without installing a full Checkmk OS agent or using SSH.

Apply or update it with:

```bash
kubectl apply -f docs/harvester_node_collector.yaml
kubectl -n checkmk-monitoring rollout restart daemonset/checkmk-harvester-node-collector
kubectl -n checkmk-monitoring rollout status daemonset/checkmk-harvester-node-collector
```

## Configuration

1. Apply `docs/harvester_rbac.yaml` and create/store a token for the `checkmk-harvester` ServiceAccount.
2. Create a host in Checkmk for the Harvester cluster/source endpoint.
3. Configure the **Harvester** special agent rule with the API endpoint, token, Prometheus endpoint and cluster name. Prometheus authentication is **independent and optional**; it does not receive the Kubernetes API token automatically. Configure a separate Prometheus bearer token in the Prometheus endpoint section only if needed. For remote endpoints, use verified HTTPS with bearer authentication.
4. Optionally deploy `docs/harvester_node_collector.yaml` and enable node collector log ingestion in the rule.
5. Run service discovery on the source host and generated Harvester node piggyback hosts.

## Relationship to checkmk-kubevirt

This package focuses on Harvester platform, Longhorn and node monitoring. To monitor KubeVirt VMs as VM piggyback hosts, install and configure the separate `checkmk-kubevirt` package in addition.

## Development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
pytest
python tools/build_mkp.py
```

## License

GPL-2.0-only. See `LICENSE`.

## Upgrading to v0.1.2

Longhorn PVC-bound volume service items now use `namespace/pvc`, eliminating collisions between PVCs with the same name in different namespaces. Use Checkmk service discovery to accept the new services and remove the old bare-PVC services. Existing history is not automatically transferred.

Harvester-discovered host labels now use `harvester/` rather than Checkmk-reserved `cmk/harvester/`. Dynamic values (counts, IPs, version strings, operational flags) are no longer host labels. Update any rules matching old labels and run host-label discovery. Cluster/node status and other operational details remain available via their checks.

Optional collector log data is validated against the pod's Kubernetes node assignment and sanitized to prevent additional Checkmk sections or arbitrary piggyback hosts from being introduced via log contents.
