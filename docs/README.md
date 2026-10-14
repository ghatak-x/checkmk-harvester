# Kubernetes manifests

`harvester_rbac.yaml` creates the ServiceAccount and read-only RBAC used by the Harvester special agent.

`harvester_node_collector.yaml` is optional and deploys the DaemonSet used for node-local context. Deploy it only when node collector log ingestion is enabled in the Checkmk rule.
