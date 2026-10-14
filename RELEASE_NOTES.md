# Harvester v0.1.1

Patch release addressing API failure visibility and credential isolation.

- The Harvester special agent now fails visibly when the Kubernetes API returns 401/403 or other unexpected errors, or when it cannot reach the API server.
- HTTP 404 is treated as an empty list only for explicitly optional Harvester/Longhorn CRDs. Kubernetes nodes, pods and Harvester settings remain mandatory.
- Invalid API list payloads now fail instead of silently removing services.
- The Kubernetes token is no longer sent to Prometheus. Prometheus bearer authentication can be configured separately, if needed.
- Automatic redirects for API requests are disabled to avoid forwarding credentials.

**Compatibility:** Existing source-host checks and node piggyback names remain unchanged. For Prometheus endpoints that previously required the Kubernetes token, configure independent Prometheus authentication in the Harvester rule. On installations using unauthenticated Prometheus, no new configuration is necessary.

Test on Checkmk 2.5 before upgrading production. No changes are required to the node collector DaemonSet or Kubernetes RBAC manifest.
