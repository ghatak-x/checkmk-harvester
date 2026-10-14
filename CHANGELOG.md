# Changelog

## 0.1.1

- Make Kubernetes API authentication, permission, network, timeout, and server failures visible as special-agent errors instead of silently treating them as empty lists.
- Skip HTTP 404 only for explicitly optional Harvester and Longhorn resource lists; required Kubernetes nodes, pods, and Harvester settings remain mandatory.
- Reject malformed Kubernetes list responses instead of silently assuming the list is empty.
- Use an independent, optional Prometheus bearer token. Never send the Kubernetes API bearer token to Prometheus implicitly, and reject unsafe remote bearer-token transports.
- Disable automatic HTTP redirects for credential-bearing API requests.
- Add regression tests for API failures, optional resource discovery and Prometheus credential separation.

## 0.1.0

Initial public release.
