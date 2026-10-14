# Harvester v0.1.2

Corrective release addressing three additional code-review findings:

- **Longhorn service identities:** PVC-backed volumes now use `namespace/pvc` instead of bare PVC names; volumes without complete PVC metadata fall back to their Longhorn volume ID. Checks and discovery use the same identity.
- **Host labels:** Checkmk-reserved `cmk/harvester/...` labels are replaced by plugin-owned `harvester/...` labels. Dynamic values such as node/disk counts, IPs, version strings and collector availability are omitted as host labels; they remain visible in relevant service output where available.
- **Node collector output validation:** Section/piggyback delimiter lines from collector logs are filtered, including embedded-line delimiters. Collector-reported node identity must exactly match the Kubernetes pod's `spec.nodeName`; mismatches are marked unavailable for that pod's node.

**Upgrade notice:** After upgrading, run service and host-label discovery on the Harvester cluster and its piggyback nodes. Longhorn PVC service names change (for example, `Longhorn volume mypvc` becomes `Longhorn volume default/mypvc`), creating new Checkmk services; old service graphs do not migrate automatically. Update rules referencing `cmk/harvester/*` host labels to `harvester/*` or remove references to labels that were deliberately dropped. Other service names and piggyback host naming remain unchanged.

Includes all 0.1.1 corrections for Kubernetes API error handling and Prometheus credential isolation. Test the MKP on Checkmk 2.5 before uploading the release to GitHub/Exchange.
