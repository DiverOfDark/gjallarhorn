# Configuration

## Chart values

| Key | Meaning | Default |
| --- | --- | --- |
| `image.repository`, `image.tag`, `image.pullPolicy` | The image. | `ghcr.io/diverofdark/gjallarhorn`, `latest`, `IfNotPresent` |
| `refreshSeconds` | Seconds between reads of the reports. | `120` |
| `logLevel` | Log filter, e.g. `gjallarhorn=debug,warn`. | `gjallarhorn=info,warn` |
| `ingress.*` | A standard Ingress: `className`, `annotations`, `labels`, `hosts`, `tls`. | off |
| `service.type`, `service.port` | The Service. | `ClusterIP`, `8080` |
| `rbac.create` | Create the ClusterRole and its binding, see [Permissions](permissions.md). | `true` |
| `serviceAccount.annotations` | Annotations on the service account. | `{}` |
| `additionalObjects` | Extra manifests rendered with the release, passed through `tpl`. | `[]` |
| `podAnnotations`, `podLabels`, `resources`, `nodeSelector`, `tolerations`, `affinity` | The usual pod settings. | empty |

## Flags

The binary reads flags or the matching environment variables. The chart sets them for you.

| Flag | Environment | Meaning | Default |
| --- | --- | --- | --- |
| `--bind` | `GJALLARHORN_BIND` | Address to listen on. The image sets `0.0.0.0:8080`. | `127.0.0.1:8080` |
| `--refresh` | `GJALLARHORN_REFRESH` | Seconds between reads of the reports. | `120` |
| `--context` | `GJALLARHORN_CONTEXT` | Kubeconfig context. In a pod the service account is used. | current context |
| `--fixtures` | `GJALLARHORN_FIXTURES` | Serve reports from a JSON file instead of a cluster, see [Development](development.md). | off |
| | `RUST_LOG` | Log filter. | `info` |
