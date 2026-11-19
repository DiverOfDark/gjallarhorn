# Endpoints

Everything is on one port, 8080 by default.

| Path | Purpose |
| --- | --- |
| `/` | The dashboard. Routes after `#/` are handled in the browser. |
| `/healthz` | Liveness. Answers `ok` once the server is up, before the first read finishes. |
| `/api/status` | Whether a snapshot is ready, whether a read is running, when the last one finished, and the last error. |
| `/api/overview` | Everything the overview shows. |
| `/api/images`, `/api/images/{id}` | Images, and one image with its findings, workloads and secrets. |
| `/api/cves`, `/api/cves/{id}` | CVEs, and one CVE with every affected image. |
| `/api/workloads` | Workloads with their images and counts. |
| `/api/misconfigs` | Failed configuration and RBAC checks, by resource. |
| `/api/secrets` | Exposed secrets, without the matched text. |
| `/api/compliance` | Compliance reports and their controls. |
| `POST /api/refresh` | Read the reports again now. |

Until the first read finishes, the data endpoints answer `503` with `{"error": "loading reports…"}`. Responses are gzip-compressed when the client accepts it.
