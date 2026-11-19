# Install

Gjallarhorn needs the [Trivy Operator](https://aquasecurity.github.io/trivy-operator/) installed and scanning. Install the chart:

```bash
helm install gjallarhorn oci://ghcr.io/diverofdark/charts/gjallarhorn \
  --namespace gjallarhorn --create-namespace \
  --set ingress.enabled=true \
  --set 'ingress.hosts[0].host=security.example.com' \
  --set 'ingress.hosts[0].paths[0].path=/' \
  --set 'ingress.hosts[0].paths[0].pathType=Prefix'
```

The chart also lives in this repository under `charts/gjallarhorn`, which is what an Argo CD Application can point at.

Gjallarhorn has no login. The page tells anyone who opens it which of your images are vulnerable and how. Keep the Ingress on a private network, or put an authenticating proxy such as oauth2-proxy in front of it.

The first read takes a few seconds; until then the page shows "Loading". If the Trivy Operator is installed but has not finished its first scans, the page is mostly empty and fills in as reports arrive.

## Resources

Memory grows with the number of reports. As a starting point:

```yaml
resources:
  requests: { cpu: 20m, memory: 192Mi }
  limits: { memory: 512Mi }
```
