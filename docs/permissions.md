# Permissions

The chart creates a ClusterRole with:

- `get` and `list` on `vulnerabilityreports`, `configauditreports`, `clusterconfigauditreports`, `rbacassessmentreports`, `clusterrbacassessmentreports`, `exposedsecretreports` and `clustercompliancereports` in `aquasecurity.github.io`.
- `list` on `replicasets`, to show reports under their Deployment. Without it, they show under the ReplicaSet.

Nothing else: no Secrets, no Pods, and no write access of any kind.

`exposedsecretreports` contain the matched secret text, partly masked by Trivy. Gjallarhorn's parser skips that field, so it is never kept in memory or served, but the service account can read it. If that is a concern, remove `exposedsecretreports` from the role and the Secrets page stays empty.

The dashboard has no login. Anyone who can open the page sees which images are vulnerable. See [Install](install.md).
