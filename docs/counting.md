# How findings are counted

## Images

An image is its registry, repository and digest. When several pods or containers run the same digest, its findings count once. Totals on the overview add up images, not containers.

The Trivy Operator writes a report per container. Gjallarhorn keeps the first report for each digest and drops findings that repeat the same CVE, package, version and file.

## Workloads

Reports on a ReplicaSet are shown under the Deployment that owns it, looked up from the ReplicaSet's owner reference. When a Deployment has old ReplicaSets that are still reported, their images appear under it too.

## CVEs

A CVE's severity is the highest any image reports for it, and its score the highest CVSS score. It is "fixable" when at least one affected package has a fixed version.

## Not rated

Trivy reports severity `UNKNOWN` when the vendor has not rated a CVE yet, which is common for the newest ones, even when a CVSS score already exists. Gjallarhorn calls these "not rated", counts them, and keeps them out of the bars and the "fix first" ranking, because there can be many of them and they would hide the rated ones.

## Fixed versions

Only findings the Trivy Operator reports are counted. With `trivy.ignoreUnfixed: true` it skips CVEs that have no fix, so every finding shown has a fixed version.
