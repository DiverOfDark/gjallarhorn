# Overview

The overview is built to tell you what to do next, not only how bad things are.

## Fix first

The headline counts the critical findings in the five images that hold the most of them, out of all critical findings in the cluster: "Five images carry 27 of your 31 critical vulnerabilities." When there are no critical findings it uses high ones instead.

The bar under the headline is every critical finding in the cluster. The numbered segments are the five images, sized by their share; the hatched part is everything else. Each segment and each row of the list opens that image.

When every one of those findings has a fixed version, the text says so. That is the common case when the Trivy Operator runs with `trivy.ignoreUnfixed: true`.

## Totals

Below the headline are the totals by severity, each a link to the [CVE list](images.md#cves) filtered to that severity. Findings that are too new to have a vendor severity are counted separately as "not rated" and kept out of the bar, see [How findings are counted](counting.md#not-rated).

The row under the totals links to the other report types: misconfigured resources, critical RBAC risks, secrets found in images, and images on an end-of-life OS.

## Namespaces

Namespaces sorted by critical, then high findings. The switch above the table measures them by vulnerabilities, workload misconfigurations or RBAC findings. A row opens the namespace's workloads, or its misconfigurations.

## Lists on the right

- **New this month**: critical and high CVEs published in the last 30 days that affect at least one image.
- **Most widespread**: the CVEs that reach the most images.
- **Compliance**: each compliance report with its failing controls, or "not run yet".

The header shows when the reports were last read. **Refresh** reads them again now.
