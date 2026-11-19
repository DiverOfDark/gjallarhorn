# Misconfigurations and RBAC

The page has two report types, switched at the top:

- **Workload config**: `ConfigAuditReport` and `ClusterConfigAuditReport`. Checks such as running as root, a writable root file system, host networking or privileged containers.
- **RBAC**: `RbacAssessmentReport` and `ClusterRbacAssessmentReport`. Roles and bindings that grant too much, such as managing Secrets or wildcard verbs.

Only failed checks are listed, and resources where everything passes are left out.

**By resource** lists each resource with its failed checks by severity. Click a row for each check's message and how to fix it.

**By check** turns it around: each failed check with how many resources fail it and the fix. Click a row for the list of resources. This is the quicker view when one setting is wrong in many places.

Filter by severity or by text: namespace, name or check.

Infrastructure such as CSI drivers or a CNI often needs host access and fails several checks by design. Those findings are accurate; whether they matter is your call.
