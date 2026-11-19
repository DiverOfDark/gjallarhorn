# Compliance

One section per `ClusterComplianceReport`, for example the NSA Kubernetes Hardening Guidance or the Pod Security Standards. Each control shows its id, name, severity and how many resources fail it, or "Pass".

The Trivy Operator produces these reports on a schedule, every six hours by default. Until the first run a report shows "First run pending" with its schedule.

The specs are chosen in the Trivy Operator chart under `compliance.specs`.
