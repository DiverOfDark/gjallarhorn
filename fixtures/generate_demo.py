#!/usr/bin/env python3
"""Write fixtures/demo.json: a made-up homelab for screenshots and local work.

Image names are fictional (ghcr.io/example/...) and CVE ids are invented, so
nothing here describes real software. Publication dates are relative to the
day you run this, which keeps "New this month" populated:

    python3 fixtures/generate_demo.py
"""

import datetime as dt
import json
import pathlib
import random

rng = random.Random(7)
today = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
GROUP = "aquasecurity.github.io/v1alpha1"

PACKAGES = [
    ("openssl", "3.0.11-1", "3.0.15-1"), ("libssl3", "3.0.11-1", "3.0.15-1"), ("zlib1g", "1.2.13", "1.2.13.1"),
    ("curl", "7.88.1-10", "7.88.1-10+deb12u8"), ("libcurl4", "7.88.1-10", "7.88.1-10+deb12u8"),
    ("libc6", "2.36-9", "2.36-9+deb12u9"), ("stdlib", "v1.22.4", "1.22.12, 1.23.6"),
    ("golang.org/x/net", "v0.23.0", "0.36.0"), ("golang.org/x/crypto", "v0.21.0", "0.35.0"),
    ("python3.11", "3.11.2-6", "3.11.2-6+deb12u5"), ("libxml2", "2.9.14", "2.9.14+dfsg-1.3~deb12u1"),
    ("sqlite3", "3.40.1-2", "3.40.1-2+deb12u1"), ("libexpat1", "2.5.0-1", "2.5.0-1+deb12u1"),
    ("krb5-libs", "1.20.1-r1", "1.20.2-r1"), ("busybox", "1.36.1-r2", "1.36.1-r7"), ("musl", "1.2.4-r1", "1.2.4-r3"),
    ("PyJWT", "2.8.0", "2.10.1"), ("requests", "2.31.0", "2.32.4"), ("node-tar", "6.1.13", "6.2.1"),
]
TITLES = [
    "heap buffer overflow when parsing crafted input", "use-after-free in connection teardown",
    "integer overflow in length calculation", "denial of service via deeply nested data",
    "certificate validation bypass on session resumption", "path traversal when extracting archives",
    "out-of-bounds read in decoder", "request smuggling through malformed headers",
]

# A shared pool, so some CVEs reach many images.
POOL = []
for i in range(220):
    pkg, inst, fixed = PACKAGES[i % len(PACKAGES)]
    sev = rng.choices(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], [4, 22, 30, 4, 40])[0]
    age = rng.choice([3, 6, 11, 19, 27]) if i < 14 else rng.randint(40, 900)
    POOL.append({
        "vulnerabilityID": f"CVE-{(today - dt.timedelta(days=age)).year}-{9000 + i * 7}",
        "resource": pkg, "installedVersion": inst,
        "fixedVersion": "" if rng.random() < 0.08 else fixed,
        "severity": sev,
        "score": round(rng.uniform(9.0, 9.9) if sev == "CRITICAL" else rng.uniform(7.0, 8.9) if sev == "HIGH" else rng.uniform(4.0, 6.9), 1),
        "title": f"{pkg}: {rng.choice(TITLES)}",
        "primaryLink": f"https://example.com/advisories/{9000 + i * 7}",
        "publishedDate": (today - dt.timedelta(days=age)).isoformat().replace("+00:00", "Z"),
        "target": "", "packageType": "debian",
    })

# (registry, repository, tag, os family, os name, eosl, critical, high, medium, other, workloads)
IMAGES = [
    ("ghcr.io", "example/media-server", "latest", "debian", "12.8", False, 9, 34, 40, 160, [("media", "Deployment", "media-server")]),
    ("docker.io", "example/postgres", "14.12-bullseye", "debian", "11.11", True, 6, 48, 30, 90,
     [("auth", "StatefulSet", "auth-db"), ("wiki", "StatefulSet", "wiki-db"), ("photos", "StatefulSet", "photos-db")]),
    ("ghcr.io", "example/backup-agent", "v0.8.2", "alpine", "3.14.0", True, 5, 41, 22, 60, [("backup", "CronJob", "nightly-backup")]),
    ("docker.io", "example/grafana", "10.2.0", "alpine", "3.18.4", True, 4, 25, 18, 70, [("monitoring", "Deployment", "grafana")]),
    ("registry.example.com", "csi/smb-plugin", "v1.14.0", "debian", "12.4", False, 3, 20, 15, 80,
     [("kube-system", "DaemonSet", "csi-smb-node"), ("kube-system", "Deployment", "csi-smb-controller")]),
    ("docker.io", "example/nginx", "1.25.3", "debian", "12.4", False, 2, 12, 20, 40, [("web", "Deployment", "homepage"), ("wiki", "Deployment", "wiki-proxy")]),
    ("ghcr.io", "example/photo-gallery", "3.2.1", "debian", "12.8", False, 1, 9, 14, 25, [("photos", "Deployment", "photo-gallery")]),
    ("quay.io", "example/node-exporter", "v1.7.0", "", "", False, 1, 4, 3, 2, [("monitoring", "DaemonSet", "node-exporter")]),
    ("registry.example.com", "coredns/coredns", "v1.11.1", "", "", False, 0, 3, 2, 1, [("kube-system", "Deployment", "coredns")]),
    ("docker.io", "example/redis", "7.2.4", "debian", "12.5", False, 0, 4, 9, 30, [("auth", "Deployment", "auth-cache"), ("wiki", "Deployment", "wiki-cache")]),
    ("ghcr.io", "example/home-automation", "2026.11.1", "alpine", "3.20.3", False, 0, 2, 6, 12, [("home", "StatefulSet", "home-automation")]),
    ("ghcr.io", "example/wiki", "1.6.0", "alpine", "3.21.0", False, 0, 1, 3, 4, [("wiki", "Deployment", "wiki")]),
    ("ghcr.io", "example/auth-server", "4.19.2", "alpine", "3.21.0", False, 0, 0, 2, 3, [("auth", "Deployment", "auth-server")]),
    ("ghcr.io", "example/static-site", "2.1.0", "", "", False, 0, 0, 0, 0, [("web", "Deployment", "docs")]),
]

def pick(sev, n):
    cands = [v for v in POOL if (v["severity"] == sev if sev != "other" else v["severity"] in ("LOW", "UNKNOWN"))]
    return rng.sample(cands, min(n, len(cands)))

def meta(kind, ns, name, labels):
    m = {"name": name, "labels": {"app.kubernetes.io/managed-by": "trivy-operator", **labels}}
    if ns is not None:
        m["namespace"] = ns
    return {"apiVersion": GROUP, "kind": kind, "metadata": m}

def owner_labels(ns, kind, name, container=None):
    l = {"trivy-operator.resource.namespace": ns, "trivy-operator.resource.kind": kind, "trivy-operator.resource.name": name}
    if container:
        l["trivy-operator.container.name"] = container
    return l

def rs_name(name):
    return f"{name}-{rng.randrange(16**9):09x}"[:len(name) + 10]

replica_sets, vuln_reports, secret_reports = [], [], []
owners = {}  # (ns, kind, name) -> (report kind, report name)
for reg, repo, tag, fam, osname, eosl, c, h, m, o, workloads in IMAGES:
    vulns = pick("CRITICAL", c) + pick("HIGH", h) + pick("MEDIUM", m) + pick("other", o)
    digest = "sha256:" + "".join(rng.choice("0123456789abcdef") for _ in range(64))
    for ns, kind, name in workloads:
        rkind, rname = kind, name
        if kind == "Deployment":
            rkind, rname = "ReplicaSet", owners.setdefault((ns, kind, name), (None, rs_name(name)))[1]
            replica_sets.append({"namespace": ns, "name": rname, "ownerKind": "Deployment", "ownerName": name})
        container = repo.split("/")[-1]
        artifact = {"repository": repo, "tag": tag, "digest": digest}
        report = {
            "artifact": artifact, "registry": {"server": reg},
            "os": {"family": fam, "name": osname, "eosl": eosl} if fam else {},
            "scanner": {"name": "Trivy", "vendor": "Aqua Security", "version": "0.70.0"},
            "summary": {}, "vulnerabilities": vulns, "updateTimestamp": today.isoformat().replace("+00:00", "Z"),
        }
        vuln_reports.append({**meta("VulnerabilityReport", ns, f"{rkind.lower()}-{rname}-{container}", owner_labels(ns, rkind, rname, container)), "report": report})
        secrets = []
        if repo == "example/media-server":
            secrets = [{"target": "/app/config/.env.example", "ruleID": "aws-access-key-id", "title": "AWS Access Key ID",
                        "severity": "CRITICAL", "category": "AWS", "match": "AWS_ACCESS_KEY_ID=****************"}]
        if repo == "example/backup-agent":
            secrets = [{"target": "/usr/share/backup/test/key.pem", "ruleID": "private-key", "title": "Asymmetric Private Key",
                        "severity": "HIGH", "category": "AsymmetricPrivateKey", "match": "-----BEGIN PRIVATE KEY-----****"}]
        secret_reports.append({**meta("ExposedSecretReport", ns, f"{rkind.lower()}-{rname}-{container}", owner_labels(ns, rkind, rname, container)),
                               "report": {"artifact": artifact, "registry": {"server": reg}, "secrets": secrets}})

CHECKS = {
    "KSV-0001": ("Process can elevate its own privileges", "MEDIUM", "Set 'set containers[].securityContext.allowPrivilegeEscalation' to 'false'."),
    "KSV-0012": ("Runs as root user", "MEDIUM", "Set 'containers[].securityContext.runAsNonRoot' to true."),
    "KSV-0014": ("Root file system is not read-only", "HIGH", "Set 'containers[].securityContext.readOnlyRootFilesystem' to true."),
    "KSV-0017": ("Privileged", "HIGH", "Set 'containers[].securityContext.privileged' to false."),
    "KSV-0009": ("Access to host network", "HIGH", "Do not set 'spec.template.spec.hostNetwork' to true."),
    "KSV-0011": ("CPU not limited", "LOW", "Set a limit value under 'containers[].resources.limits.cpu'."),
    "KSV-0106": ("Container capabilities must only include NET_BIND_SERVICE", "LOW", "Set 'spec.containers[*].securityContext.capabilities.drop' to 'ALL'."),
}
def checks(failing, passing=("KSV-0011",)):
    out = []
    for cid in failing + tuple(p for p in passing if p not in failing):
        title, sev, fix = CHECKS[cid]
        ok = cid not in failing
        out.append({"checkID": cid, "title": title, "severity": sev, "category": "Kubernetes Security Check", "success": ok,
                    "description": f"{title}.", "messages": [] if ok else [f"Container of the workload should not fail '{title}'"], "remediation": fix})
    return out

config_reports = []
MISCONFIG = {
    ("kube-system", "DaemonSet", "csi-smb-node"): ("KSV-0017", "KSV-0009", "KSV-0014", "KSV-0012", "KSV-0001"),
    ("monitoring", "DaemonSet", "node-exporter"): ("KSV-0009", "KSV-0014", "KSV-0012"),
    ("media", "Deployment", "media-server"): ("KSV-0012", "KSV-0014", "KSV-0001", "KSV-0106"),
    ("auth", "StatefulSet", "auth-db"): ("KSV-0014", "KSV-0001"),
    ("backup", "CronJob", "nightly-backup"): ("KSV-0012", "KSV-0014", "KSV-0011"),
    ("home", "StatefulSet", "home-automation"): ("KSV-0017", "KSV-0009"),
    ("web", "Deployment", "homepage"): ("KSV-0014",),
}
for (ns, kind, name), failing in MISCONFIG.items():
    rkind, rname = kind, name
    if kind == "Deployment":
        rkind, rname = "ReplicaSet", owners[(ns, kind, name)][1]
    config_reports.append({**meta("ConfigAuditReport", ns, f"{rkind.lower()}-{rname}", owner_labels(ns, rkind, rname)),
                           "report": {"checks": checks(failing), "summary": {}}})

RBAC = [
    ("ClusterRoleBinding", None, "backup-operator", [("KSV-0046", "Manage all resources", "CRITICAL"), ("KSV-0041", "Manage secrets", "CRITICAL")]),
    ("Role", "media", "media-server", [("KSV-0113", "Manage namespace secrets", "MEDIUM")]),
    ("ClusterRole", None, "monitoring-agent", [("KSV-0045", "No wildcard verb roles", "CRITICAL")]),
]
rbac_reports, cluster_rbac_reports = [], []
for kind, ns, name, fails in RBAC:
    report = {"checks": [{"checkID": i, "title": t, "severity": s, "category": "Kubernetes Security Check", "success": False,
                          "messages": [f"{kind} '{name}' shouldn't {t.lower()}"], "remediation": f"Remove the rule that grants: {t.lower()}."}
                         for i, t, s in fails]}
    obj = {**meta("RbacAssessmentReport" if ns else "ClusterRbacAssessmentReport", ns, f"{kind.lower()}-{name}", owner_labels(ns or "", kind, name)), "report": report}
    (rbac_reports if ns else cluster_rbac_reports).append(obj)

CONTROLS = [("1.0", "Non-root containers", "MEDIUM", 5), ("1.1", "Immutable container file systems", "LOW", 9),
            ("1.2", "Preventing privileged containers", "HIGH", 2), ("1.3", "Share containers process namespaces", "HIGH", 0),
            ("1.4", "Share host process namespaces", "HIGH", 0), ("1.5", "Use the host network", "HIGH", 3),
            ("1.6", "Run with root privileges or with root group membership", "LOW", 4),
            ("1.7", "Restricts escalation to root privileges", "MEDIUM", 4), ("1.8", "Sets the SELinux context of the container", "MEDIUM", 0),
            ("2.0", "Pod and/or namespace selectors", "MEDIUM", 6), ("4.0", "Use CNI plugin that supports NetworkPolicy API", "CRITICAL", 0)]
def compliance(name, title, cron, with_status):
    o = {"apiVersion": GROUP, "kind": "ClusterComplianceReport", "metadata": {"name": name},
         "spec": {"cron": cron, "reportType": "summary", "compliance": {"id": name, "title": title, "description": title,
                  "controls": [{"id": i, "name": n, "description": n + ".", "severity": s} for i, n, s, _ in CONTROLS]}}}
    if with_status:
        fails = [c for c in CONTROLS if c[3]]
        o["status"] = {"summary": {"passCount": len(CONTROLS) - len(fails), "failCount": len(fails)},
                       "summaryReport": {"controlCheck": [{"id": i, "name": n, "severity": s, "totalFail": f} for i, n, s, f in CONTROLS]},
                       "updateTimestamp": (today - dt.timedelta(hours=2)).isoformat().replace("+00:00", "Z")}
    return o

fixture = {
    "vulnerabilityReports": vuln_reports,
    "configAuditReports": config_reports,
    "rbacAssessmentReports": rbac_reports,
    "clusterRbacAssessmentReports": cluster_rbac_reports,
    "exposedSecretReports": secret_reports,
    "clusterComplianceReports": [
        compliance("k8s-nsa-1.0", "National Security Agency - Kubernetes Hardening Guidance v1.0", "0 */6 * * *", True),
        compliance("k8s-pss-baseline-0.1", "Kubernetes Pod Security Standards - Baseline", "0 */6 * * *", False),
    ],
    "replicaSets": replica_sets,
}
out = pathlib.Path(__file__).with_name("demo.json")
out.write_text(json.dumps(fixture, indent=1) + "\n")
print(f"wrote {out} ({len(vuln_reports)} vulnerability reports)")
