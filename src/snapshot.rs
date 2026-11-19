//! Collects all Trivy Operator reports from the cluster and aggregates them
//! into a read-only snapshot the API serves from memory.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::hash::{DefaultHasher, Hash, Hasher};
use std::time::Instant;

use anyhow::{Context, Result};
use k8s_openapi::api::apps::v1::ReplicaSet;
use kube::{
    Api, Client,
    api::{ApiResource, DynamicObject, GroupVersionKind, ListParams},
};
use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::raw;

const GROUP: &str = "aquasecurity.github.io";
const VERSION: &str = "v1alpha1";

// ---------------------------------------------------------------- severity

pub fn rank(sev: &str) -> u8 {
    match sev {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, PartialEq, Eq)]
pub struct Sev {
    pub critical: u32,
    pub high: u32,
    pub medium: u32,
    pub low: u32,
    pub unknown: u32,
}

impl Sev {
    pub fn add(&mut self, sev: &str) {
        match rank(sev) {
            4 => self.critical += 1,
            3 => self.high += 1,
            2 => self.medium += 1,
            1 => self.low += 1,
            _ => self.unknown += 1,
        }
    }
    pub fn merge(&mut self, o: &Sev) {
        self.critical += o.critical;
        self.high += o.high;
        self.medium += o.medium;
        self.low += o.low;
        self.unknown += o.unknown;
    }
    /// Sort key: worst first.
    fn key(&self) -> (u32, u32, u32, u32) {
        (self.critical, self.high, self.medium, self.low)
    }
}

// ---------------------------------------------------------------- API types

#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadRef {
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub container: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageRow {
    pub id: String,
    pub registry: String,
    pub repository: String,
    pub tag: String,
    pub digest: String,
    pub os: String,
    pub eosl: bool,
    pub severity: Sev,
    pub fixable: Sev,
    pub workload_count: usize,
    pub namespaces: Vec<String>,
    pub secrets: u32,
    pub updated: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VulnOut {
    pub id: String,
    pub pkg: String,
    pub pkg_type: String,
    pub installed: String,
    pub fixed: String,
    pub severity: String,
    pub score: Option<f64>,
    pub title: String,
    pub link: String,
    pub published: String,
    pub target: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ImageDetail {
    #[serde(flatten)]
    pub row: ImageRow,
    pub vulnerabilities: Vec<VulnOut>,
    pub workloads: Vec<WorkloadRef>,
    pub exposed_secrets: Vec<SecretRow>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Cve {
    pub id: String,
    pub severity: String,
    pub score: Option<f64>,
    pub title: String,
    pub link: String,
    pub published: String,
    pub fixable: bool,
    pub packages: Vec<String>,
    pub image_count: usize,
    pub workload_count: usize,
    pub namespaces: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CveAffected {
    pub image_id: String,
    pub image: String,
    pub pkg: String,
    pub installed: String,
    pub fixed: String,
    pub target: String,
    pub workloads: Vec<WorkloadRef>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CveDetail {
    #[serde(flatten)]
    pub cve: Cve,
    pub affected: Vec<CveAffected>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkloadContainer {
    pub container: String,
    pub image_id: String,
    pub image: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Workload {
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub containers: Vec<WorkloadContainer>,
    pub severity: Sev,
    pub fixable: Sev,
    pub misconfig: Sev,
    pub secrets: u32,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckOut {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub messages: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResource {
    /// "config" or "rbac"
    pub scope: &'static str,
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub failed: Vec<CheckOut>,
    pub failed_sev: Sev,
    pub pass_count: usize,
    pub updated: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecretRow {
    pub namespace: String,
    pub kind: String,
    pub name: String,
    pub container: String,
    pub image: String,
    pub image_id: String,
    pub target: String,
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlOut {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
    /// None until the operator has produced a status for this report.
    pub total_fail: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Compliance {
    pub name: String,
    pub id: String,
    pub title: String,
    pub description: String,
    pub cron: String,
    pub pending: bool,
    pub pass: u32,
    pub fail: u32,
    pub controls: Vec<ControlOut>,
    pub updated: String,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NamespaceStat {
    pub namespace: String,
    pub images: usize,
    pub workloads: usize,
    pub severity: Sev,
    pub fixable: Sev,
    pub misconfig: Sev,
    pub rbac: Sev,
    pub secrets: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Counts {
    pub images: usize,
    pub workloads: usize,
    pub namespaces: usize,
    pub cves: usize,
    pub audited_resources: usize,
    pub misconfigured_resources: usize,
    pub eosl_images: usize,
    pub vulnerability_reports: usize,
    pub config_reports: usize,
    pub rbac_reports: usize,
    pub secret_reports: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Overview {
    pub refreshed_at: String,
    pub duration_ms: u128,
    pub errors: Vec<String>,
    pub counts: Counts,
    pub severity: Sev,
    pub fixable: Sev,
    pub misconfig: Sev,
    pub rbac: Sev,
    pub secrets: Sev,
    pub namespaces: Vec<NamespaceStat>,
    pub top_images: Vec<ImageRow>,
    pub top_cves: Vec<Cve>,
    /// Critical/high CVEs published in the last 30 days, newest first.
    pub recent_cves: Vec<Cve>,
    pub compliance: Vec<Compliance>,
}

pub struct Snapshot {
    pub overview: Overview,
    pub images: Vec<ImageRow>,
    pub image_details: HashMap<String, ImageDetail>,
    pub cves: Vec<Cve>,
    pub cve_details: HashMap<String, CveDetail>,
    pub workloads: Vec<Workload>,
    pub misconfigs: Vec<CheckResource>,
    pub secrets: Vec<SecretRow>,
    pub compliance: Vec<Compliance>,
}

// ---------------------------------------------------------------- fetching

async fn list_all(client: &Client, kind: &str, plural: &str) -> Result<Vec<DynamicObject>> {
    let gvk = GroupVersionKind::gvk(GROUP, VERSION, kind);
    let ar = ApiResource::from_gvk_with_plural(&gvk, plural);
    let api: Api<DynamicObject> = Api::all_with(client.clone(), &ar);
    let mut out = Vec::new();
    let mut token: Option<String> = None;
    loop {
        let mut lp = ListParams::default().limit(100);
        if let Some(t) = &token {
            lp = lp.continue_token(t);
        }
        let list = api
            .list(&lp)
            .await
            .with_context(|| format!("listing {plural}"))?;
        out.extend(list.items);
        match list.metadata.continue_ {
            Some(t) if !t.is_empty() => token = Some(t),
            _ => break,
        }
    }
    Ok(out)
}

/// (namespace, replicaset) -> (owner kind, owner name), so reports on
/// ReplicaSets can be shown under their Deployment.
async fn replicaset_owners(client: &Client) -> Result<HashMap<(String, String), (String, String)>> {
    let api: Api<ReplicaSet> = Api::all(client.clone());
    let list = api
        .list_metadata(&ListParams::default())
        .await
        .context("listing replicasets")?;
    let mut map = HashMap::new();
    for rs in list.items {
        let (Some(ns), Some(name)) = (rs.metadata.namespace, rs.metadata.name) else {
            continue;
        };
        if let Some(owner) = rs
            .metadata
            .owner_references
            .unwrap_or_default()
            .into_iter()
            .find(|o| o.controller == Some(true))
        {
            map.insert((ns, name), (owner.kind, owner.name));
        }
    }
    Ok(map)
}

fn take<T: Default>(r: Result<T>, errors: &mut Vec<String>) -> T {
    r.unwrap_or_else(|e| {
        errors.push(format!("{e:#}"));
        T::default()
    })
}

fn field<T: DeserializeOwned + Default>(obj: &mut DynamicObject, name: &str) -> T {
    match obj.data.get_mut(name).map(Value::take) {
        None | Some(Value::Null) => T::default(),
        Some(v) => serde_json::from_value(v).unwrap_or_else(|e| {
            tracing::warn!(object = ?obj.metadata.name, field = name, "unparseable report: {e}");
            T::default()
        }),
    }
}

struct Owner {
    namespace: String,
    kind: String,
    name: String,
    container: String,
}

fn owner(obj: &DynamicObject, rs: &HashMap<(String, String), (String, String)>) -> Owner {
    let labels = obj.metadata.labels.clone().unwrap_or_default();
    let get = |k: &str| labels.get(k).cloned().unwrap_or_default();
    let mut o = Owner {
        namespace: labels
            .get("trivy-operator.resource.namespace")
            .cloned()
            .or_else(|| obj.metadata.namespace.clone())
            .unwrap_or_default(),
        kind: get("trivy-operator.resource.kind"),
        name: get("trivy-operator.resource.name"),
        container: get("trivy-operator.container.name"),
    };
    if o.kind == "ReplicaSet"
        && let Some((k, n)) = rs.get(&(o.namespace.clone(), o.name.clone()))
    {
        o.kind = k.clone();
        o.name = n.clone();
    }
    o
}

fn short_hash(s: &str) -> String {
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    format!("{:016x}", h.finish())
}

fn image_key(reg: &raw::Registry, a: &raw::Artifact) -> (String, String) {
    let pin = if a.digest.is_empty() {
        &a.tag
    } else {
        &a.digest
    };
    let key = format!("{}/{}@{}", reg.server, a.repository, pin);
    let display = if a.tag.is_empty() {
        a.repository.clone()
    } else {
        format!("{}:{}", a.repository, a.tag)
    };
    (short_hash(&key), display)
}

// ---------------------------------------------------------------- aggregation

struct ImgAcc {
    row: ImageRow,
    vulns: Vec<VulnOut>,
    workloads: BTreeSet<WorkloadRef>,
    secrets: Vec<SecretRow>,
}

struct CveAcc {
    cve: Cve,
    rank: u8,
    packages: BTreeSet<String>,
    images: BTreeSet<String>,
    workloads: BTreeSet<(String, String, String)>,
    namespaces: BTreeSet<String>,
    affected: Vec<CveAffected>,
}

#[derive(Default)]
struct WlAcc {
    containers: BTreeSet<(String, String)>,
    misconfig: Sev,
    secrets: u32,
}

/// Every report list the dashboard reads, plus ReplicaSet ownership.
#[derive(Default)]
pub struct Inputs {
    pub vulns: Vec<DynamicObject>,
    pub config: Vec<DynamicObject>,
    pub cluster_config: Vec<DynamicObject>,
    pub rbac: Vec<DynamicObject>,
    pub cluster_rbac: Vec<DynamicObject>,
    pub secrets: Vec<DynamicObject>,
    pub compliance: Vec<DynamicObject>,
    pub replicasets: HashMap<(String, String), (String, String)>,
    /// Report types that could not be read; shown on the overview.
    pub errors: Vec<String>,
}

pub async fn collect(client: &Client) -> Result<Snapshot> {
    let start = Instant::now();
    let (vulns, cfg, ccfg, rbac, crbac, secrets, comp, rs) = tokio::join!(
        list_all(client, "VulnerabilityReport", "vulnerabilityreports"),
        list_all(client, "ConfigAuditReport", "configauditreports"),
        list_all(
            client,
            "ClusterConfigAuditReport",
            "clusterconfigauditreports"
        ),
        list_all(client, "RbacAssessmentReport", "rbacassessmentreports"),
        list_all(
            client,
            "ClusterRbacAssessmentReport",
            "clusterrbacassessmentreports"
        ),
        list_all(client, "ExposedSecretReport", "exposedsecretreports"),
        list_all(
            client,
            "ClusterComplianceReport",
            "clustercompliancereports"
        ),
        replicaset_owners(client),
    );
    if let (Err(e), Err(_), Err(_), Err(_)) = (&vulns, &cfg, &rbac, &secrets) {
        return Err(anyhow::anyhow!("cannot read any Trivy reports: {e:#}"));
    }
    let mut errors = Vec::new();
    let inputs = Inputs {
        vulns: take(vulns, &mut errors),
        config: take(cfg, &mut errors),
        cluster_config: take(ccfg, &mut errors),
        rbac: take(rbac, &mut errors),
        cluster_rbac: take(crbac, &mut errors),
        secrets: take(secrets, &mut errors),
        compliance: take(comp, &mut errors),
        replicasets: take(rs, &mut errors),
        errors,
    };
    let mut snap = build(inputs);
    snap.overview.duration_ms = start.elapsed().as_millis();
    Ok(snap)
}

/// Aggregates raw reports into the snapshot the API serves. Pure, so it can
/// be tested without a cluster.
pub fn build(inputs: Inputs) -> Snapshot {
    let Inputs {
        vulns,
        config: cfg,
        cluster_config: ccfg,
        rbac,
        cluster_rbac: crbac,
        secrets,
        compliance: comp,
        replicasets: rs,
        errors,
    } = inputs;

    let mut counts = Counts {
        vulnerability_reports: vulns.len(),
        config_reports: cfg.len() + ccfg.len(),
        rbac_reports: rbac.len() + crbac.len(),
        secret_reports: secrets.len(),
        ..Default::default()
    };

    // ---- images & workloads from vulnerability reports
    let mut images: BTreeMap<String, ImgAcc> = BTreeMap::new();
    let mut workloads: BTreeMap<(String, String, String), WlAcc> = BTreeMap::new();
    let mut image_names: HashMap<String, String> = HashMap::new();

    for mut obj in vulns {
        let o = owner(&obj, &rs);
        let rep: raw::VulnReport = field(&mut obj, "report");
        let (id, display) = image_key(&rep.registry, &rep.artifact);
        image_names.insert(id.clone(), display.clone());
        let wref = WorkloadRef {
            namespace: o.namespace.clone(),
            kind: o.kind.clone(),
            name: o.name.clone(),
            container: o.container.clone(),
        };
        workloads
            .entry((o.namespace, o.kind, o.name))
            .or_default()
            .containers
            .insert((o.container, id.clone()));

        let acc = images.entry(id.clone()).or_insert_with(|| {
            let mut seen = HashSet::new();
            let mut vulns: Vec<VulnOut> = rep
                .vulnerabilities
                .iter()
                .filter(|v| {
                    seen.insert((
                        v.vulnerability_id.clone(),
                        v.resource.clone(),
                        v.installed_version.clone(),
                        v.target.clone(),
                    ))
                })
                .map(|v| VulnOut {
                    id: v.vulnerability_id.clone(),
                    pkg: v.resource.clone(),
                    pkg_type: v.package_type.clone(),
                    installed: v.installed_version.clone(),
                    fixed: v.fixed_version.clone(),
                    severity: v.severity.clone(),
                    score: v.score,
                    title: v.title.clone(),
                    link: v.primary_link.clone(),
                    published: v.published_date.clone(),
                    target: v.target.clone(),
                })
                .collect();
            vulns.sort_by(|a, b| {
                rank(&b.severity).cmp(&rank(&a.severity)).then(
                    b.score
                        .partial_cmp(&a.score)
                        .unwrap_or(std::cmp::Ordering::Equal),
                )
            });
            let mut severity = Sev::default();
            let mut fixable = Sev::default();
            for v in &vulns {
                severity.add(&v.severity);
                if !v.fixed.is_empty() {
                    fixable.add(&v.severity);
                }
            }
            ImgAcc {
                row: ImageRow {
                    id: id.clone(),
                    registry: rep.registry.server.clone(),
                    repository: rep.artifact.repository.clone(),
                    tag: rep.artifact.tag.clone(),
                    digest: rep.artifact.digest.clone(),
                    os: format!("{} {}", rep.os.family, rep.os.name)
                        .trim()
                        .to_string(),
                    eosl: rep.os.eosl,
                    severity,
                    fixable,
                    workload_count: 0,
                    namespaces: vec![],
                    secrets: 0,
                    updated: rep.update_timestamp.clone(),
                },
                vulns,
                workloads: BTreeSet::new(),
                secrets: vec![],
            }
        });
        acc.workloads.insert(wref);
    }

    // ---- exposed secrets
    let mut secret_rows = Vec::new();
    for mut obj in secrets {
        let o = owner(&obj, &rs);
        let rep: raw::SecretReport = field(&mut obj, "report");
        let (id, display) = image_key(&rep.registry, &rep.artifact);
        for s in rep.secrets {
            let row = SecretRow {
                namespace: o.namespace.clone(),
                kind: o.kind.clone(),
                name: o.name.clone(),
                container: o.container.clone(),
                image: display.clone(),
                image_id: id.clone(),
                target: s.target,
                rule_id: s.rule_id,
                title: s.title,
                severity: s.severity,
                category: s.category,
            };
            if let Some(w) =
                workloads.get_mut(&(o.namespace.clone(), o.kind.clone(), o.name.clone()))
            {
                w.secrets += 1;
            }
            if let Some(img) = images.get_mut(&id) {
                // Same image in several workloads yields duplicate findings; keep one per target+rule.
                if !img
                    .secrets
                    .iter()
                    .any(|x| x.target == row.target && x.rule_id == row.rule_id)
                {
                    img.secrets.push(row.clone());
                }
            }
            secret_rows.push(row);
        }
    }
    secret_rows.sort_by(|a, b| {
        rank(&b.severity)
            .cmp(&rank(&a.severity))
            .then(a.namespace.cmp(&b.namespace))
    });

    // ---- config & rbac audits
    let mut misconfigs = Vec::new();
    for (scope, list) in [
        ("config", cfg),
        ("config", ccfg),
        ("rbac", rbac),
        ("rbac", crbac),
    ] {
        for mut obj in list {
            counts.audited_resources += 1;
            let o = owner(&obj, &rs);
            let rep: raw::CheckReport = field(&mut obj, "report");
            let pass_count = rep.checks.iter().filter(|c| c.success).count();
            let mut failed: Vec<CheckOut> = rep
                .checks
                .into_iter()
                .filter(|c| !c.success)
                .map(|c| CheckOut {
                    id: c.check_id,
                    title: c.title,
                    description: c.description,
                    severity: c.severity,
                    category: c.category,
                    messages: c.messages,
                    remediation: c.remediation,
                })
                .collect();
            if failed.is_empty() {
                continue;
            }
            failed.sort_by_key(|c| std::cmp::Reverse(rank(&c.severity)));
            let mut failed_sev = Sev::default();
            failed.iter().for_each(|c| failed_sev.add(&c.severity));
            if scope == "config"
                && let Some(w) =
                    workloads.get_mut(&(o.namespace.clone(), o.kind.clone(), o.name.clone()))
            {
                w.misconfig.merge(&failed_sev);
            }
            misconfigs.push(CheckResource {
                scope,
                namespace: o.namespace,
                kind: o.kind,
                name: o.name,
                failed,
                failed_sev,
                pass_count,
                updated: rep.update_timestamp,
            });
        }
    }
    // Several ReplicaSets of one Deployment collapse to the same resource; keep the first.
    {
        let mut seen = HashSet::new();
        misconfigs.retain(|m| {
            seen.insert((m.scope, m.namespace.clone(), m.kind.clone(), m.name.clone()))
        });
    }
    counts.misconfigured_resources = misconfigs.len();
    misconfigs.sort_by_key(|m| std::cmp::Reverse(m.failed_sev.key()));

    // ---- finalize images
    for acc in images.values_mut() {
        acc.row.workload_count = acc
            .workloads
            .iter()
            .map(|w| (&w.namespace, &w.kind, &w.name))
            .collect::<HashSet<_>>()
            .len();
        acc.row.namespaces = acc
            .workloads
            .iter()
            .map(|w| w.namespace.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        acc.row.secrets = acc.secrets.len() as u32;
    }

    // ---- CVEs
    let mut cves: HashMap<String, CveAcc> = HashMap::new();
    for acc in images.values() {
        let display = image_names.get(&acc.row.id).cloned().unwrap_or_default();
        let wl: Vec<WorkloadRef> = acc.workloads.iter().cloned().collect();
        for v in &acc.vulns {
            let c = cves.entry(v.id.clone()).or_insert_with(|| CveAcc {
                cve: Cve {
                    id: v.id.clone(),
                    severity: v.severity.clone(),
                    score: v.score,
                    title: v.title.clone(),
                    link: v.link.clone(),
                    published: v.published.clone(),
                    fixable: false,
                    packages: vec![],
                    image_count: 0,
                    workload_count: 0,
                    namespaces: vec![],
                },
                rank: rank(&v.severity),
                packages: BTreeSet::new(),
                images: BTreeSet::new(),
                workloads: BTreeSet::new(),
                namespaces: BTreeSet::new(),
                affected: vec![],
            });
            if rank(&v.severity) > c.rank {
                c.rank = rank(&v.severity);
                c.cve.severity = v.severity.clone();
            }
            if v.score > c.cve.score {
                c.cve.score = v.score;
            }
            if c.cve.title.is_empty() {
                c.cve.title = v.title.clone();
            }
            c.cve.fixable |= !v.fixed.is_empty();
            c.packages.insert(v.pkg.clone());
            c.images.insert(acc.row.id.clone());
            for w in &wl {
                c.workloads
                    .insert((w.namespace.clone(), w.kind.clone(), w.name.clone()));
                c.namespaces.insert(w.namespace.clone());
            }
            c.affected.push(CveAffected {
                image_id: acc.row.id.clone(),
                image: display.clone(),
                pkg: v.pkg.clone(),
                installed: v.installed.clone(),
                fixed: v.fixed.clone(),
                target: v.target.clone(),
                workloads: wl.clone(),
            });
        }
    }
    let mut cve_details: HashMap<String, CveDetail> = HashMap::new();
    let mut cve_list: Vec<Cve> = Vec::with_capacity(cves.len());
    for (id, mut c) in cves {
        c.cve.packages = c.packages.into_iter().collect();
        c.cve.image_count = c.images.len();
        c.cve.workload_count = c.workloads.len();
        c.cve.namespaces = c.namespaces.into_iter().collect();
        cve_list.push(c.cve.clone());
        cve_details.insert(
            id,
            CveDetail {
                cve: c.cve,
                affected: c.affected,
            },
        );
    }
    cve_list.sort_by(|a, b| {
        rank(&b.severity)
            .cmp(&rank(&a.severity))
            .then(b.image_count.cmp(&a.image_count))
            .then(
                b.score
                    .partial_cmp(&a.score)
                    .unwrap_or(std::cmp::Ordering::Equal),
            )
    });
    counts.cves = cve_list.len();

    // ---- workloads
    let mut workload_list = Vec::new();
    for ((namespace, kind, name), w) in workloads {
        let mut severity = Sev::default();
        let mut fixable = Sev::default();
        let mut seen = HashSet::new();
        let containers = w
            .containers
            .into_iter()
            .map(|(container, image_id)| {
                if seen.insert(image_id.clone())
                    && let Some(img) = images.get(&image_id)
                {
                    severity.merge(&img.row.severity);
                    fixable.merge(&img.row.fixable);
                }
                WorkloadContainer {
                    image: image_names.get(&image_id).cloned().unwrap_or_default(),
                    container,
                    image_id,
                }
            })
            .collect();
        workload_list.push(Workload {
            namespace,
            kind,
            name,
            containers,
            severity,
            fixable,
            misconfig: w.misconfig,
            secrets: w.secrets,
        });
    }
    workload_list.sort_by_key(|w| std::cmp::Reverse(w.severity.key()));

    // ---- namespaces
    let mut ns: BTreeMap<String, (NamespaceStat, HashSet<String>)> = BTreeMap::new();
    fn ns_get<'a>(
        ns: &'a mut BTreeMap<String, (NamespaceStat, HashSet<String>)>,
        name: &str,
    ) -> &'a mut (NamespaceStat, HashSet<String>) {
        let key = if name.is_empty() {
            "(cluster)".to_string()
        } else {
            name.to_string()
        };
        let e = ns.entry(key.clone()).or_default();
        e.0.namespace = key;
        e
    }
    for w in &workload_list {
        let e = ns_get(&mut ns, &w.namespace);
        e.0.workloads += 1;
        for c in &w.containers {
            if e.1.insert(c.image_id.clone())
                && let Some(img) = images.get(&c.image_id)
            {
                e.0.severity.merge(&img.row.severity);
                e.0.fixable.merge(&img.row.fixable);
            }
        }
    }
    for m in &misconfigs {
        let e = ns_get(&mut ns, &m.namespace);
        if m.scope == "config" {
            e.0.misconfig.merge(&m.failed_sev)
        } else {
            e.0.rbac.merge(&m.failed_sev)
        }
    }
    for s in &secret_rows {
        ns_get(&mut ns, &s.namespace).0.secrets += 1;
    }
    let mut namespaces: Vec<NamespaceStat> = ns
        .into_values()
        .map(|(mut s, imgs)| {
            s.images = imgs.len();
            s
        })
        .collect();
    namespaces.sort_by(|a, b| {
        b.severity
            .key()
            .cmp(&a.severity.key())
            .then(b.misconfig.key().cmp(&a.misconfig.key()))
    });
    counts.namespaces = namespaces
        .iter()
        .filter(|n| n.namespace != "(cluster)")
        .count();
    counts.workloads = workload_list.len();

    // ---- compliance
    let mut compliance = Vec::new();
    for mut obj in comp {
        let spec: raw::ComplianceSpec = field(&mut obj, "spec");
        let status: Option<raw::ComplianceStatus> =
            match obj.data.get_mut("status").map(Value::take) {
                None | Some(Value::Null) => None,
                Some(v) => serde_json::from_value(v).ok(),
            };
        let fails: HashMap<String, Option<u32>> = status
            .as_ref()
            .and_then(|s| s.summary_report.as_ref())
            .map(|r| {
                r.control_check
                    .iter()
                    .map(|c| (c.id.clone(), c.total_fail))
                    .collect()
            })
            .unwrap_or_default();
        let pending = status.is_none();
        let mut controls: Vec<ControlOut> = spec
            .compliance
            .controls
            .into_iter()
            .map(|c| ControlOut {
                total_fail: if pending {
                    None
                } else {
                    Some(fails.get(&c.id).copied().flatten().unwrap_or(0))
                },
                id: c.id,
                name: c.name,
                description: c.description,
                severity: c.severity,
            })
            .collect();
        controls.sort_by(|a, b| {
            b.total_fail
                .unwrap_or(0)
                .cmp(&a.total_fail.unwrap_or(0))
                .then(rank(&b.severity).cmp(&rank(&a.severity)))
        });
        let (pass, fail, updated) = status
            .map(|s| {
                (
                    s.summary.pass_count,
                    s.summary.fail_count,
                    s.update_timestamp,
                )
            })
            .unwrap_or_default();
        compliance.push(Compliance {
            name: obj.metadata.name.clone().unwrap_or_default(),
            id: spec.compliance.id,
            title: spec.compliance.title,
            description: spec.compliance.description,
            cron: spec.cron,
            pending,
            pass,
            fail,
            controls,
            updated,
        });
    }

    // ---- images list & totals
    let mut image_rows: Vec<ImageRow> = images.values().map(|a| a.row.clone()).collect();
    image_rows.sort_by_key(|r| std::cmp::Reverse(r.severity.key()));
    let mut severity = Sev::default();
    let mut fixable = Sev::default();
    for r in &image_rows {
        severity.merge(&r.severity);
        fixable.merge(&r.fixable);
    }
    counts.images = image_rows.len();
    counts.eosl_images = image_rows.iter().filter(|r| r.eosl).count();
    let mut misconfig = Sev::default();
    let mut rbac_sev = Sev::default();
    for m in &misconfigs {
        if m.scope == "config" {
            misconfig.merge(&m.failed_sev)
        } else {
            rbac_sev.merge(&m.failed_sev)
        }
    }
    let mut secrets_sev = Sev::default();
    secret_rows
        .iter()
        .for_each(|s| secrets_sev.add(&s.severity));

    let image_details: HashMap<String, ImageDetail> = images
        .into_iter()
        .map(|(id, a)| {
            (
                id,
                ImageDetail {
                    row: a.row,
                    vulnerabilities: a.vulns,
                    workloads: a.workloads.into_iter().collect(),
                    exposed_secrets: a.secrets,
                },
            )
        })
        .collect();

    let overview = Overview {
        refreshed_at: chrono::Utc::now().to_rfc3339(),
        duration_ms: 0,
        errors,
        counts,
        severity,
        fixable,
        misconfig,
        rbac: rbac_sev,
        secrets: secrets_sev,
        namespaces,
        top_images: image_rows.iter().take(10).cloned().collect(),
        top_cves: cve_list.iter().take(8).cloned().collect(),
        recent_cves: {
            let cutoff = chrono::Utc::now() - chrono::Duration::days(30);
            let mut r: Vec<Cve> = cve_list
                .iter()
                .filter(|c| rank(&c.severity) >= 3)
                .filter(|c| {
                    chrono::DateTime::parse_from_rfc3339(&c.published).is_ok_and(|d| d >= cutoff)
                })
                .cloned()
                .collect();
            r.sort_by(|a, b| b.published.cmp(&a.published));
            r.truncate(8);
            r
        },
        compliance: compliance.clone(),
    };

    Snapshot {
        overview,
        images: image_rows,
        image_details,
        cves: cve_list,
        cve_details,
        workloads: workload_list,
        misconfigs,
        secrets: secret_rows,
        compliance,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn obj(kind: &str, ns: Option<&str>, name: &str, labels: Value, body: Value) -> DynamicObject {
        let mut v = json!({
            "apiVersion": "aquasecurity.github.io/v1alpha1",
            "kind": kind,
            "metadata": { "name": name, "labels": labels },
        });
        if let Some(ns) = ns {
            v["metadata"]["namespace"] = json!(ns);
        }
        for (k, val) in body.as_object().unwrap() {
            v[k] = val.clone();
        }
        serde_json::from_value(v).unwrap()
    }

    fn owner_labels(ns: &str, kind: &str, name: &str, container: &str) -> Value {
        json!({
            "trivy-operator.resource.namespace": ns,
            "trivy-operator.resource.kind": kind,
            "trivy-operator.resource.name": name,
            "trivy-operator.container.name": container,
        })
    }

    fn vuln(id: &str, pkg: &str, sev: &str, fixed: &str) -> Value {
        json!({
            "vulnerabilityID": id, "resource": pkg, "installedVersion": "1.0",
            "fixedVersion": fixed, "severity": sev, "title": format!("{id} in {pkg}"),
            "score": 7.5, "publishedDate": "2026-01-01T00:00:00Z", "target": "",
        })
    }

    fn vuln_report(
        ns: &str,
        rs: &str,
        repo: &str,
        digest: &str,
        vulns: Vec<Value>,
    ) -> DynamicObject {
        obj(
            "VulnerabilityReport",
            Some(ns),
            &format!("replicaset-{rs}-app"),
            owner_labels(ns, "ReplicaSet", rs, "app"),
            json!({ "report": {
                "artifact": { "repository": repo, "tag": "1.0", "digest": digest },
                "registry": { "server": "ghcr.io" },
                "os": { "family": "debian", "name": "12.1" },
                "vulnerabilities": vulns,
            }}),
        )
    }

    fn rs_map(entries: &[(&str, &str, &str)]) -> HashMap<(String, String), (String, String)> {
        entries
            .iter()
            .map(|(ns, rs, dep)| {
                (
                    (ns.to_string(), rs.to_string()),
                    ("Deployment".into(), dep.to_string()),
                )
            })
            .collect()
    }

    #[test]
    fn replicasets_collapse_into_their_deployment_and_images_count_once() {
        let v = || {
            vec![
                vuln("CVE-1", "openssl", "CRITICAL", "1.1"),
                vuln("CVE-2", "zlib", "HIGH", ""),
            ]
        };
        let snap = build(Inputs {
            vulns: vec![
                vuln_report("web", "web-aaa", "acme/web", "sha256:1", v()),
                vuln_report("web", "web-bbb", "acme/web", "sha256:1", v()),
            ],
            replicasets: rs_map(&[("web", "web-aaa", "web"), ("web", "web-bbb", "web")]),
            ..Default::default()
        });

        assert_eq!(snap.images.len(), 1, "same digest is one image");
        assert_eq!(
            snap.workloads.len(),
            1,
            "both ReplicaSets belong to one Deployment"
        );
        let w = &snap.workloads[0];
        assert_eq!((w.kind.as_str(), w.name.as_str()), ("Deployment", "web"));
        assert_eq!(
            w.severity,
            Sev {
                critical: 1,
                high: 1,
                ..Default::default()
            }
        );
        assert_eq!(
            snap.overview.severity.critical, 1,
            "findings are not double counted"
        );
        assert_eq!(
            snap.overview.fixable,
            Sev {
                critical: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn duplicate_findings_within_a_report_are_dropped() {
        let snap = build(Inputs {
            vulns: vec![vuln_report(
                "a",
                "x-1",
                "acme/x",
                "sha256:2",
                vec![
                    vuln("CVE-1", "openssl", "HIGH", "2"),
                    vuln("CVE-1", "openssl", "HIGH", "2"),
                ],
            )],
            ..Default::default()
        });
        assert_eq!(
            snap.image_details
                .values()
                .next()
                .unwrap()
                .vulnerabilities
                .len(),
            1
        );
    }

    #[test]
    fn cves_aggregate_across_images_with_the_worst_severity() {
        let snap = build(Inputs {
            vulns: vec![
                vuln_report(
                    "a",
                    "a-1",
                    "acme/a",
                    "sha256:a",
                    vec![vuln("CVE-9", "curl", "MEDIUM", "")],
                ),
                vuln_report(
                    "b",
                    "b-1",
                    "acme/b",
                    "sha256:b",
                    vec![vuln("CVE-9", "curl", "CRITICAL", "8.0")],
                ),
            ],
            ..Default::default()
        });
        let c = &snap.cve_details["CVE-9"];
        assert_eq!(c.cve.image_count, 2);
        assert_eq!(c.cve.severity, "CRITICAL");
        assert!(c.cve.fixable);
        assert_eq!(c.cve.namespaces, vec!["a", "b"]);
        assert_eq!(c.affected.len(), 2);
    }

    #[test]
    fn unrated_findings_are_counted_as_unknown() {
        let snap = build(Inputs {
            vulns: vec![vuln_report(
                "a",
                "a-1",
                "acme/a",
                "sha256:a",
                vec![vuln("CVE-3", "apt", "UNKNOWN", "2")],
            )],
            ..Default::default()
        });
        assert_eq!(
            snap.overview.severity,
            Sev {
                unknown: 1,
                ..Default::default()
            }
        );
    }

    #[test]
    fn exposed_secret_match_text_is_never_served() {
        let report = obj(
            "ExposedSecretReport",
            Some("a"),
            "replicaset-a-1-app",
            owner_labels("a", "ReplicaSet", "a-1", "app"),
            json!({ "report": {
                "artifact": { "repository": "acme/a", "digest": "sha256:a" },
                "registry": { "server": "ghcr.io" },
                "secrets": [{
                    "target": "/app/.env", "ruleID": "aws-access-key-id", "title": "AWS Access Key",
                    "severity": "CRITICAL", "category": "AWS", "match": "AKIA-DO-NOT-LEAK"
                }],
            }}),
        );
        let snap = build(Inputs {
            secrets: vec![report],
            ..Default::default()
        });
        assert_eq!(snap.secrets.len(), 1);
        let served = serde_json::to_string(&snap.secrets).unwrap();
        assert!(!served.contains("AKIA-DO-NOT-LEAK"));
        assert_eq!(snap.overview.secrets.critical, 1);
    }

    #[test]
    fn only_failed_checks_are_listed_and_passing_resources_are_skipped() {
        let check = |id: &str, sev: &str, ok: bool| json!({ "checkID": id, "title": id, "severity": sev, "success": ok });
        let snap = build(Inputs {
            config: vec![
                obj(
                    "ConfigAuditReport",
                    Some("a"),
                    "replicaset-a-1",
                    owner_labels("a", "ReplicaSet", "a-1", ""),
                    json!({ "report": { "checks": [check("KSV-1", "HIGH", false), check("KSV-2", "LOW", true)] } }),
                ),
                obj(
                    "ConfigAuditReport",
                    Some("a"),
                    "service-a",
                    owner_labels("a", "Service", "a", ""),
                    json!({ "report": { "checks": [check("KSV-3", "HIGH", true)] } }),
                ),
            ],
            rbac: vec![obj(
                "RbacAssessmentReport",
                Some("a"),
                "role-a",
                owner_labels("a", "Role", "a", ""),
                json!({ "report": { "checks": [check("KSV-41", "CRITICAL", false)] } }),
            )],
            replicasets: rs_map(&[("a", "a-1", "a")]),
            ..Default::default()
        });
        assert_eq!(snap.misconfigs.len(), 2);
        let cfg = snap
            .misconfigs
            .iter()
            .find(|m| m.scope == "config")
            .unwrap();
        assert_eq!(
            (cfg.kind.as_str(), cfg.failed.len(), cfg.pass_count),
            ("Deployment", 1, 1)
        );
        assert_eq!(snap.overview.misconfig.high, 1);
        assert_eq!(snap.overview.rbac.critical, 1);
        assert_eq!(snap.overview.counts.audited_resources, 3);
    }

    #[test]
    fn compliance_without_status_is_pending() {
        let spec = json!({ "spec": { "cron": "0 */6 * * *", "compliance": {
            "id": "nsa", "title": "NSA",
            "controls": [{ "id": "1.0", "name": "Non-root", "severity": "MEDIUM" }],
        }}});
        let pending = obj(
            "ClusterComplianceReport",
            None,
            "nsa",
            json!({}),
            spec.clone(),
        );
        let mut done = spec;
        done["status"] = json!({
            "summary": { "passCount": 3, "failCount": 1 },
            "summaryReport": { "controlCheck": [{ "id": "1.0", "name": "Non-root", "severity": "MEDIUM", "totalFail": 4 }] },
        });
        let done = obj("ClusterComplianceReport", None, "nsa-done", json!({}), done);

        let snap = build(Inputs {
            compliance: vec![pending, done],
            ..Default::default()
        });
        let p = snap.compliance.iter().find(|c| c.name == "nsa").unwrap();
        assert!(p.pending);
        assert_eq!(p.controls[0].total_fail, None);
        let d = snap
            .compliance
            .iter()
            .find(|c| c.name == "nsa-done")
            .unwrap();
        assert!(!d.pending);
        assert_eq!((d.pass, d.fail), (3, 1));
        assert_eq!(d.controls[0].total_fail, Some(4));
    }

    #[test]
    fn unparseable_reports_degrade_to_empty_instead_of_failing() {
        let broken = obj(
            "VulnerabilityReport",
            Some("a"),
            "x",
            owner_labels("a", "Pod", "x", "c"),
            json!({ "report": { "vulnerabilities": "not a list" } }),
        );
        let snap = build(Inputs {
            vulns: vec![broken],
            ..Default::default()
        });
        assert_eq!(snap.overview.severity, Sev::default());
    }
}
