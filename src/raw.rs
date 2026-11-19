//! Serde shapes of the Trivy Operator CRDs (aquasecurity.github.io/v1alpha1).
//! Only the fields the dashboard needs; everything is defaulted so partial
//! or future reports still parse.

use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Summary {
    pub critical_count: u32,
    pub high_count: u32,
    pub medium_count: u32,
    pub low_count: u32,
    pub unknown_count: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Artifact {
    pub repository: String,
    pub tag: String,
    pub digest: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Registry {
    pub server: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Os {
    pub family: String,
    pub name: String,
    pub eosl: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Vulnerability {
    #[serde(rename = "vulnerabilityID")]
    pub vulnerability_id: String,
    pub resource: String,
    pub installed_version: String,
    pub fixed_version: String,
    pub severity: String,
    pub title: String,
    pub primary_link: String,
    pub score: Option<f64>,
    pub published_date: String,
    pub target: String,
    pub package_type: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VulnReport {
    pub artifact: Artifact,
    pub registry: Registry,
    pub os: Os,
    pub summary: Summary,
    pub vulnerabilities: Vec<Vulnerability>,
    pub update_timestamp: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Check {
    #[serde(rename = "checkID")]
    pub check_id: String,
    pub title: String,
    pub description: String,
    pub severity: String,
    pub category: String,
    pub success: bool,
    pub messages: Vec<String>,
    pub remediation: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CheckReport {
    pub checks: Vec<Check>,
    pub summary: Summary,
    pub update_timestamp: String,
}

/// Exposed secret finding. The `match` field is deliberately not parsed:
/// the dashboard has no auth, so even Trivy's masked match is never served.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct Secret {
    pub target: String,
    #[serde(rename = "ruleID")]
    pub rule_id: String,
    pub title: String,
    pub severity: String,
    pub category: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SecretReport {
    pub artifact: Artifact,
    pub registry: Registry,
    pub secrets: Vec<Secret>,
    pub update_timestamp: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ComplianceSpec {
    pub compliance: ComplianceDef,
    pub cron: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ComplianceDef {
    pub id: String,
    pub title: String,
    pub description: String,
    pub controls: Vec<ComplianceControlDef>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ComplianceControlDef {
    pub id: String,
    pub name: String,
    pub description: String,
    pub severity: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ComplianceStatus {
    pub summary: ComplianceCounts,
    pub summary_report: Option<SummaryReport>,
    pub update_timestamp: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ComplianceCounts {
    pub pass_count: u32,
    pub fail_count: u32,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SummaryReport {
    pub control_check: Vec<ControlCheck>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ControlCheck {
    #[serde(alias = "ID")]
    pub id: String,
    #[serde(alias = "Name")]
    pub name: String,
    #[serde(alias = "Severity")]
    pub severity: String,
    #[serde(alias = "TotalFail")]
    pub total_fail: Option<u32>,
}
