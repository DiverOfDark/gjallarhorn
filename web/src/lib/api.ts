export type Sev = { critical: number; high: number; medium: number; low: number; unknown: number }
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'] as const
export type SevKey = (typeof SEVERITIES)[number]

export type WorkloadRef = { namespace: string; kind: string; name: string; container: string }

export type ImageRow = {
  id: string
  registry: string
  repository: string
  tag: string
  digest: string
  os: string
  eosl: boolean
  severity: Sev
  fixable: Sev
  workloadCount: number
  namespaces: string[]
  secrets: number
  updated: string
}

export type Vuln = {
  id: string
  pkg: string
  pkgType: string
  installed: string
  fixed: string
  severity: string
  score: number | null
  title: string
  link: string
  published: string
  target: string
}

export type ImageDetail = ImageRow & { vulnerabilities: Vuln[]; workloads: WorkloadRef[]; exposedSecrets: SecretRow[] }

export type Cve = {
  id: string
  severity: string
  score: number | null
  title: string
  link: string
  published: string
  fixable: boolean
  packages: string[]
  imageCount: number
  workloadCount: number
  namespaces: string[]
}

export type CveDetail = Cve & {
  affected: { imageId: string; image: string; pkg: string; installed: string; fixed: string; target: string; workloads: WorkloadRef[] }[]
}

export type Workload = {
  namespace: string
  kind: string
  name: string
  containers: { container: string; imageId: string; image: string }[]
  severity: Sev
  fixable: Sev
  misconfig: Sev
  secrets: number
}

export type CheckOut = {
  id: string
  title: string
  description: string
  severity: string
  category: string
  messages: string[]
  remediation: string
}

export type CheckResource = {
  scope: 'config' | 'rbac'
  namespace: string
  kind: string
  name: string
  failed: CheckOut[]
  failedSev: Sev
  passCount: number
  updated: string
}

export type SecretRow = {
  namespace: string
  kind: string
  name: string
  container: string
  image: string
  imageId: string
  target: string
  ruleId: string
  title: string
  severity: string
  category: string
}

export type Compliance = {
  name: string
  id: string
  title: string
  description: string
  cron: string
  pending: boolean
  pass: number
  fail: number
  controls: { id: string; name: string; description: string; severity: string; totalFail: number | null }[]
  updated: string
}

export type NamespaceStat = {
  namespace: string
  images: number
  workloads: number
  severity: Sev
  fixable: Sev
  misconfig: Sev
  rbac: Sev
  secrets: number
}

export type Overview = {
  refreshedAt: string
  durationMs: number
  errors: string[]
  counts: {
    images: number
    workloads: number
    namespaces: number
    cves: number
    auditedResources: number
    misconfiguredResources: number
    eoslImages: number
    vulnerabilityReports: number
    configReports: number
    rbacReports: number
    secretReports: number
  }
  severity: Sev
  fixable: Sev
  misconfig: Sev
  rbac: Sev
  secrets: Sev
  namespaces: NamespaceStat[]
  topImages: ImageRow[]
  topCves: Cve[]
  recentCves: Cve[]
  compliance: Compliance[]
}

export type Status = { ready: boolean; refreshing: boolean; refreshedAt: string | null; error: string | null }

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message)
  }
}

export async function get<T>(path: string): Promise<T> {
  const r = await fetch(`/api${path}`)
  if (!r.ok) {
    let msg = `${r.status} ${r.statusText}`
    try {
      const body = await r.json()
      if (body?.error) msg = body.error
    } catch {}
    throw new ApiError(r.status, msg)
  }
  return r.json()
}

export const refresh = () => fetch('/api/refresh', { method: 'POST' })
