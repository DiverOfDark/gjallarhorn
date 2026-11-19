import type { Sev } from './api'

export const sevKey = (s: string) => (s || 'unknown').toLowerCase() as keyof Sev
export const sevRank = (s: string) => ({ CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 })[s?.toUpperCase()] ?? 0
export const sevTotal = (s: Sev) => s.critical + s.high + s.medium + s.low + s.unknown
/** Findings with a vendor severity; excludes not-yet-rated ones. */
export const ratedTotal = (s: Sev) => s.critical + s.high + s.medium + s.low
export const sevLabel = (k: string) => {
  const s = sevKey(k) === 'unknown' ? 'not rated' : sevKey(k)
  return s[0].toUpperCase() + s.slice(1)
}

const collator = new Intl.Collator(undefined, { numeric: true })
/**
 * Highest fixed version across findings. Fields may hold comma-separated
 * per-branch fixes ("1.24.13, 1.25.7"); pre-releases lose to stable versions.
 */
export function newestFix(fixed: string[]): string {
  const all = fixed.flatMap((f) => f.split(',').map((x) => x.trim())).filter(Boolean)
  const stable = all.filter((v) => !/(rc|alpha|beta|pre)/i.test(v))
  const pool = stable.length ? stable : all
  return pool.sort(collator.compare).at(-1) ?? ''
}
export const sevCmp = (a: Sev, b: Sev) =>
  b.critical - a.critical || b.high - a.high || b.medium - a.medium || b.low - a.low || b.unknown - a.unknown

const nf = new Intl.NumberFormat()
export const n = (x: number) => nf.format(x)

export function ago(iso: string | null | undefined): string {
  if (!iso) return 'never'
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 45) return 'just now'
  if (s < 3600) return `${Math.round(s / 60)} min ago`
  if (s < 86400) return `${Math.round(s / 3600)} h ago`
  return `${Math.round(s / 86400)} d ago`
}

export const imageName = (i: { repository: string; tag: string }) => (i.tag ? `${i.repository}:${i.tag}` : i.repository)

export function matches(q: string, ...fields: (string | undefined | null)[]) {
  if (!q) return true
  const needle = q.toLowerCase()
  return fields.some((f) => f && f.toLowerCase().includes(needle))
}
