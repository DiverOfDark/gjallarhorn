<script lang="ts">
  import type { CheckResource, SevKey } from '../lib/api'
  import Load from '../lib/Load.svelte'
  import SevTag from '../lib/SevTag.svelte'
  import Count from '../lib/Count.svelte'
  import { matches, sevKey, n } from '../lib/format'
  import { route, setQuery } from '../lib/router.svelte'

  let q = $state(route.query.get('q') ?? '')
  const scope = $derived((route.query.get('scope') ?? 'config') as 'config' | 'rbac')
  const sev = $derived((route.query.get('sev') ?? '') as SevKey | '')
  let open = $state<Record<string, boolean>>({})
  let byCheck = $state(false)

  const tally = (r: CheckResource) => {
    const s: Record<SevKey, number> = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }
    for (const c of r.failed) s[sevKey(c.severity)]++
    return s
  }

  const key = (r: CheckResource) => `${r.scope}/${r.namespace}/${r.kind}/${r.name}`

  function filtered(rows: CheckResource[]) {
    return rows
      .filter((r) => r.scope === scope)
      .map((r) => ({ ...r, failed: r.failed.filter((c) => !sev || sevKey(c.severity) === sev) }))
      .filter((r) => r.failed.length > 0 && matches(q, r.namespace, r.kind, r.name, ...r.failed.map((c) => c.title), ...r.failed.map((c) => c.id)))
  }

  function checks(rows: CheckResource[]) {
    const m = new Map<string, { id: string; title: string; severity: string; remediation: string; description: string; resources: CheckResource[] }>()
    for (const r of rows)
      for (const c of r.failed) {
        const e = m.get(c.id) ?? { id: c.id, title: c.title, severity: c.severity, remediation: c.remediation, description: c.description, resources: [] }
        e.resources.push(r)
        m.set(c.id, e)
      }
    return [...m.values()].sort((a, b) => b.resources.length - a.resources.length)
  }
</script>

<div class="page-head">
  <h1>{scope === 'rbac' ? 'RBAC risks' : 'Misconfigurations'}</h1>
  <span class="muted">
    {scope === 'rbac' ? 'Roles and bindings that grant more than they should.' : 'Failed Kubernetes security checks on workloads and cluster resources.'}
  </span>
</div>

<Load path="/misconfigs">
  {#snippet children(rows: CheckResource[])}
    {@const v = filtered(rows)}
    <div class="toolbar">
      <div class="segmented" role="group" aria-label="Report type">
        <button aria-pressed={scope === 'config'} onclick={() => setQuery('scope', 'config')}>Workload config</button>
        <button aria-pressed={scope === 'rbac'} onclick={() => setQuery('scope', 'rbac')}>RBAC</button>
      </div>
      <div class="segmented" role="group" aria-label="Group by">
        <button aria-pressed={!byCheck} onclick={() => (byCheck = false)}>By resource</button>
        <button aria-pressed={byCheck} onclick={() => (byCheck = true)}>By check</button>
      </div>
      <select value={sev} onchange={(e) => setQuery('sev', e.currentTarget.value)} aria-label="Severity">
        <option value="">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
      </select>
      <input type="search" placeholder="Filter by namespace, name or check" bind:value={q} oninput={() => setQuery('q', q)} />
      <span class="spacer"></span>
      <span class="muted">{n(v.length)} resources</span>
    </div>

    {#if byCheck}
      <table class="grid">
        <thead><tr><th>Severity</th><th>Check</th><th class="num">Resources</th><th>How to fix</th></tr></thead>
        <tbody>
          {#each checks(v) as c (c.id)}
            <tr class="clickable" onclick={() => (open[c.id] = !open[c.id])}>
              <td><SevTag severity={c.severity} /></td>
              <td><strong>{c.title}</strong> <span class="faint small">{c.id}</span></td>
              <td class="num">{c.resources.length}</td>
              <td class="small muted">{c.remediation}</td>
            </tr>
            {#if open[c.id]}
              <tr class="detail">
                <td></td>
                <td colspan="3" class="small">
                  <p class="muted">{c.description}</p>
                  {#each c.resources as r}<div>{r.namespace || '(cluster)'} / {r.kind} / {r.name}</div>{/each}
                </td>
              </tr>
            {/if}
          {/each}
        </tbody>
      </table>
    {:else}
      <table class="grid">
        <thead>
          <tr><th>Resource</th><th class="num">Critical</th><th class="num">High</th><th class="num">Medium</th><th class="num">Low</th><th>Failed checks</th></tr>
        </thead>
        <tbody>
          {#each v as r (key(r))}
            {@const s = tally(r)}
            {@const titles = [...new Set(r.failed.map((c) => c.title))]}
            <tr class="clickable" onclick={() => (open[key(r)] = !open[key(r)])} aria-expanded={!!open[key(r)]}>
              <td>
                <strong>{r.name}</strong>
                <div class="faint small">{r.kind}{r.namespace ? ` in ${r.namespace}` : ', cluster-wide'}</div>
              </td>
              <td class="num"><Count v={s.critical} strong /></td>
              <td class="num"><Count v={s.high} /></td>
              <td class="num"><Count v={s.medium} /></td>
              <td class="num"><Count v={s.low} /></td>
              <td class="small muted">{titles.slice(0, 3).join(', ')}{titles.length > 3 ? `, and ${titles.length - 3} more` : ''}</td>
            </tr>
            {#if open[key(r)]}
              <tr class="detail">
                <td colspan="6">
                  {#each r.failed as c}
                    <div class="check">
                      <div class="ch"><SevTag severity={c.severity} /> <strong>{c.title}</strong> <span class="faint small">{c.id}</span></div>
                      {#each c.messages as m}<div class="small">{m}</div>{/each}
                      {#if c.remediation}<div class="small muted">Fix: {c.remediation}</div>{/if}
                    </div>
                  {/each}
                </td>
              </tr>
            {/if}
          {:else}
            <tr><td colspan="6" class="muted">Nothing fails these filters.</td></tr>
          {/each}
        </tbody>
      </table>
    {/if}
  {/snippet}
</Load>

<style>
  .small {
    font-size: 12.5px;
  }
  .detail td {
    background: var(--panel);
  }
  .grid tbody tr.detail:hover td {
    background: var(--panel);
  }
  .check {
    padding: 8px 0 8px 4px;
    border-bottom: 1px solid var(--hair);
    max-width: 100ch;
  }
  .check:last-child {
    border-bottom: 0;
  }
  .ch {
    display: flex;
    gap: 10px;
    align-items: baseline;
    margin-bottom: 2px;
  }
  p {
    margin: 0 0 8px;
  }
</style>
