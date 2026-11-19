<script lang="ts">
  import type { Workload } from '../lib/api'
  import Load from '../lib/Load.svelte'
  import SevBar from '../lib/SevBar.svelte'
  import Count from '../lib/Count.svelte'
  import { matches, sevTotal, ratedTotal, sevCmp, n } from '../lib/format'
  import { href, route, setQuery } from '../lib/router.svelte'

  let q = $state(route.query.get('q') ?? '')
  const ns = $derived(route.query.get('ns') ?? '')
</script>

<div class="page-head">
  <h1>Workloads</h1>
  <span class="muted">Deployments, StatefulSets, DaemonSets and jobs, with the images they run.</span>
</div>

<Load path="/workloads">
  {#snippet children(rows: Workload[])}
    {@const namespaces = [...new Set(rows.map((r) => r.namespace))].sort()}
    {@const v = rows
      .filter((r) => (!ns || r.namespace === ns) && matches(q, r.name, r.namespace, r.kind, ...r.containers.map((c) => c.image)))
      .sort((a, b) => sevCmp(a.severity, b.severity))}
    {@const max = Math.max(1, ...v.map((r) => ratedTotal(r.severity)))}
    <div class="toolbar">
      <select value={ns} onchange={(e) => setQuery('ns', e.currentTarget.value)} aria-label="Namespace">
        <option value="">All namespaces</option>
        {#each namespaces as x}<option value={x}>{x}</option>{/each}
      </select>
      <input type="search" placeholder="Filter by name, kind or image" bind:value={q} oninput={() => setQuery('q', q)} />
      <span class="spacer"></span>
      <span class="muted">{n(v.length)} of {n(rows.length)}</span>
    </div>
    <table class="grid">
      <thead>
        <tr>
          <th>Workload</th>
          <th class="hide-sm">Images</th>
          <th style="width:18%" class="hide-sm">Vulnerabilities</th>
          <th class="num">Critical</th>
          <th class="num">High</th>
          <th class="num">Misconfig</th>
          <th class="num">Secrets</th>
        </tr>
      </thead>
      <tbody>
        {#each v as w (w.namespace + w.kind + w.name)}
          <tr>
            <td>
              <strong>{w.name}</strong>
              <div class="faint small">{w.kind} in <a href={href('/workloads', { ns: w.namespace })}>{w.namespace}</a></div>
            </td>
            <td class="small hide-sm">
              {#each w.containers as c}
                <div><a href={href(`/images/${c.imageId}`)}>{c.image}</a> <span class="faint">({c.container})</span></div>
              {/each}
            </td>
            <td class="mid hide-sm"><SevBar sev={w.severity} {max} /></td>
            <td class="num"><Count v={w.severity.critical} strong /></td>
            <td class="num"><Count v={w.severity.high} /></td>
            <td class="num">
              <a href={href('/misconfigs', { scope: 'config', q: w.name })}><Count v={sevTotal(w.misconfig)} /></a>
            </td>
            <td class="num"><Count v={w.secrets} strong /></td>
          </tr>
        {:else}
          <tr><td colspan="7" class="muted">No workloads match the filters.</td></tr>
        {/each}
      </tbody>
    </table>
  {/snippet}
</Load>

<style>
  .small {
    font-size: 12.5px;
  }
  .mid {
    vertical-align: middle;
  }
</style>
