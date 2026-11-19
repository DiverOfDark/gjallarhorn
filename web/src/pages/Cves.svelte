<script lang="ts">
  import type { Cve, SevKey } from '../lib/api'
  import { SEVERITIES } from '../lib/api'
  import Load from '../lib/Load.svelte'
  import SevTag from '../lib/SevTag.svelte'
  import { matches, sevKey, sevRank, n } from '../lib/format'
  import { href, route, setQuery } from '../lib/router.svelte'
  import { Sorter } from '../lib/sort.svelte'

  let q = $state(route.query.get('q') ?? '')
  const sev = $derived((route.query.get('sev') ?? '') as SevKey | '')
  let limit = $state(300)

  const sorter = new Sorter<Cve>(
    {
      severity: (c) => sevRank(c.severity) * 1e4 + c.imageCount,
      id: (c) => c.id,
      score: (c) => c.score ?? -1,
      images: (c) => c.imageCount,
      workloads: (c) => c.workloadCount,
      published: (c) => c.published,
    },
    'severity',
  )

  const view = (rows: Cve[]) =>
    sorter.apply(rows.filter((c) => (!sev || sevKey(c.severity) === sev) && matches(q, c.id, c.title, ...c.packages, ...c.namespaces)))
</script>

<div class="page-head">
  <h1>CVEs</h1>
  <span class="muted">Every distinct vulnerability, with how far it has spread.</span>
</div>

<Load path="/cves">
  {#snippet children(rows: Cve[])}
    {@const v = view(rows)}
    {@const counts = Object.fromEntries(SEVERITIES.map((k) => [k, rows.filter((c) => sevKey(c.severity) === k).length]))}
    <div class="toolbar">
      <input type="search" placeholder="Filter by ID, package, title or namespace" bind:value={q} oninput={() => setQuery('q', q)} />
      {#each SEVERITIES.filter((k) => counts[k] > 0) as k}
        <button aria-pressed={sev === k} onclick={() => setQuery('sev', sev === k ? '' : k)}>
          <SevTag severity={k} /> <span class="muted">{n(counts[k])}</span>
        </button>
      {/each}
      <span class="spacer"></span>
      <span class="muted">{n(v.length)} of {n(rows.length)}</span>
    </div>
    <table class="grid">
      <thead>
        <tr>
          <th class="sortable" onclick={() => sorter.toggle('severity')}>Severity{sorter.arrow('severity')}</th>
          <th class="sortable" onclick={() => sorter.toggle('id')}>ID{sorter.arrow('id')}</th>
          <th class="num sortable" onclick={() => sorter.toggle('score')}>CVSS{sorter.arrow('score')}</th>
          <th>Title</th>
          <th>Packages</th>
          <th class="num sortable" onclick={() => sorter.toggle('images')}>Images{sorter.arrow('images')}</th>
          <th class="num sortable" onclick={() => sorter.toggle('workloads')}>Workloads{sorter.arrow('workloads')}</th>
          <th class="sortable" onclick={() => sorter.toggle('published')}>Published{sorter.arrow('published')}</th>
        </tr>
      </thead>
      <tbody>
        {#each v.slice(0, limit) as c (c.id)}
          <tr class="clickable" onclick={() => (location.hash = href(`/cves/${c.id}`))}>
            <td><SevTag severity={c.severity} /></td>
            <td class="nowrap"><a href={href(`/cves/${c.id}`)}>{c.id}</a></td>
            <td class="num">{c.score ?? '—'}</td>
            <td class="small">{c.title}</td>
            <td class="small muted">{c.packages.slice(0, 3).join(', ')}{c.packages.length > 3 ? ` +${c.packages.length - 3}` : ''}</td>
            <td class="num">{c.imageCount}</td>
            <td class="num">{c.workloadCount}</td>
            <td class="small muted nowrap">{c.published?.slice(0, 10) || '—'}</td>
          </tr>
        {:else}
          <tr><td colspan="8" class="muted">No CVEs match. Clear the filters to see all {n(rows.length)}.</td></tr>
        {/each}
      </tbody>
    </table>
    {#if v.length > limit}
      <p><button onclick={() => (limit += 500)}>Show 500 more ({n(v.length - limit)} hidden)</button></p>
    {/if}
  {/snippet}
</Load>

<style>
  .small {
    font-size: 12.5px;
  }
  .nowrap {
    white-space: nowrap;
  }
  .toolbar button {
    display: inline-flex;
    gap: 6px;
    align-items: center;
  }
</style>
