<script lang="ts">
  import type { ImageRow } from '../lib/api'
  import Load from '../lib/Load.svelte'
  import SevBar from '../lib/SevBar.svelte'
  import Count from '../lib/Count.svelte'
  import { matches, imageName, sevTotal, ratedTotal, sevCmp, n } from '../lib/format'
  import { href, route, setQuery } from '../lib/router.svelte'
  import { Sorter } from '../lib/sort.svelte'

  let q = $state(route.query.get('q') ?? '')
  const eosl = $derived(route.query.get('eosl') === '1')
  const onlyCritical = $derived(route.query.get('crit') === '1')

  const sorter = new Sorter<ImageRow>(
    {
      image: (r) => imageName(r),
      critical: (r) => r.severity.critical * 1e6 + r.severity.high,
      high: (r) => r.severity.high,
      medium: (r) => r.severity.medium,
      unknown: (r) => r.severity.unknown,
      total: (r) => sevTotal(r.severity),
      workloads: (r) => r.workloadCount,
    },
    'critical',
  )

  function view(rows: ImageRow[]) {
    const f = rows.filter(
      (r) =>
        matches(q, imageName(r), r.registry, r.os, ...r.namespaces) &&
        (!eosl || r.eosl) &&
        (!onlyCritical || r.severity.critical > 0),
    )
    return sorter.col === 'critical' ? f.sort((a, b) => (sorter.desc ? sevCmp(a.severity, b.severity) : -sevCmp(a.severity, b.severity))) : sorter.apply(f)
  }
</script>

<div class="page-head">
  <h1>Images</h1>
  <span class="muted">Each unique image digest, counted once no matter how many pods run it.</span>
</div>

<Load path="/images">
  {#snippet children(rows: ImageRow[])}
    {@const v = view(rows)}
    {@const max = Math.max(1, ...v.map((r) => ratedTotal(r.severity)))}
    <div class="toolbar">
      <input type="search" placeholder="Filter by image, registry, OS or namespace" bind:value={q} oninput={() => setQuery('q', q)} />
      <button aria-pressed={onlyCritical} onclick={() => setQuery('crit', onlyCritical ? '' : '1')}>Has critical</button>
      <button aria-pressed={eosl} onclick={() => setQuery('eosl', eosl ? '' : '1')}>End-of-life OS</button>
      <span class="spacer"></span>
      <span class="muted">{n(v.length)} of {n(rows.length)}</span>
    </div>
    <table class="grid">
      <thead>
        <tr>
          <th class="sortable" onclick={() => sorter.toggle('image')}>Image{sorter.arrow('image')}</th>
          <th style="width:22%" class="hide-sm"></th>
          <th class="num sortable" onclick={() => sorter.toggle('critical')}>Critical{sorter.arrow('critical')}</th>
          <th class="num sortable" onclick={() => sorter.toggle('high')}>High{sorter.arrow('high')}</th>
          <th class="num sortable hide-sm" onclick={() => sorter.toggle('medium')}>Medium{sorter.arrow('medium')}</th>
          <th class="num sortable hide-sm" onclick={() => sorter.toggle('unknown')}>Not rated{sorter.arrow('unknown')}</th>
          <th class="num sortable hide-sm" onclick={() => sorter.toggle('workloads')}>Workloads{sorter.arrow('workloads')}</th>
          <th class="hide-sm">Namespaces</th>
        </tr>
      </thead>
      <tbody>
        {#each v as r (r.id)}
          <tr class="clickable" onclick={() => (location.hash = href(`/images/${r.id}`))}>
            <td>
              <a href={href(`/images/${r.id}`)}>{imageName(r)}</a>
              <div class="faint small">
                {r.registry}{r.os ? `, ${r.os}` : ''}{#if r.eosl}<span class="eol">end of life</span>{/if}
              </div>
            </td>
            <td class="mid hide-sm"><SevBar sev={r.severity} {max} /></td>
            <td class="num"><Count v={r.severity.critical} strong /></td>
            <td class="num"><Count v={r.severity.high} /></td>
            <td class="num hide-sm"><Count v={r.severity.medium} /></td>
            <td class="num hide-sm faint">{n(r.severity.unknown)}</td>
            <td class="num hide-sm">{r.workloadCount}</td>
            <td class="small muted hide-sm">{r.namespaces.slice(0, 3).join(', ')}{r.namespaces.length > 3 ? ` +${r.namespaces.length - 3}` : ''}</td>
          </tr>
        {:else}
          <tr><td colspan="8" class="muted">No images match. Clear the filters to see all {rows.length}.</td></tr>
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
  .eol {
    margin-left: 8px;
    color: var(--sev-high);
  }
</style>
