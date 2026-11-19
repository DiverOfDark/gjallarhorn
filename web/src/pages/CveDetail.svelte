<script lang="ts">
  import type { CveDetail } from '../lib/api'
  import Load from '../lib/Load.svelte'
  import SevTag from '../lib/SevTag.svelte'
  import { href } from '../lib/router.svelte'

  let { id }: { id: string } = $props()
</script>

<Load path={`/cves/${encodeURIComponent(id)}`}>
  {#snippet children(c: CveDetail)}
    <p class="crumb"><a href={href('/cves')}>CVEs</a></p>
    <div class="page-head">
      <h1>{c.id}</h1>
      <SevTag severity={c.severity} />
      {#if c.score != null}<span class="muted">CVSS {c.score}</span>{/if}
    </div>
    <p class="lead">{c.title}</p>
    <p class="muted">
      {#if c.published}Published {c.published.slice(0, 10)}.{/if}
      {c.fixable ? 'A fixed version exists.' : 'No fixed version yet.'}
      {#if c.link}<a href={c.link} target="_blank" rel="noreferrer noopener">Read the advisory</a>{/if}
    </p>

    <h2 class="gap">Affected images ({new Set(c.affected.map((a) => a.imageId)).size})</h2>
    <table class="grid">
      <thead><tr><th>Image</th><th>Package</th><th>Installed</th><th>Fixed in</th><th>Workloads</th></tr></thead>
      <tbody>
        {#each c.affected as a}
          <tr>
            <td><a href={href(`/images/${a.imageId}`)}>{a.image}</a>{#if a.target}<div class="faint small">{a.target}</div>{/if}</td>
            <td>{a.pkg}</td>
            <td class="code">{a.installed}</td>
            <td class="code">{a.fixed || '—'}</td>
            <td class="small">
              {#each [...new Map(a.workloads.map((w) => [`${w.namespace}/${w.name}`, w])).values()] as w, i}
                {#if i > 0}, {/if}<a href={href('/workloads', { ns: w.namespace, q: w.name })}>{w.namespace}/{w.name}</a>
              {/each}
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/snippet}
</Load>

<style>
  .crumb {
    margin: 22px 0 4px;
  }
  .lead {
    font-size: 17px;
    max-width: 75ch;
    margin: 10px 0 6px;
  }
  .gap {
    margin: 28px 0 8px;
  }
  .small {
    font-size: 12.5px;
  }
</style>
