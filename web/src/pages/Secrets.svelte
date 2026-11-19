<script lang="ts">
  import type { SecretRow } from '../lib/api'
  import Load from '../lib/Load.svelte'
  import SevTag from '../lib/SevTag.svelte'
  import { href } from '../lib/router.svelte'
</script>

<div class="page-head">
  <h1>Exposed secrets</h1>
  <span class="muted">Credentials Trivy found baked into image layers. Values are never shown here.</span>
</div>

<Load path="/secrets">
  {#snippet children(rows: SecretRow[])}
    <table class="grid top">
      <thead><tr><th>Severity</th><th>What</th><th>File in image</th><th>Image</th><th>Workload</th></tr></thead>
      <tbody>
        {#each rows as s}
          <tr>
            <td><SevTag severity={s.severity} /></td>
            <td>{s.title}<div class="faint small">{s.category}, rule {s.ruleId}</div></td>
            <td class="code">{s.target}</td>
            <td><a href={href(`/images/${s.imageId}`)}>{s.image}</a></td>
            <td><a href={href('/workloads', { ns: s.namespace, q: s.name })}>{s.namespace}/{s.name}</a> <span class="faint small">({s.container})</span></td>
          </tr>
        {:else}
          <tr><td colspan="5" class="muted">No exposed secrets found in any image.</td></tr>
        {/each}
      </tbody>
    </table>
  {/snippet}
</Load>

<style>
  .top {
    margin-top: 16px;
  }
  .small {
    font-size: 12.5px;
  }
</style>
