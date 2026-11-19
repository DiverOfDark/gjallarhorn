<script lang="ts">
  import type { Compliance } from '../lib/api'
  import Load from '../lib/Load.svelte'
  import SevTag from '../lib/SevTag.svelte'
  import { ago } from '../lib/format'
</script>

<div class="page-head">
  <h1>Compliance</h1>
  <span class="muted">Cluster checks against published hardening benchmarks.</span>
</div>

<Load path="/compliance">
  {#snippet children(rows: Compliance[])}
    {#each rows as c (c.name)}
      <section>
        <div class="head">
          <h2>{c.title}</h2>
          {#if c.pending}
            <span class="faint">First run pending. Scheduled by cron <span class="code">{c.cron}</span>.</span>
          {:else}
            <span><strong>{c.fail}</strong> failing, {c.pass} passing <span class="faint">(updated {ago(c.updated)})</span></span>
          {/if}
        </div>
        <table class="grid">
          <thead><tr><th>Control</th><th>Name</th><th>Severity</th><th class="num">Failures</th></tr></thead>
          <tbody>
            {#each c.controls as k (k.id)}
              <tr class:passing={k.totalFail === 0}>
                <td class="faint">{k.id}</td>
                <td>{k.name}<div class="faint small">{k.description}</div></td>
                <td><SevTag severity={k.severity} /></td>
                <td class="num">{k.totalFail == null ? '—' : k.totalFail === 0 ? 'Pass' : k.totalFail}</td>
              </tr>
            {/each}
          </tbody>
        </table>
      </section>
    {:else}
      <p class="muted">No ClusterComplianceReports exist. Enable them in the trivy-operator Helm values (compliance.specs).</p>
    {/each}
  {/snippet}
</Load>

<style>
  section {
    margin-top: 28px;
  }
  .head {
    display: flex;
    flex-wrap: wrap;
    justify-content: space-between;
    align-items: baseline;
    gap: 12px;
    margin-bottom: 6px;
  }
  .small {
    font-size: 12.5px;
  }
  .passing td {
    color: var(--ink-3);
  }
</style>
