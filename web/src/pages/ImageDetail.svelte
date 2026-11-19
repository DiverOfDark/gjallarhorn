<script lang="ts">
  import type { ImageDetail, SevKey, Vuln } from '../lib/api'
  import { SEVERITIES } from '../lib/api'
  import Load from '../lib/Load.svelte'
  import SevBar from '../lib/SevBar.svelte'
  import SevTag from '../lib/SevTag.svelte'
  import Count from '../lib/Count.svelte'
  import { matches, imageName, sevKey, sevRank, newestFix, n } from '../lib/format'
  import { href } from '../lib/router.svelte'

  let { id }: { id: string } = $props()
  let q = $state('')
  let sev = $state<SevKey | ''>('')
  let byPackage = $state(true)
  let open = $state<Record<string, boolean>>({})

  type Pkg = { key: string; pkg: string; installed: string; target: string; fixed: string[]; vulns: Vuln[]; c: number; h: number; worst: string }
  function packages(vulns: Vuln[]): Pkg[] {
    const m = new Map<string, Pkg>()
    for (const v of vulns) {
      const key = `${v.target}|${v.pkg}|${v.installed}`
      const p = m.get(key) ?? { key, pkg: v.pkg, installed: v.installed, target: v.target, fixed: [], vulns: [], c: 0, h: 0, worst: v.severity }
      p.vulns.push(v)
      if (v.fixed && !p.fixed.includes(v.fixed)) p.fixed.push(v.fixed)
      if (sevKey(v.severity) === 'critical') p.c++
      if (sevKey(v.severity) === 'high') p.h++
      if (sevRank(v.severity) > sevRank(p.worst)) p.worst = v.severity
      m.set(key, p)
    }
    return [...m.values()].sort((a, b) => b.c - a.c || b.h - a.h || b.vulns.length - a.vulns.length)
  }

  const workloadLink = (w: { namespace: string; name: string }) => href('/workloads', { ns: w.namespace, q: w.name })
</script>

<Load path={`/images/${id}`}>
  {#snippet children(d: ImageDetail)}
    {@const vulns = d.vulnerabilities.filter(
      (v) => (!sev || sevKey(v.severity) === sev) && matches(q, v.id, v.pkg, v.title, v.target),
    )}
    {@const pkgs = packages(vulns)}
    {@const workloads = [...new Map(d.workloads.map((w) => [`${w.namespace}/${w.kind}/${w.name}`, w])).values()]}
    <p class="crumb"><a href={href('/images')}>Images</a></p>
    <h1 class="title">{imageName(d)}</h1>
    <p class="muted meta">
      {d.registry}{d.os ? `, ${d.os}` : ''}
      {#if d.digest}<br /><span class="code faint">{d.digest}</span>{/if}
    </p>
    {#if d.eosl}
      <p class="eol"><strong>End-of-life OS.</strong> {d.os} no longer gets security updates. Rebuilding on a supported base image is the only fix.</p>
    {/if}

    <div class="sums">
      {#each SEVERITIES.filter((k) => d.severity[k] > 0) as k}
        <button aria-pressed={sev === k} onclick={() => (sev = sev === k ? '' : k)}>
          <span class="wide big">{n(d.severity[k])}</span>
          <SevTag severity={k} />
        </button>
      {/each}
    </div>
    <SevBar sev={d.severity} height={12} />

    <div class="cols">
      <section>
        <div class="toolbar">
          <h2>Vulnerabilities</h2>
          <div class="segmented" role="group" aria-label="Group vulnerabilities">
            <button aria-pressed={byPackage} onclick={() => (byPackage = true)}>By package</button>
            <button aria-pressed={!byPackage} onclick={() => (byPackage = false)}>By CVE</button>
          </div>
          <input type="search" placeholder="Filter by CVE, package or title" bind:value={q} />
          <span class="spacer"></span>
          <span class="muted">
            {byPackage ? `${n(pkgs.length)} packages, ` : ''}{n(vulns.length)} of {n(d.vulnerabilities.length)} findings
          </span>
        </div>
        {#if byPackage}
          <p class="hint muted">Each row is one package. Updating it to the version shown clears every finding in the row.</p>
          <table class="grid">
            <thead>
              <tr><th>Package</th><th>Installed</th><th>Update to</th><th class="num">Critical</th><th class="num">High</th><th class="num">Findings</th></tr>
            </thead>
            <tbody>
              {#each pkgs as p (p.key)}
                <tr class="clickable" onclick={() => (open[p.key] = !open[p.key])} aria-expanded={!!open[p.key]}>
                  <td><strong>{p.pkg}</strong>{#if p.target}<div class="faint small">{p.target}</div>{/if}</td>
                  <td class="code">{p.installed}</td>
                  <td class="code">{newestFix(p.fixed) || '—'}</td>
                  <td class="num"><Count v={p.c} strong /></td>
                  <td class="num"><Count v={p.h} /></td>
                  <td class="num">{p.vulns.length}</td>
                </tr>
                {#if open[p.key]}
                  <tr class="detail">
                    <td colspan="6">
                      {#each p.vulns as v (v.id)}
                        <div class="vrow"><SevTag severity={v.severity} /><a href={href(`/cves/${v.id}`)}>{v.id}</a><span class="small">{v.title}</span></div>
                      {/each}
                    </td>
                  </tr>
                {/if}
              {:else}
                <tr><td colspan="6" class="muted">No vulnerabilities match the filter.</td></tr>
              {/each}
            </tbody>
          </table>
        {:else}
        <table class="grid">
          <thead>
            <tr><th>Severity</th><th>ID</th><th>Package</th><th>Installed</th><th>Fixed in</th><th class="num">CVSS</th><th>Title</th></tr>
          </thead>
          <tbody>
            {#each vulns as v (v.id + v.pkg + v.installed + v.target)}
              <tr>
                <td><SevTag severity={v.severity} /></td>
                <td class="nowrap"><a href={href(`/cves/${v.id}`)}>{v.id}</a></td>
                <td>{v.pkg}{#if v.target}<div class="faint small">{v.target}</div>{/if}</td>
                <td class="code">{v.installed}</td>
                <td class="code">{v.fixed || '—'}</td>
                <td class="num">{v.score ?? '—'}</td>
                <td class="small">{v.title}</td>
              </tr>
            {:else}
              <tr><td colspan="7" class="muted">No vulnerabilities match the filter.</td></tr>
            {/each}
          </tbody>
        </table>
        {/if}
      </section>

      <aside>
        <h2>Running in</h2>
        <ul class="plain">
          {#each workloads as w}
            <li><a href={workloadLink(w)}>{w.name}</a> <span class="faint">{w.kind} in {w.namespace}</span></li>
          {/each}
        </ul>
        {#if d.exposedSecrets.length}
          <h2 class="gap">Exposed secrets</h2>
          <ul class="plain">
            {#each d.exposedSecrets as s}
              <li><SevTag severity={s.severity} /> {s.title}<div class="code faint">{s.target}</div></li>
            {/each}
          </ul>
        {/if}
      </aside>
    </div>
  {/snippet}
</Load>

<style>
  .crumb {
    margin: 22px 0 4px;
  }
  .title {
    word-break: break-all;
  }
  .meta {
    margin: 6px 0 0;
  }
  .eol {
    border-left: 3px solid var(--sev-high);
    padding: 6px 12px;
    background: var(--panel);
  }
  .sums {
    display: flex;
    gap: 10px;
    margin: 20px 0 12px;
    flex-wrap: wrap;
  }
  .sums button {
    display: flex;
    flex-direction: column;
    align-items: flex-start;
    padding: 8px 14px;
    min-width: 110px;
  }
  .big {
    font-size: 28px;
    font-weight: 620;
    line-height: 1.1;
  }
  .cols {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 280px;
    gap: 36px;
    margin-top: 12px;
  }
  @media (max-width: 1000px) {
    .cols {
      grid-template-columns: 1fr;
    }
  }
  aside {
    padding-top: 20px;
  }
  .gap {
    margin-top: 24px;
  }
  .plain {
    list-style: none;
    padding: 0;
    margin: 8px 0 0;
  }
  .plain li {
    padding: 5px 0;
    border-bottom: 1px solid var(--hair);
  }
  .small {
    font-size: 12.5px;
  }
  .hint {
    margin: -4px 0 8px;
    font-size: 13px;
  }
  .detail td {
    background: var(--panel);
  }
  .grid tbody tr.detail:hover td {
    background: var(--panel);
  }
  .vrow {
    display: grid;
    grid-template-columns: 90px 150px minmax(0, 1fr);
    gap: 12px;
    padding: 3px 0;
    align-items: baseline;
  }
  .nowrap {
    white-space: nowrap;
  }
</style>
