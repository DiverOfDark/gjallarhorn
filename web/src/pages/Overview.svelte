<script lang="ts">
  import type { Overview, ImageRow, NamespaceStat } from '../lib/api'
  import Load from '../lib/Load.svelte'
  import SevBar from '../lib/SevBar.svelte'
  import SevTag from '../lib/SevTag.svelte'
  import Count from '../lib/Count.svelte'
  import { n, sevTotal, ratedTotal, imageName, ago } from '../lib/format'
  import { href } from '../lib/router.svelte'
  import { tooltip } from '../lib/tooltip.svelte'

  type Lens = 'severity' | 'misconfig' | 'rbac'
  let lens = $state<Lens>('severity')
  const lensLabel: Record<Lens, string> = {
    severity: 'Vulnerabilities',
    misconfig: 'Misconfigurations',
    rbac: 'RBAC',
  }
  const lensUnit: Record<Lens, string> = { severity: 'findings', misconfig: 'failed checks', rbac: 'failed checks' }

  const WORDS = ['No', 'One', 'Two', 'Three', 'Four', 'Five']

  /** The few images that hold most of the worst findings. */
  function fixFirst(o: Overview) {
    const level: 'critical' | 'high' = o.severity.critical > 0 ? 'critical' : 'high'
    const total = o.severity[level]
    const picks = [...o.topImages]
      .filter((i) => i.severity[level] > 0)
      .sort((a, b) => b.severity[level] - a.severity[level] || b.severity.high - a.severity.high)
      .slice(0, 5)
    const covered = picks.reduce((s, i) => s + i.severity[level], 0)
    const allFixable = picks.every((i) => i.fixable[level] === i.severity[level])
    return { level, total, picks, covered, allFixable, max: Math.max(1, ...picks.map((i) => i.severity[level])) }
  }

  function nsRows(o: Overview) {
    const rows = o.namespaces.filter((x) => ratedTotal(x[lens]) > 0)
    rows.sort(
      (a, b) =>
        b[lens].critical - a[lens].critical || b[lens].high - a[lens].high || ratedTotal(b[lens]) - ratedTotal(a[lens]),
    )
    return rows
  }
  const nsLink = (x: NamespaceStat) =>
    lens === 'severity'
      ? href('/workloads', { ns: x.namespace })
      : href('/misconfigs', { scope: lens === 'rbac' ? 'rbac' : 'config', q: x.namespace })

  const where = (i: ImageRow) =>
    i.namespaces.length <= 2 ? i.namespaces.join(', ') : `${i.namespaces.slice(0, 2).join(', ')} and ${i.namespaces.length - 2} more`
</script>

<Load path="/overview">
  {#snippet children(o: Overview)}
    {@const f = fixFirst(o)}
    {@const rows = nsRows(o)}
    {@const nsMax = Math.max(1, ...rows.map((r) => ratedTotal(r[lens])))}

    {#if o.errors.length}
      <div class="warn" role="alert">
        <strong>Some report types could not be read.</strong> Everything else on this page uses the reports that loaded.
        <ul>{#each o.errors as e}<li class="code">{e}</li>{/each}</ul>
      </div>
    {/if}

    <!-- Fix first: the one bold element on the page. -->
    <section class="hero">
      {#if f.picks.length}
        <div class="intro">
        <h1 class="headline">
          {WORDS[f.picks.length]}
          {f.picks.length === 1 ? 'image carries' : 'images carry'}
          {n(f.covered)} of your {n(f.total)}
          {f.level} vulnerabilities.
        </h1>
        <p class="lede muted">
          {#if f.allFixable}
            Every one of them has a fixed version upstream. Updating these images first removes the most risk for the
            least work.
          {:else}
            Updating these images first removes the most risk for the least work.
          {/if}
        </p>

        <div class="share" role="img" aria-label={`${f.covered} of ${f.total} ${f.level} vulnerabilities are in these images`}>
          {#each f.picks as i, idx (i.id)}
            <a
              class="part"
              href={href(`/images/${i.id}`)}
              style:flex-grow={i.severity[f.level]}
              use:tooltip={`${idx + 1}. ${imageName(i)}: ${i.severity[f.level]} ${f.level}`}><span>{idx + 1}</span></a
            >
          {/each}
          {#if f.total > f.covered}
            <span class="rest" style:flex-grow={f.total - f.covered} use:tooltip={`${f.total - f.covered} ${f.level} in ${o.counts.images - f.picks.length} other images`}
            ></span>
          {/if}
        </div>
        </div>

        <ol class="fix">
          {#each f.picks as i, idx (i.id)}
            <li>
              <span class="rank wide">{idx + 1}</span>
              <div class="what">
                <a class="img" href={href(`/images/${i.id}`)}>{imageName(i)}</a>
                <span class="faint small">
                  Runs in {where(i)}{#if i.eosl}<span class="eol">, end-of-life OS</span>{/if}
                </span>
              </div>
              <div class="counts">
                <span><strong>{i.severity.critical}</strong> critical</span>
                <span class="muted">{i.severity.high} high</span>
              </div>
            </li>
          {/each}
        </ol>
      {:else}
        <h1 class="headline">No critical or high vulnerabilities in running images.</h1>
        <p class="lede muted">Trivy scanned {n(o.counts.images)} images. The lists below cover misconfigurations and secrets.</p>
      {/if}
    </section>

    <section class="ledger" aria-label="All vulnerability findings">
      <div class="tally">
        {#each ['critical', 'high', 'medium', 'low'] as const as k}
          {#if o.severity[k] > 0 || k !== 'low'}
            <a href={href('/cves', { sev: k })}><span class="v wide">{n(o.severity[k])}</span> <SevTag severity={k} /></a>
          {/if}
        {/each}
      </div>
      <SevBar sev={o.severity} height={8} />
      <p class="small muted">
        {n(o.counts.cves)} distinct CVEs across {n(o.counts.images)} images in {n(o.counts.workloads)} workloads.
        {#if o.severity.unknown > 0}
          <a href={href('/cves', { sev: 'unknown' })}>{n(o.severity.unknown)} more findings</a> are too new to have a vendor
          rating and are left out of the bars.
        {/if}
      </p>
    </section>

    <section class="strip">
      <a class="stat" href={href('/misconfigs', { scope: 'config' })}>
        <span class="v wide">{n(o.counts.misconfiguredResources)}</span>
        <span>misconfigured resources</span>
        <span class="small muted">{n(o.misconfig.high)} high-severity failed checks</span>
      </a>
      <a class="stat" href={href('/misconfigs', { scope: 'rbac' })}>
        <span class="v wide">{n(o.rbac.critical)}</span>
        <span>critical RBAC risks</span>
        <span class="small muted">{n(sevTotal(o.rbac))} RBAC findings in total</span>
      </a>
      <a class="stat" href={href('/secrets')}>
        <span class="v wide">{n(sevTotal(o.secrets))}</span>
        <span>secrets baked into images</span>
        <span class="small muted">{n(o.secrets.critical)} critical</span>
      </a>
      <a class="stat" href={href('/images', { eosl: '1' })}>
        <span class="v wide">{n(o.counts.eoslImages)}</span>
        <span>images on an end-of-life OS</span>
        <span class="small muted">they get no more OS security fixes</span>
      </a>
    </section>

    <div class="cols">
      <section>
        <div class="sec-head">
          <h2>Namespaces</h2>
          <div class="segmented seg-ctl" role="group" aria-label="Measure namespaces by">
            {#each Object.keys(lensLabel) as l}
              <button aria-pressed={lens === l} onclick={() => (lens = l as Lens)}>{lensLabel[l as Lens]}</button>
            {/each}
          </div>
        </div>
        <table class="grid nsgrid">
          <thead>
            <tr>
              <th>Namespace</th>
              <th class="hide-sm" style="width:46%"><span class="sr">Distribution</span></th>
              <th class="num">Critical</th>
              <th class="num">High</th>
              <th class="num hide-sm">Rated</th>
            </tr>
          </thead>
          <tbody>
            {#each rows as x (x.namespace)}
              <tr class="clickable" onclick={() => (location.hash = nsLink(x))}>
                <td><a href={nsLink(x)}>{x.namespace}</a></td>
                <td class="hide-sm"><SevBar sev={x[lens]} max={nsMax} label={lensUnit[lens]} /></td>
                <td class="num"><Count v={x[lens].critical} strong /></td>
                <td class="num"><Count v={x[lens].high} /></td>
                <td class="num hide-sm"><Count v={ratedTotal(x[lens])} /></td>
              </tr>
            {:else}
              <tr><td colspan="5" class="muted">No namespace has {lensUnit[lens]} of this kind.</td></tr>
            {/each}
          </tbody>
        </table>
      </section>

      <aside>
        <section>
          <div class="sec-head"><h2>New this month</h2><a href={href('/cves')}>All CVEs</a></div>
          <ul class="list">
            {#each o.recentCves as c (c.id)}
              <li>
                <span class="cve"><SevTag severity={c.severity} /><a href={href(`/cves/${c.id}`)}>{c.id}</a></span>
                <span class="faint small">{ago(c.published)}, {c.imageCount} {c.imageCount === 1 ? 'image' : 'images'}</span>
              </li>
            {:else}
              <li class="muted">No critical or high CVEs published in the last 30 days affect your images.</li>
            {/each}
          </ul>
        </section>

        <section>
          <div class="sec-head"><h2>Most widespread</h2><a href={href('/cves')}>All {n(o.counts.cves)}</a></div>
          <ul class="list">
            {#each o.topCves as c (c.id)}
              <li>
                <span class="cve"><SevTag severity={c.severity} /><a href={href(`/cves/${c.id}`)}>{c.id}</a></span>
                <span class="faint small">{c.imageCount} {c.imageCount === 1 ? 'image' : 'images'}</span>
              </li>
            {/each}
          </ul>
        </section>

        <section>
          <div class="sec-head"><h2>Compliance</h2><a href={href('/compliance')}>Details</a></div>
          <ul class="list">
            {#each o.compliance as c (c.name)}
              <li class="comp">
                <span>{c.title}</span>
                {#if c.pending}
                  <span class="faint small nowrap">not run yet</span>
                {:else}
                  <span class="small nowrap"><strong>{c.fail}</strong> failing</span>
                {/if}
              </li>
            {:else}
              <li class="muted">No compliance reports are configured.</li>
            {/each}
          </ul>
        </section>
      </aside>
    </div>
  {/snippet}
</Load>

<style>
  .warn {
    border-left: 3px solid var(--sev-high);
    padding: 8px 14px;
    margin: 20px 0 0;
    background: var(--panel);
  }
  .small {
    font-size: 12.5px;
  }
  .nowrap {
    white-space: nowrap;
  }
  .sr {
    position: absolute;
    width: 1px;
    height: 1px;
    overflow: hidden;
    clip: rect(0 0 0 0);
  }

  /* ---- hero */
  .hero {
    padding: 44px 0 32px;
    display: grid;
    grid-template-columns: minmax(0, 5fr) minmax(0, 6fr);
    gap: 24px 64px;
    align-items: end;
  }
  @media (max-width: 1100px) {
    .hero {
      grid-template-columns: 1fr;
    }
  }
  .headline {
    font-size: clamp(30px, 4.2vw, 50px);
    font-stretch: 122%;
    font-weight: 620;
    line-height: 1.05;
    letter-spacing: -0.025em;
    max-width: 20ch;
    text-wrap: balance;
  }
  .lede {
    max-width: 62ch;
    font-size: 16px;
    margin: 14px 0 26px;
  }
  .share {
    display: flex;
    gap: 3px;
    height: 30px;
  }
  .part {
    flex-basis: 0;
    min-width: 22px;
    background: var(--sev-critical);
    border-radius: 3px;
    display: flex;
    align-items: center;
    padding-left: 8px;
    color: #fff;
    font-weight: 650;
    font-size: 13px;
  }
  .part:hover {
    text-decoration: none;
    filter: brightness(1.12);
  }
  .rest {
    flex-basis: 0;
    border-radius: 3px;
    box-shadow: inset 0 0 0 1.5px var(--hair-2);
    background: repeating-linear-gradient(135deg, transparent 0 5px, var(--hair) 5px 6px);
  }
  .fix {
    list-style: none;
    padding: 0;
    margin: 0;
  }
  .fix li:first-child {
    border-top: 0;
  }
  .fix li {
    display: grid;
    grid-template-columns: 34px minmax(0, 1fr) auto;
    align-items: center;
    gap: 16px;
    padding: 10px 0;
    border-top: 1px solid var(--hair);
  }
  .rank {
    font-size: 22px;
    font-weight: 600;
    color: var(--ink-3);
  }
  .what {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }
  .img {
    font-size: 15.5px;
    font-weight: 560;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  .eol {
    color: var(--sev-high);
  }
  .counts {
    display: flex;
    gap: 14px;
    justify-content: flex-end;
    font-size: 13.5px;
    white-space: nowrap;
  }

  /* ---- ledger of all findings */
  .ledger {
    padding: 22px 0 18px;
    border-top: 1px solid var(--hair-2);
  }
  .tally {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 36px;
    margin-bottom: 12px;
  }
  .tally a {
    display: inline-flex;
    align-items: baseline;
    gap: 10px;
    color: var(--ink);
  }
  .tally a:hover {
    text-decoration: none;
  }
  .tally a:hover .v {
    color: var(--accent);
  }
  .tally .v {
    font-size: 26px;
    font-weight: 600;
  }
  .ledger p {
    margin: 10px 0 0;
    max-width: 90ch;
  }

  /* ---- secondary signals */
  .strip {
    display: grid;
    grid-template-columns: repeat(4, minmax(0, 1fr));
    border-top: 1px solid var(--hair-2);
    border-bottom: 1px solid var(--hair-2);
  }
  .stat {
    display: flex;
    flex-direction: column;
    padding: 16px 18px;
    color: var(--ink);
    border-left: 1px solid var(--hair);
  }
  .stat:first-child {
    border-left: 0;
    padding-left: 0;
  }
  .stat:hover {
    text-decoration: none;
    background: var(--accent-wash);
  }
  .stat .v {
    font-size: 28px;
    font-weight: 600;
    line-height: 1.1;
  }

  /* ---- columns */
  .cols {
    display: grid;
    grid-template-columns: minmax(0, 1.7fr) minmax(280px, 1fr);
    gap: 44px;
    margin-top: 34px;
  }
  .sec-head {
    display: flex;
    align-items: baseline;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 8px 12px;
    margin-bottom: 8px;
  }
  .seg-ctl button {
    font-size: 12.5px;
    padding: 3px 9px;
  }
  .nsgrid td {
    vertical-align: middle;
    padding-top: 6px;
    padding-bottom: 6px;
  }
  aside {
    display: flex;
    flex-direction: column;
    gap: 30px;
  }
  .list {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .list li {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
    gap: 12px;
    padding: 6px 0;
    border-bottom: 1px solid var(--hair);
  }
  .cve {
    display: flex;
    gap: 10px;
    align-items: baseline;
    min-width: 0;
  }
  .cve :global(.tag) {
    width: 64px;
    flex: none;
  }

  @media (max-width: 1000px) {
    .cols {
      grid-template-columns: 1fr;
    }
    .strip {
      grid-template-columns: repeat(2, minmax(0, 1fr));
    }
    .stat:nth-child(3) {
      border-left: 0;
      padding-left: 0;
    }
    .stat:nth-child(n + 3) {
      border-top: 1px solid var(--hair);
    }
  }
  @media (max-width: 640px) {
    .hero {
      padding-top: 28px;
    }
    .fix li {
      grid-template-columns: 24px minmax(0, 1fr);
      gap: 4px 12px;
    }
    .counts {
      grid-column: 2;
      justify-content: flex-start;
    }
    .stat {
      padding: 12px 12px 12px 0;
    }
    .stat:nth-child(even) {
      padding-left: 12px;
    }
    .stat .v {
      font-size: 24px;
    }
  }
</style>
