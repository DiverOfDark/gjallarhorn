<script lang="ts">
  import { SEVERITIES, type Sev } from './api'
  import { n, sevTotal, ratedTotal } from './format'
  import { tooltip } from './tooltip.svelte'

  let {
    sev,
    max = 0,
    height = 10,
    label = 'findings',
    rated = true,
  }: { sev: Sev; max?: number; height?: number; label?: string; rated?: boolean } = $props()

  // By default only vendor-rated findings are drawn: not-rated ones would
  // otherwise dominate every bar while saying little about risk.
  const total = $derived(rated ? ratedTotal(sev) : sevTotal(sev))
  const scale = $derived(max > 0 ? max : total)
  const segs = $derived(
    SEVERITIES.filter((k) => sev[k] > 0 && (!rated || k !== 'unknown')).map((k) => ({ k, v: sev[k] })),
  )
</script>

<div class="track" style:height={`${height}px`} role="img" aria-label={segs.map((s) => `${s.k} ${s.v}`).join(', ') || `no ${label}`}>
  {#if total > 0}
    <div class="fill" style:width={`${Math.max(1.5, (total / scale) * 100)}%`}>
      {#each segs as s (s.k)}
        <span
          class="seg"
          style:flex-grow={s.v}
          style:background={`var(--sev-${s.k})`}
          use:tooltip={`${s.k[0].toUpperCase()}${s.k.slice(1)}: ${n(s.v)} ${label}`}
        ></span>
      {/each}
    </div>
  {/if}
</div>

<style>
  .track {
    width: 100%;
    min-width: 60px;
    display: flex;
  }
  .fill {
    display: flex;
    gap: 2px;
    height: 100%;
  }
  .seg {
    flex-basis: 0;
    min-width: 3px;
    height: 100%;
    border-radius: 2px;
  }
  .seg:first-child {
    border-top-left-radius: 4px;
    border-bottom-left-radius: 4px;
  }
  .seg:last-child {
    border-top-right-radius: 4px;
    border-bottom-right-radius: 4px;
  }
  .seg:hover {
    filter: brightness(1.15);
  }
</style>
