<script lang="ts">
  import { sevKey, sevLabel } from './format'
  let { severity }: { severity: string } = $props()
  const k = $derived(sevKey(severity))
</script>

<span class="tag"><i style:background={`var(--sev-${k})`} class:hollow={k === 'unknown'}></i>{sevLabel(k)}</span>

<style>
  .tag {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
    color: var(--ink);
    font-size: 13px;
  }
  i.hollow {
    background: transparent !important;
    box-shadow: inset 0 0 0 1.5px var(--sev-unknown);
  }
  i {
    width: 8px;
    height: 8px;
    border-radius: 2px;
    flex: none;
  }
</style>
