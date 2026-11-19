<script lang="ts">
  // A table cell number: zero renders faint so non-zero values stand out.
  import { n } from './format'
  let { v, strong = false }: { v: number; strong?: boolean } = $props()
</script>

<span class:zero={v === 0} class:strong={strong && v > 0}>{v === 0 ? '0' : n(v)}</span>

<style>
  .zero {
    color: var(--ink-3);
    opacity: 0.6;
  }
  .strong {
    font-weight: 650;
  }
</style>
