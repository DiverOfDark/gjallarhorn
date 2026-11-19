<script lang="ts" generics="T">
  import type { Snippet } from 'svelte'
  import { get } from './api'
  import { app } from './state.svelte'

  let { path, children }: { path: string; children: Snippet<[T]> } = $props()

  let data = $state<T | null>(null)
  let error = $state<string | null>(null)

  let loadedPath = ''

  $effect(() => {
    const p = path
    void app.version
    let cancelled = false
    error = null
    // New path: drop stale data. Same path (background refresh): keep showing it.
    if (p !== loadedPath) data = null
    loadedPath = p
    get<T>(p)
      .then((d) => !cancelled && (data = d))
      .catch((e) => !cancelled && (error = e.message))
    return () => (cancelled = true)
  })
</script>

{#if error && !data}
  <div class="state">
    <p><strong>Can't load {path}.</strong> {error}</p>
    <p class="muted">The backend keeps retrying. This page updates once it has data.</p>
  </div>
{:else if data}
  {@render children(data)}
{:else}
  <div class="state muted">Loading…</div>
{/if}

<style>
  .state {
    padding: 48px 0;
  }
</style>
