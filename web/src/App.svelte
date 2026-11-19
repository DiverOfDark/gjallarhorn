<script lang="ts">
  import { onMount } from 'svelte'
  import { route, href } from './lib/router.svelte'
  import { app, pollStatus, refreshNow } from './lib/state.svelte'
  import { tip } from './lib/tooltip.svelte'
  import { ago } from './lib/format'
  import Overview from './pages/Overview.svelte'
  import Images from './pages/Images.svelte'
  import ImageDetail from './pages/ImageDetail.svelte'
  import Cves from './pages/Cves.svelte'
  import CveDetail from './pages/CveDetail.svelte'
  import Workloads from './pages/Workloads.svelte'
  import Misconfigs from './pages/Misconfigs.svelte'
  import Secrets from './pages/Secrets.svelte'
  import Compliance from './pages/Compliance.svelte'

  const nav = [
    ['', 'Overview'],
    ['images', 'Images'],
    ['cves', 'CVEs'],
    ['workloads', 'Workloads'],
    ['misconfigs', 'Misconfigurations'],
    ['secrets', 'Secrets'],
    ['compliance', 'Compliance'],
  ] as const

  let theme = $state(localStorage.getItem('theme') ?? (matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'))
  $effect(() => {
    document.documentElement.dataset.theme = theme
    localStorage.setItem('theme', theme)
  })

  let now = $state(Date.now())
  onMount(() => {
    pollStatus()
    const a = setInterval(pollStatus, 20000)
    const b = setInterval(() => (now = Date.now()), 15000)
    return () => {
      clearInterval(a)
      clearInterval(b)
    }
  })

  const section = $derived(route.parts[0] ?? '')
  const refreshedLabel = $derived((void now, ago(app.status?.refreshedAt)))
</script>

<header>
  <div class="bar">
    <a class="brand" href="#/">
      <svg viewBox="0 0 32 32" width="22" height="22" aria-hidden="true"><path d="M4 22c6-1 12-6 16-14l4 2c-3 8-9 15-19 17z" fill="var(--sev-high)" /><circle cx="25" cy="8" r="4" fill="none" stroke="var(--sev-critical)" stroke-width="2.5" /></svg>
      <span class="wide">Gjallarhorn</span>
    </a>
    <nav>
      {#each nav as [p, label]}
        <a href={`#/${p}`} aria-current={section === p ? 'page' : undefined}>{label}</a>
      {/each}
    </nav>
    <div class="status">
      {#if app.status?.error}
        <span class="err" title={app.status.error}>Last refresh failed</span>
      {/if}
      <span class="faint">Scanned {refreshedLabel}</span>
      <button onclick={refreshNow} disabled={app.refreshing}>{app.refreshing ? 'Refreshing…' : 'Refresh'}</button>
      <button
        class="theme"
        onclick={() => (theme = theme === 'dark' ? 'light' : 'dark')}
        aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>{theme === 'dark' ? '☀' : '☾'}</button
      >
    </div>
  </div>
</header>

<main>
  {#if section === ''}
    <Overview />
  {:else if section === 'images' && route.parts[1]}
    <ImageDetail id={route.parts[1]} />
  {:else if section === 'images'}
    <Images />
  {:else if section === 'cves' && route.parts[1]}
    <CveDetail id={route.parts[1]} />
  {:else if section === 'cves'}
    <Cves />
  {:else if section === 'workloads'}
    <Workloads />
  {:else if section === 'misconfigs'}
    <Misconfigs />
  {:else if section === 'secrets'}
    <Secrets />
  {:else if section === 'compliance'}
    <Compliance />
  {:else}
    <p class="muted">No page here. <a href={href('/')}>Go to the overview</a>.</p>
  {/if}
</main>

{#if tip.show}
  <div class="tip" style:left={`${tip.x + 12}px`} style:top={`${tip.y + 14}px`} role="tooltip">{tip.text}</div>
{/if}

<style>
  header {
    position: sticky;
    top: 0;
    z-index: 10;
    background: var(--bg);
    border-bottom: 1px solid var(--hair-2);
  }
  .bar {
    max-width: 1440px;
    margin: 0 auto;
    padding: 0 28px;
    display: flex;
    align-items: center;
    gap: 28px;
    height: 54px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--ink);
    font-weight: 650;
    font-size: 16px;
  }
  .brand:hover {
    text-decoration: none;
  }
  nav {
    display: flex;
    gap: 2px;
    overflow-x: auto;
  }
  nav a {
    color: var(--ink-2);
    padding: 16px 10px 14px;
    border-bottom: 2px solid transparent;
    white-space: nowrap;
  }
  nav a:hover {
    color: var(--ink);
    text-decoration: none;
  }
  nav a[aria-current='page'] {
    color: var(--ink);
    border-bottom-color: var(--accent);
  }
  .status {
    margin-left: auto;
    display: flex;
    align-items: center;
    gap: 10px;
    font-size: 13px;
    white-space: nowrap;
  }
  .err {
    color: var(--sev-high);
  }
  .theme {
    width: 32px;
    padding: 4px 0;
  }
  main {
    max-width: 1440px;
    margin: 0 auto;
    padding: 0 28px 80px;
  }
  .tip {
    position: fixed;
    pointer-events: none;
    background: var(--panel-2);
    color: var(--ink);
    border: 1px solid var(--hair-2);
    border-radius: var(--r-m);
    padding: 4px 9px;
    font-size: 12.5px;
    z-index: 100;
    box-shadow: 0 4px 14px rgba(0, 0, 0, 0.25);
  }
  @media (max-width: 1100px) {
    .bar {
      flex-wrap: wrap;
      height: auto;
      gap: 0 16px;
      padding: 8px 20px 0;
    }
    nav {
      order: 3;
      flex: 1 1 100%;
      margin: 0 -10px;
    }
    nav a {
      padding: 10px 10px 9px;
    }
  }
  @media (max-width: 640px) {
    .bar {
      padding: 8px 16px 0;
    }
    .status .faint {
      display: none;
    }
    main {
      padding: 0 16px 60px;
    }
  }
</style>
