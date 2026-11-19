import { get, refresh as postRefresh, type Status } from './api'

/** Bumped whenever the backend publishes a new snapshot; pages refetch on change. */
export const app = $state({ version: 0, status: null as Status | null, refreshing: false })

let lastSeen: string | null = null

export async function pollStatus() {
  try {
    const s = await get<Status>('/status')
    app.status = s
    if (s.refreshedAt && s.refreshedAt !== lastSeen) {
      if (lastSeen !== null) app.version++
      lastSeen = s.refreshedAt
    }
    return s
  } catch {
    return null
  }
}

export async function refreshNow() {
  app.refreshing = true
  const before = lastSeen
  await postRefresh()
  for (let i = 0; i < 60; i++) {
    await new Promise((r) => setTimeout(r, 1000))
    const s = await pollStatus()
    if (s && !s.refreshing && s.refreshedAt !== before) break
  }
  app.refreshing = false
}
