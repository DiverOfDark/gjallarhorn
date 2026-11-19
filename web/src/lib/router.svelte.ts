// Tiny hash router: #/path/segments?key=value
function parse() {
  const raw = location.hash.replace(/^#/, '') || '/'
  const [path, qs = ''] = raw.split('?')
  return { parts: path.split('/').filter(Boolean).map(decodeURIComponent), query: new URLSearchParams(qs) }
}

export const route = $state(parse())

window.addEventListener('hashchange', () => {
  const r = parse()
  route.parts = r.parts
  route.query = r.query
  window.scrollTo(0, 0)
})

export function href(path: string, query: Record<string, string | undefined> = {}) {
  const q = new URLSearchParams(Object.entries(query).filter(([, v]) => v) as [string, string][]).toString()
  return `#${path}${q ? `?${q}` : ''}`
}

/** Update one query param without adding history noise. */
export function setQuery(key: string, value: string) {
  const q = new URLSearchParams(route.query)
  if (value) q.set(key, value)
  else q.delete(key)
  const path = '/' + route.parts.map(encodeURIComponent).join('/')
  history.replaceState(null, '', href(path, Object.fromEntries(q)))
  route.query = q
}
