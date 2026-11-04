import { useEffect, useState } from 'react'
import type { Account, CveResult, Evidence, Meta } from './types'
import type { FilterSet } from './filters'
import type { WorkspaceSnapshot } from './workspace'

// The app's only data source: the read API (api/app.py). Every list, count and badge is computed on
// the server, so the browser holds one page of accounts however big the market gets.

// every filter takes several values (ORed); different filters are ANDed
export type ApiFilters = {
  template?: string; list_id?: string; exclude_listed?: boolean; q?: string; since_build?: string
  country?: string[]; industry?: string[]; sector?: string[]; software?: string[]; size?: string[]; strong?: boolean
  icp_country?: string[]; icp_sector?: string[]; icp_industry?: string[]; icp_size?: string[]
}
export type Page = { total: number; offset: number; accounts: Account[] }
export type Facets = Record<'country' | 'industry' | 'sector' | 'size' | 'software', [string, number][]>

// every route but login needs a session; a 401 anywhere sends the app to the sign-in screen
export const SIGN_IN = 'recon:sign-in'
let signInNeeded = false
export const needsSignIn = () => signInNeeded

const pause = (ms: number, signal?: AbortSignal) => new Promise<void>((done, fail) => {
  const t = setTimeout(done, ms)
  signal?.addEventListener('abort', () => { clearTimeout(t); fail(signal.reason) }, { once: true })
})

// worth asking again: throttled, briefly unavailable, or an error page from the tunnel in front of the
// app (ngrok marks its own with this header, e.g. while its session reconnects)
const transient = (r: Response) => [429, 502, 503, 504].includes(r.status) || r.headers.has('ngrok-error-code')

async function call<T>(path: string, body?: unknown, signal?: AbortSignal, method?: string): Promise<T> {
  const send = () => fetch(`./api/${path}`, body === undefined && !method ? { signal } : {
    method: method ?? 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body ?? {}), signal,
  })
  // a dropped connection or a transient answer is retried with backoff (about 3 s in all) before giving up
  let r!: Response
  for (let wait = 400; ; wait *= 2) {
    try {
      r = await send()
      if (!transient(r) || wait > 1600) break
    } catch (e) {
      if (signal?.aborted || wait > 1600) throw e
    }
    await pause(wait + Math.random() * 200, signal)
  }
  if (r.status === 401 && path !== 'login') {
    signInNeeded = true
    window.dispatchEvent(new Event(SIGN_IN))
  }
  if (!r.ok) throw new Error(`${path}: ${r.status}`)
  return r.json()
}

export const api = {
  login: (username: string, password: string) => call<{ username: string }>('login', { username, password }),
  logout: () => call('logout', {}),
  me: () => call<{ username: string }>('me'),
  meta: () => call<Meta>('meta'),
  // your work (api/workspace.py)
  workspace: () => call<WorkspaceSnapshot>('workspace'),
  createList: (id: string, name: string) => call('lists', { id, name }),
  renameList: (id: string, name: string) => call(`lists/${id}`, { name }, undefined, 'PATCH'),
  deleteList: (id: string) => call(`lists/${id}`, undefined, undefined, 'DELETE'),
  addToList: (id: string, what: { ids?: string[]; search?: ApiFilters }) =>
    call<{ added: number; in_list: number }>(`lists/${id}/items`, what),
  removeFromList: (id: string, ids: string[]) => call(`lists/${id}/items/remove`, { ids }),
  setStatus: (account_id: string, status: string) => call('status', { account_id, status }, undefined, 'PUT'),
  saveSearch: (id: string, name: string, filters: FilterSet, profile: ApiFilters) => call('searches', { id, name, filters, profile }),
  updateSearch: (id: string, patch: { reviewed?: boolean; schedule?: string }) => call(`searches/${id}`, patch, undefined, 'PATCH'),
  deleteSearch: (id: string) => call(`searches/${id}`, undefined, undefined, 'DELETE'),
  saveProfile: (p: unknown) => call('profile', p, undefined, 'PUT'),
  search: (f: ApiFilters, offset = 0, limit = 100, s?: AbortSignal) => call<Page>('search', { ...f, offset, limit }, s),
  ids: (f: ApiFilters, limit = 5000) => call<{ total: number; ids: string[] }>('ids', { ...f, limit }),
  counts: (f: ApiFilters, s?: AbortSignal) => call<Record<string, number>>('counts', f, s),
  facets: (f: ApiFilters, dims?: string[], s?: AbortSignal) => call<Facets>('facets', dims ? { ...f, dims } : f, s),
  account: (id: string) => call<Account>(`accounts/${encodeURIComponent(id)}`),
  evidence: (id: string) => call<Evidence[]>(`accounts/${encodeURIComponent(id)}/evidence`),
  cve: (cve: string, f: ApiFilters, s?: AbortSignal) => call<CveResult>('cve', { ...f, cve }, s),
  async exportCsv(f: ApiFilters) {
    const r = await fetch('./api/export.csv', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(f) })
    const url = URL.createObjectURL(await r.blob())
    Object.assign(document.createElement('a'), { href: url, download: 'accounts.csv' }).click()
    URL.revokeObjectURL(url)
  },
}

// answers for the same request are reused for the session (the data only changes with a new build)
const cache = new Map<string, unknown>()
const remember = (k: string, v: unknown) => {
  if (cache.size > 300) cache.delete(cache.keys().next().value!)
  cache.set(k, v)
}

/** Runs fn whenever key changes; a newer key cancels the older request. Keeps the last answer on
 *  screen while the next one loads, so lists don't flash. key = null means "don't ask yet". */
export function useApi<T>(key: string | null, fn: (signal: AbortSignal) => Promise<T>) {
  const [state, setState] = useState<{ key: string | null; data: T | null; error: boolean }>(
    () => ({ key, data: key && cache.has(key) ? (cache.get(key) as T) : null, error: false }))
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    if (key === null) return
    if (cache.has(key)) {
      setState({ key, data: cache.get(key) as T, error: false })
      return
    }
    const ctl = new AbortController()
    fn(ctl.signal)
      .then((data) => { remember(key, data); setState({ key, data, error: false }) })
      .catch((e) => { if (!ctl.signal.aborted) { console.error(e); setState((s) => ({ ...s, key, error: true })) } })
    return () => ctl.abort()
    // fn is recreated each render; the key is what identifies the request
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, retry])
  return { data: state.data, loading: key !== null && state.key !== key, error: state.error, retry: () => setRetry((n) => n + 1) }
}

export function useDebounced<T>(value: T, ms = 200) {
  const [v, setV] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setV(value), ms)
    return () => clearTimeout(t)
  }, [value, ms])
  return v
}
