import { useEffect, useState } from 'react'
import type { Account, CveResult, Evidence, Meta } from './types'

// The app's only data source: the read API (api/app.py). Every list, count and badge is computed on
// the server, so the browser holds one page of accounts however big the market gets.

// every filter takes several values (ORed); different filters are ANDed
export type ApiFilters = {
  template?: string; ids?: string[]; exclude_ids?: string[]; q?: string; since_build?: string
  country?: string[]; industry?: string[]; sector?: string[]; software?: string[]; size?: string[]; strong?: boolean
  icp_country?: string[]; icp_sector?: string[]; icp_industry?: string[]; icp_size?: string[]
}
export type Page = { total: number; offset: number; accounts: Account[] }
export type Facets = Record<'country' | 'industry' | 'sector' | 'size' | 'software', [string, number][]>

async function call<T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const r = await fetch(`./api/${path}`, body === undefined ? { signal } : {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), signal,
  })
  if (!r.ok) throw new Error(`${path}: ${r.status}`)
  return r.json()
}

export const api = {
  meta: () => call<Meta>('meta'),
  search: (f: ApiFilters, offset = 0, limit = 100, s?: AbortSignal) => call<Page>('search', { ...f, offset, limit }, s),
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
