import type { ApiFilters } from './api'
import { DEFAULT_PLAY } from './plays'

// A search: a view (the market, a signal template or one of your lists) plus filters. Every filter
// takes several values, ORed (GB or IE); different filters are ANDed. Kept in the URL so a search can
// be shared, and saved as a named search that can be run again later.
export type FilterSet = {
  play: string
  q: string
  country: string[]
  industry: string[]
  sector: string[]
  software: string[]
  size: string[]
  strong: boolean
  hideListed: boolean // leave out accounts already in any of your lists
}
export type ViewState = FilterSet & { id: string | null; search: string | null; onlyNew: boolean }

export const MULTI = ['country', 'industry', 'sector', 'software', 'size'] as const
export const NO_FILTERS = { q: '', country: [], industry: [], sector: [], software: [], size: [], strong: false, hideListed: false }

const arr = (v: unknown): string[] => (Array.isArray(v) ? v.map(String) : typeof v === 'string' && v ? [v] : [])

/** A filter set from storage or a link, with every field present and every filter a list. */
export function normalise(x: Partial<Record<keyof FilterSet, unknown>>): FilterSet {
  const play = typeof x.play === 'string' ? x.play : DEFAULT_PLAY
  return {
    play, q: typeof x.q === 'string' ? x.q : '', strong: !!x.strong, hideListed: !!x.hideListed,
    country: arr(x.country), industry: arr(x.industry), sector: arr(x.sector), software: arr(x.software), size: arr(x.size),
  }
}

export function readUrl(): ViewState {
  const p = new URLSearchParams(window.location.search)
  const list = (k: string) => (p.get(k) ? p.get(k)!.split(',').filter(Boolean) : [])
  return {
    play: p.get('import') ? 'list:mine' : p.get('play') ?? DEFAULT_PLAY,
    q: p.get('q') ?? '', country: list('country'), industry: list('industry'), sector: list('sector'),
    software: list('software'), size: list('size'), strong: p.get('strong') === '1', hideListed: p.get('new') === '1',
    id: p.get('account'), search: p.get('search'), onlyNew: p.get('since') === '1',
  }
}

export function writeUrl(f: ViewState) {
  const p = new URLSearchParams()
  if (f.play !== DEFAULT_PLAY) p.set('play', f.play)
  if (f.q) p.set('q', f.q)
  for (const k of MULTI) if (f[k].length) p.set(k, f[k].join(','))
  if (f.strong) p.set('strong', '1')
  if (f.hideListed) p.set('new', '1')
  if (f.search) p.set('search', f.search)
  if (f.onlyNew) p.set('since', '1')
  if (f.id) p.set('account', f.id)
  const qs = p.toString().replace(/%2C/g, ',')
  window.history.replaceState(null, '', qs ? `?${qs}` : window.location.pathname)
}

export const isFiltered = (f: FilterSet) => !!(f.q || MULTI.some((k) => f[k].length) || f.strong || f.hideListed)

/** The toolbar filters as API filters (the profile and list membership are added by the caller). */
export const toApi = (f: FilterSet): ApiFilters => ({
  q: f.q, country: f.country, industry: f.industry, sector: f.sector, software: f.software, size: f.size, strong: f.strong,
})
