import { useCallback, useState } from 'react'
import { normalise, type FilterSet } from './filters'
import type { ApiFilters } from './api'

// Saved searches: a view plus filters (and the profile it was made with), kept so it can be run again.
// Each run remembers the data build it saw. Running it later shows what is new since then, and which
// of those aren't in any list yet: every account carries the build it was first ranked in, so "new
// since you last ran it" is one server-side filter (first_ranked > last run), with no copy of old
// results kept here.
// Per browser in this demo; in production a scheduler re-runs every saved search when a build lands
// (or daily) and notifies the owner, from the same API.
export type Schedule = 'daily' | 'manual'
export type SavedSearch = {
  id: string; name: string; filters: FilterSet; profile: ApiFilters; created: string
  lastRun: string | null // build id seen on the last run
  lastRunAt: string | null
  schedule: Schedule
}

const KEY = 'recon.searches.v1'

function read(): SavedSearch[] {
  try {
    const raw = localStorage.getItem(KEY)
    if (raw) return JSON.parse(raw)
    // segments saved before become saved searches
    const old = JSON.parse(localStorage.getItem('recon.segments.v1') ?? '[]') as { id: string; name: string; filters: Record<string, unknown>; created: string }[]
    return old.map((s) => ({ id: s.id, name: s.name, filters: normalise(s.filters), profile: {}, created: s.created, lastRun: null, lastRunAt: null, schedule: 'daily' }))
  } catch {
    return []
  }
}

export function useSearches() {
  const [searches, setSearches] = useState<SavedSearch[]>(read)
  const update = useCallback((fn: (s: SavedSearch[]) => SavedSearch[]) => {
    setSearches((cur) => {
      const next = fn(cur)
      try {
        localStorage.setItem(KEY, JSON.stringify(next))
      } catch {
        // storage unavailable: saved searches last for this visit
      }
      return next
    })
  }, [])
  const add = (name: string, filters: FilterSet, profile: ApiFilters, build: string) => {
    const s: SavedSearch = { id: `s${Date.now().toString(36)}`, name: name.trim(), filters, profile, created: new Date().toISOString(),
      lastRun: build, lastRunAt: new Date().toISOString(), schedule: 'daily' }
    update((all) => [s, ...all])
    return s.id
  }
  const markRun = (id: string, build: string) =>
    update((all) => all.map((s) => (s.id === id ? { ...s, lastRun: build, lastRunAt: new Date().toISOString() } : s)))
  const setSchedule = (id: string, schedule: Schedule) => update((all) => all.map((s) => (s.id === id ? { ...s, schedule } : s)))
  const remove = (id: string) => update((all) => all.filter((s) => s.id !== id))
  return { searches, add, markRun, setSchedule, remove }
}
