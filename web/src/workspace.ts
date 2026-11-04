import { useCallback, useEffect, useMemo, useState } from 'react'
import { api, type ApiFilters } from './api'
import type { FilterSet } from './filters'
import { normalise } from './filters'
import type { Icp } from './icp'

// The signed-in user's work, kept by the API (api/workspace.py): lists, the status of each listed
// account, saved searches and the profile. The app loads it once and applies each change on screen
// straight away, then saves it; if a save fails, it reloads what the server has.

export const STATUSES = [
  ['to_contact', 'To contact'],
  ['contacted', 'Contacted'],
  ['meeting', 'Meeting booked'],
  ['not_a_fit', 'Not a fit'],
] as const
export type Status = (typeof STATUSES)[number][0]
export const statusLabel = (s: Status) => STATUSES.find(([k]) => k === s)?.[1] ?? s

export type List = { id: string; name: string; created: string; n?: number }
export type Entry = { status: Status; added: string; lists: string[] }
export type Schedule = 'daily' | 'manual'
export type SavedSearch = {
  id: string; name: string; filters: FilterSet; profile: ApiFilters; created: string
  lastRun: string | null; lastRunAt: string | null; schedule: Schedule
}
type Snapshot = { lists: List[]; entries: Record<string, Entry>; searches: SavedSearch[]; profile: Icp | null }
export type WorkspaceSnapshot = Snapshot

const newId = (prefix: string) => prefix + Array.from(crypto.getRandomValues(new Uint8Array(8)), (b) => b.toString(16).padStart(2, '0')).join('')

export function useWorkspace(build: string) {
  const [snap, setSnap] = useState<Snapshot | null>(null)
  const [version, setVersion] = useState(0) // bumps when list membership changes, so searches re-run
  const [error, setError] = useState('')

  const reload = useCallback(() => {
    api.workspace().then((s) => {
      setSnap({ ...s, searches: s.searches.map((x) => ({ ...x, filters: normalise(x.filters) })) })
      setVersion((v) => v + 1)
    }).catch(() => {})
  }, [])
  useEffect(reload, [reload])

  // apply locally, then save; a failed save shows why and restores the server's state
  const save = useCallback((p: Promise<unknown>, membership = false) => {
    if (membership) setVersion((v) => v + 1)
    p.then(() => setError('')).catch((e: Error) => {
      setError(e.message.includes('409') ? 'That would go over this workspace’s limit.' : 'That change could not be saved.')
      reload()
    })
  }, [reload])
  const edit = (fn: (s: Snapshot) => Snapshot) => setSnap((s) => (s ? fn(s) : s))

  const entries = useMemo(() => snap?.entries ?? {}, [snap])
  const lists = {
    ready: !!snap, version, error,
    lists: snap?.lists ?? [],
    entries,
    listed: Object.keys(entries),
    idsIn: (listId: string) => Object.keys(entries).filter((id) => entries[id].lists.includes(listId)),
    name: (listId: string) => snap?.lists.find((l) => l.id === listId)?.name ?? 'List',
    add(ids: string[], listId: string) {
      const added = new Date().toISOString()
      edit((s) => {
        const next = { ...s.entries }
        for (const id of ids) {
          const e = next[id]
          next[id] = e ? { ...e, lists: e.lists.includes(listId) ? e.lists : [...e.lists, listId] } : { status: 'to_contact', added, lists: [listId] }
        }
        return { ...s, entries: next }
      })
      save(api.addToList(listId, { ids }), true)
    },
    /** Every result of a search (top 5,000), resolved on the server; returns how many were added. */
    async addSearch(search: ApiFilters, listId: string) {
      const r = await api.addToList(listId, { search })
      reload()
      return r.added
    },
    removeFrom(id: string, listId: string) {
      edit((s) => {
        const e = s.entries[id]
        if (!e) return s
        const next = { ...s.entries }
        const rest = e.lists.filter((l) => l !== listId)
        if (rest.length) next[id] = { ...e, lists: rest }
        else delete next[id]
        return { ...s, entries: next }
      })
      save(api.removeFromList(listId, [id]), true)
    },
    setStatus(id: string, status: Status) {
      edit((s) => (s.entries[id] ? { ...s, entries: { ...s.entries, [id]: { ...s.entries[id], status } } } : s))
      save(api.setStatus(id, status))
    },
    create(name: string) {
      const list = { id: newId('l'), name: name.trim(), created: new Date().toISOString() }
      edit((s) => ({ ...s, lists: [...s.lists, list] }))
      save(api.createList(list.id, list.name))
      return list.id
    },
    rename(listId: string, name: string) {
      edit((s) => ({ ...s, lists: s.lists.map((l) => (l.id === listId ? { ...l, name: name.trim() } : l)) }))
      save(api.renameList(listId, name))
    },
    remove(listId: string) {
      edit((s) => {
        const next: Record<string, Entry> = {}
        for (const [id, e] of Object.entries(s.entries)) {
          const rest = e.lists.filter((l) => l !== listId)
          if (rest.length) next[id] = { ...e, lists: rest }
        }
        return { ...s, lists: s.lists.filter((l) => l.id !== listId), entries: next }
      })
      save(api.deleteList(listId), true)
    },
  }

  const saved = {
    searches: snap?.searches ?? [],
    add(name: string, filters: FilterSet, profile: ApiFilters) {
      const s: SavedSearch = { id: newId('s'), name: name.trim(), filters, profile, created: new Date().toISOString(),
        lastRun: build, lastRunAt: new Date().toISOString(), schedule: 'daily' }
      edit((x) => ({ ...x, searches: [s, ...x.searches] }))
      save(api.saveSearch(s.id, s.name, filters, profile))
      return s.id
    },
    markRun(id: string) {
      edit((x) => ({ ...x, searches: x.searches.map((s) => (s.id === id ? { ...s, lastRun: build, lastRunAt: new Date().toISOString() } : s)) }))
      save(api.updateSearch(id, { reviewed: true }))
    },
    setSchedule(id: string, schedule: Schedule) {
      edit((x) => ({ ...x, searches: x.searches.map((s) => (s.id === id ? { ...s, schedule } : s)) }))
      save(api.updateSearch(id, { schedule }))
    },
    remove(id: string) {
      edit((x) => ({ ...x, searches: x.searches.filter((s) => s.id !== id) }))
      save(api.deleteSearch(id))
    },
  }

  const profile = {
    icp: snap?.profile ?? null,
    save(p: Icp) {
      edit((x) => ({ ...x, profile: p }))
      save(api.saveProfile(p))
    },
  }
  return { ready: !!snap, lists, saved, profile }
}
export type Lists = ReturnType<typeof useWorkspace>['lists']
