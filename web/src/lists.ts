import { useCallback, useState } from 'react'

// Lists: named sets of accounts a seller works through, like "Q4 UK banks". An account can sit in
// several lists and carries one status (to contact, contacted, meeting booked, not a fit).
// Per browser in this demo; in production these are rows in the app database (lists, list_items),
// shared with the team and synced to the CRM.
export const STATUSES = [
  ['to_contact', 'To contact'],
  ['contacted', 'Contacted'],
  ['meeting', 'Meeting booked'],
  ['not_a_fit', 'Not a fit'],
] as const
export type Status = (typeof STATUSES)[number][0]
export type List = { id: string; name: string; created: string }
export type Entry = { status: Status; added: string; lists: string[] }
type State = { lists: List[]; entries: Record<string, Entry> }

export const statusLabel = (s: Status) => STATUSES.find(([k]) => k === s)?.[1] ?? s
const KEY = 'recon.lists.v1'
const DEFAULT: List = { id: 'mine', name: 'My list', created: '2026-11-01T00:00:00.000Z' }

function read(): State {
  try {
    const raw = localStorage.getItem(KEY)
    return raw ? JSON.parse(raw) : { lists: [DEFAULT], entries: {} }
  } catch {
    return { lists: [DEFAULT], entries: {} }
  }
}

export function useLists() {
  const [state, setState] = useState<State>(read)
  const update = useCallback((fn: (s: State) => State) => {
    setState((cur) => {
      const next = fn(cur)
      try {
        localStorage.setItem(KEY, JSON.stringify(next))
      } catch {
        // storage unavailable (private window): lists last for this visit
      }
      return next
    })
  }, [])

  // stable, so it can run from an effect (the ?import= link)
  const add = useCallback((ids: string[], listId: string) => update((s) => {
    const added = new Date().toISOString()
    const entries = { ...s.entries }
    for (const id of ids) {
      const e = entries[id]
      entries[id] = e ? { ...e, lists: e.lists.includes(listId) ? e.lists : [...e.lists, listId] } : { status: 'to_contact', added, lists: [listId] }
    }
    return { ...s, entries }
  }), [update])
  const removeFrom = (id: string, listId: string) => update((s) => {
    const e = s.entries[id]
    if (!e) return s
    const entries = { ...s.entries }
    const rest = e.lists.filter((l) => l !== listId)
    if (rest.length) entries[id] = { ...e, lists: rest }
    else delete entries[id]
    return { ...s, entries }
  })
  const setStatus = (id: string, status: Status) =>
    update((s) => (s.entries[id] ? { ...s, entries: { ...s.entries, [id]: { ...s.entries[id], status } } } : s))
  const create = (name: string) => {
    const list = { id: `l${Date.now().toString(36)}`, name: name.trim(), created: new Date().toISOString() }
    update((s) => ({ ...s, lists: [...s.lists, list] }))
    return list.id
  }
  const rename = (id: string, name: string) => update((s) => ({ ...s, lists: s.lists.map((l) => (l.id === id ? { ...l, name: name.trim() } : l)) }))
  const remove = (listId: string) => update((s) => {
    const entries: Record<string, Entry> = {}
    for (const [id, e] of Object.entries(s.entries)) {
      const rest = e.lists.filter((l) => l !== listId)
      if (rest.length) entries[id] = { ...e, lists: rest }
    }
    const lists = s.lists.filter((l) => l.id !== listId)
    return { lists: lists.length ? lists : [DEFAULT], entries }
  })

  const idsIn = (listId: string) => Object.keys(state.entries).filter((id) => state.entries[id].lists.includes(listId)).sort()
  const listed = Object.keys(state.entries).sort() // in any list
  const name = (listId: string) => state.lists.find((l) => l.id === listId)?.name ?? 'List'
  return { lists: state.lists, entries: state.entries, listed, idsIn, name, add, removeFrom, setStatus, create, rename, remove }
}
export type Lists = ReturnType<typeof useLists>
