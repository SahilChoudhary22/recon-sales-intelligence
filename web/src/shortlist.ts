import { useCallback, useState } from 'react'

// A seller's working list. Per-browser (localStorage) in this demo; in production it would sync to the CRM.
export const STATUSES = [
  ['to_contact', 'To contact'],
  ['contacted', 'Contacted'],
  ['meeting', 'Meeting booked'],
  ['not_a_fit', 'Not a fit'],
] as const
export type Status = (typeof STATUSES)[number][0]
export type Saved = { status: Status; added: string }
export const statusLabel = (s: Status) => STATUSES.find(([k]) => k === s)?.[1] ?? s

const KEY = 'recon.list.v1'

function read(): Record<string, Saved> {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? '{}')
  } catch {
    return {}
  }
}

export function useShortlist() {
  const [list, setList] = useState<Record<string, Saved>>(read)
  const write = useCallback((next: Record<string, Saved>) => {
    setList(next)
    try {
      localStorage.setItem(KEY, JSON.stringify(next))
    } catch {
      // storage unavailable (private window): the list still works for this visit
    }
  }, [])
  const save = (id: string) => write({ ...list, [id]: { status: 'to_contact', added: new Date().toISOString() } })
  const setStatus = (id: string, status: Status) => list[id] && write({ ...list, [id]: { ...list[id], status } })
  const remove = (id: string) => {
    const next = { ...list }
    delete next[id]
    write(next)
  }
  return { list, save, setStatus, remove }
}
