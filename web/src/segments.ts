import { useCallback, useState } from 'react'

// Segments: named saved searches (a template plus ICP filters), per browser in this demo
export type SegmentFilters = {
  play: string; q: string; country: string; industry: string; sector: string; software: string; strong: boolean
}
export type Segment = { id: string; name: string; filters: SegmentFilters; created: string }

const KEY = 'recon.segments.v1'

function read(): Segment[] {
  try {
    return JSON.parse(localStorage.getItem(KEY) ?? '[]')
  } catch {
    return []
  }
}

export function useSegments() {
  const [segments, setSegments] = useState<Segment[]>(read)
  const write = useCallback((next: Segment[]) => {
    setSegments(next)
    try {
      localStorage.setItem(KEY, JSON.stringify(next))
    } catch {
      // storage unavailable: segments last for this visit
    }
  }, [])
  const add = (name: string, filters: SegmentFilters) =>
    write([{ id: `${Date.now()}`, name: name.trim(), filters, created: new Date().toISOString() }, ...segments])
  const remove = (id: string) => write(segments.filter((s) => s.id !== id))
  return { segments, add, remove }
}
