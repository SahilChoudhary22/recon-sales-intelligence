import type { Evidence } from './types'

// IPs are masked to /24, so two hosts in one block can read as the same line ("203.0.113.x:443 BigIP").
// Show each line once, with how many hosts it stands for.
export function collapse(items: Evidence[]): { e: Evidence; n: number }[] {
  const seen = new Map<string, { e: Evidence; n: number }>()
  for (const e of items) {
    const k = `${e.ip}:${e.port} ${e.e ?? e.p ?? ''}`
    const hit = seen.get(k)
    if (hit) hit.n += 1
    else seen.set(k, { e, n: 1 })
  }
  return [...seen.values()]
}
