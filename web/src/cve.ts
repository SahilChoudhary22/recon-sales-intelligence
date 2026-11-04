// CVE-in-the-news: recognise CVE ids or well-known nicknames in the search box, and load the index
export type CveFacts = {
  inScan: boolean
  companies: number
  inApp?: number
  kev: boolean
  kevAdded?: string
  ransomware?: boolean
  vendor?: string
  product?: string
  title?: string
  cvss?: number | null
  epss?: number | null
  noise: boolean
  family?: string | null
  seenProduct?: string | null
}
export type CveIndex = {
  scanDate: string
  kev: { version?: string; released?: string }
  cves: Record<string, CveFacts>
  nicknames: Record<string, string[]>
}
// per CVE file: accounts in the app as [id, services, product, new, examples]; the rest summarised
export type CveCompanies = {
  in: [string, number, string | null, number, string[]][]
  out: [string, string | null, number, number, string | null][]
  outTotal: number
}

const FULL = /\bcve-(\d{4})-(\d{4,7})\b/gi
const BARE = /^\s*(\d{4})-(\d{4,7})\s*$/

// returns the CVE ids a query asks for (empty = not a CVE search)
export function parseCves(q: string, index: CveIndex | null): string[] {
  const ids = new Set<string>()
  for (const m of q.matchAll(FULL)) ids.add(`CVE-${m[1]}-${m[2]}`)
  const bare = q.match(BARE)
  if (bare) ids.add(`CVE-${bare[1]}-${bare[2]}`)
  if (!ids.size && index) {
    const needle = q.trim().toLowerCase()
    // longest nickname first, so "citrix bleed 2" wins over "citrix bleed"
    const hit = Object.keys(index.nicknames).sort((a, b) => b.length - a.length).find((n) => needle === n)
    if (hit) index.nicknames[hit].forEach((id) => ids.add(id))
  }
  return [...ids]
}

export const looksLikeCve = (q: string) => /cve-?\d|^\s*\d{4}-\d{4}/i.test(q)

export const nvdUrl = (id: string) => `https://nvd.nist.gov/vuln/detail/${id}`
export const kevUrl = (id: string) => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}`
