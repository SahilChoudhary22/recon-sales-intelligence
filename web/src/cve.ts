// CVE-in-the-news: the server resolves ids and nicknames (/api/cve); these are the client-side helpers
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
export const looksLikeCve = (q: string) => /cve-?\d|^\s*\d{4}-\d{4}/i.test(q)

export const nvdUrl = (id: string) => `https://nvd.nist.gov/vuln/detail/${id}`
export const kevUrl = (id: string) => `https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext=${id}`
