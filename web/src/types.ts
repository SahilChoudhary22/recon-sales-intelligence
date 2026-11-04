export type Account = {
  id: string
  name: string
  org: string | null
  country: string | null
  score: number
  tier: 'P1' | 'P2' | 'P3'
  play: string
  ips: number
  assets: number
  ident: 'cert' | 'ntlm' | 'http_host' | 'ptr' | 'same_ip' | 'org'
  signals: string[]
  kev: boolean
  eol: boolean
  maturity: string[]
  products: string[]
  need: number
  urgency: number
  fit: number
  priority: number
  industry: string | null
  shard: number
  new: boolean // a material exposure first seen in the latest scan (needs two or more scans)
  software: string[] // product families seen on its services (technographics)
}

export type SignalMeta = { label: string; category: string; weight: number }

export type Dataset = {
  generated_from: string
  funnel: Record<string, number | Record<string, number>>
  signals: Record<string, SignalMeta>
  maturity: Record<string, string>
  accounts: Account[]
}

export type Evidence = {
  s: string
  ip: string
  port: number
  p: string | null
  e: string | null
  t: string | null
  cn: string | null
}

export type Play = {
  id: string
  name: string
  blurb: string
  match: (a: Account) => boolean
}
