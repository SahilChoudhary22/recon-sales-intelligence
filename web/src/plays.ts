import type { Account, Play, Sector } from './types'
import catalog from './catalog.json'

// The catalogue (src/catalog.json) is the single source of truth for products, sectors and signal
// templates. The MCP server (mcp_server/) reads the same file, so the app and an AI assistant
// always agree on what a template matches.

// a rule is an OR of clauses; each clause is an AND of conditions
type Clause = { signals?: string[]; kev?: boolean; tier?: string; maturity?: boolean; new?: boolean }
const matches = (a: Account, rule: Clause[]) =>
  rule.some((c) =>
    (!c.signals || c.signals.some((s) => a.signals.includes(s))) &&
    (c.kev === undefined || a.kev === c.kev) &&
    (!c.tier || a.tier === c.tier) &&
    (c.maturity === undefined || (a.maturity.length > 0) === c.maturity) &&
    (c.new === undefined || a.new === c.new))

export const SECTORS = catalog.sectors as [Sector, string][]
export const PRODUCTS = catalog.products as [string, string][]
// sector is computed once in pipeline/export.py from the industry label and the name
export const sectorOf = (a: Account): Sector => a.sector

export const MARKET: Play = { ...catalog.market, match: () => true }
export const DEFAULT_PLAY = MARKET.id

export const TEMPLATES: Play[] = catalog.templates.map((t) => ({
  ...t,
  targeting: t.targeting as Play['targeting'],
  match: (a: Account) => matches(a, t.rule as Clause[]),
}))

// the recommended targeting as a predicate, so a template's worked example sits inside it
export const inTargeting = (t: Play, a: Account) =>
  (!t.targeting?.sector || sectorOf(a) === t.targeting.sector) && (!t.targeting?.strong || !['org', 'ptr'].includes(a.ident))

export const forProduct = (t: Play, product: string) => !product || !t.forProducts || t.forProducts.includes(product)
