import type { Play, Sector } from './types'
import catalog from './catalog.json'

// The catalogue (src/catalog.json) is the single source of truth for products, sectors and signal
// templates. Each template's rule is data; the server compiles it to SQL (api/rules.py), so the app,
// the API and the MCP server always agree on what a template matches. The app only shows the names.

export const SECTORS = catalog.sectors as [Sector, string][]
export const PRODUCTS = catalog.products as [string, string][]
export const MARKET: Play = { ...catalog.market }
export const DEFAULT_PLAY = MARKET.id

export const TEMPLATES: Play[] = catalog.templates.map((t) => ({
  ...t,
  targeting: t.targeting as Play['targeting'],
}))

export const forProduct = (t: Play, product: string) => !product || !t.forProducts || t.forProducts.includes(product)
