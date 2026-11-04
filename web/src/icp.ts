import { useCallback, useState } from 'react'
import type { Sector } from './types'

// Your ideal customer profile: what you sell, where, to whom, and who you call. Saved per browser in
// this demo. It sits under every view as a default layer (on top of the toolbar filters) and can be
// switched off. Every part takes several values, like the filters.
export type Size = 'small' | 'mid' | 'large'
export type Persona = 'ciso' | 'it' | 'engineer'
export type Icp = {
  product: string
  countries: string[]
  sectors: Sector[]
  industries: string[]
  sizes: Size[]
  personas: Persona[]
  active: boolean
}

export const SIZES: [Size, string, string][] = [
  ['small', 'Small estate', '1 to 5 IPs'],
  ['mid', 'Mid-size estate', '6 to 50 IPs'],
  ['large', 'Large estate', 'more than 50 IPs'],
]
export const PERSONAS: [Persona, string, string][] = [
  ['ciso', 'CISO or head of security', 'CISO OR "head of security" OR "chief information security officer"'],
  ['it', 'Head of IT', '"head of IT" OR "IT director" OR "IT manager" OR CIO'],
  ['engineer', 'Security or network engineer', '"security engineer" OR "network engineer" OR "infrastructure engineer"'],
]

const EMPTY: Icp = { product: '', countries: [], sectors: [], industries: [], sizes: [], personas: ['ciso'], active: false }
const KEY = 'recon.icp.v1'

function read(): { icp: Icp; seen: boolean } {
  try {
    const raw = localStorage.getItem(KEY)
    if (!raw) return { icp: EMPTY, seen: false }
    return { icp: { ...EMPTY, ...JSON.parse(raw) }, seen: true }
  } catch {
    return { icp: EMPTY, seen: true } // storage blocked: don't ask on every visit
  }
}

export const icpIsEmpty = (p: Icp) => !p.countries.length && !p.sectors.length && !p.industries.length && !p.sizes.length

/** The profile as API filters (an inactive profile filters nothing). */
export function icpFilters(p: Icp) {
  if (!p.active) return {}
  return { icp_country: p.countries, icp_sector: p.sectors, icp_industry: p.industries, icp_size: p.sizes }
}

/** The LinkedIn role search for the personas you picked, ORed. */
export function personaRoles(ps: Persona[]) {
  const chosen = PERSONAS.filter(([k]) => ps.includes(k))
  const use = chosen.length ? chosen : [PERSONAS[0]]
  return { who: use.map(([, l]) => l).join(', '), roles: `(${use.map(([, , r]) => r).join(' OR ')})` }
}

// one plain sentence for the toolbar chip: "GB or IE, commercial, financial services"
export function describeIcp(p: Icp, sectorName: (s: Sector) => string) {
  const list = (xs: string[]) => (xs.length <= 2 ? xs.join(' or ') : `${xs.slice(0, -1).join(', ')} or ${xs[xs.length - 1]}`)
  return [
    p.countries.length ? list(p.countries) : null,
    p.sectors.length ? list(p.sectors.map(sectorName)).toLowerCase() : null,
    p.industries.length ? list(p.industries).toLowerCase() : null,
    p.sizes.length ? list(p.sizes.map((s) => SIZES.find(([k]) => k === s)?.[1] ?? s)).toLowerCase() : null,
  ].filter(Boolean).join(', ')
}

export function useIcp() {
  const [{ icp, seen }, setState] = useState(read)
  const save = useCallback((next: Icp) => {
    setState({ icp: next, seen: true })
    try {
      localStorage.setItem(KEY, JSON.stringify(next))
    } catch {
      // storage unavailable: the profile lasts for this visit
    }
  }, [])
  return { icp, seen, save }
}
