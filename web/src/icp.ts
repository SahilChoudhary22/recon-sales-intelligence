import { useCallback, useState } from 'react'
import type { Account, Sector } from './types'

// Your ideal customer profile: what you sell, where, to whom, and who you call. Saved per browser in
// this demo; it layers on top of the ICP filters as a default, and can be switched off.
export type Size = '' | 'small' | 'mid' | 'large'
export type Persona = 'ciso' | 'it' | 'engineer'
export type Icp = {
  product: string
  countries: string[]
  sectors: Sector[]
  industries: string[]
  size: Size
  persona: Persona
  active: boolean
}

export const SIZES: [Size, string, string][] = [
  ['', 'Any size', ''],
  ['small', 'Small estate', '1 to 5 IPs'],
  ['mid', 'Mid-size estate', '6 to 50 IPs'],
  ['large', 'Large estate', 'more than 50 IPs'],
]
export const PERSONAS: [Persona, string, string][] = [
  ['ciso', 'CISO or head of security', '(CISO OR "head of security" OR "chief information security officer")'],
  ['it', 'Head of IT', '("head of IT" OR "IT director" OR "IT manager" OR CIO)'],
  ['engineer', 'Security or network engineer', '("security engineer" OR "network engineer" OR "infrastructure engineer")'],
]

const EMPTY: Icp = { product: '', countries: [], sectors: [], industries: [], size: '', persona: 'ciso', active: false }
const KEY = 'recon.icp.v1'

function read(): { icp: Icp; seen: boolean } {
  try {
    const raw = localStorage.getItem(KEY)
    return raw ? { icp: { ...EMPTY, ...JSON.parse(raw) }, seen: true } : { icp: EMPTY, seen: false }
  } catch {
    return { icp: EMPTY, seen: true } // storage blocked: don't nag on every visit
  }
}

export const icpIsEmpty = (p: Icp) => !p.countries.length && !p.sectors.length && !p.industries.length && !p.size

const sizeOk = (size: Size, ips: number) =>
  !size || (size === 'small' ? ips <= 5 : size === 'mid' ? ips > 5 && ips <= 50 : ips > 50)

export function inIcp(p: Icp, a: Account) {
  if (!p.active) return true
  return (!p.countries.length || (a.country != null && p.countries.includes(a.country))) &&
    (!p.sectors.length || p.sectors.includes(a.sector)) &&
    (!p.industries.length || (a.industry != null && p.industries.includes(a.industry))) &&
    sizeOk(p.size, a.ips)
}

// one plain sentence for the toolbar chip: "GB and IE, commercial, financial services and healthcare"
export function describeIcp(p: Icp, sectorName: (s: Sector) => string) {
  const list = (xs: string[]) => (xs.length <= 2 ? xs.join(' and ') : `${xs.slice(0, -1).join(', ')} and ${xs[xs.length - 1]}`)
  return [
    p.countries.length ? list(p.countries) : null,
    p.sectors.length ? list(p.sectors.map(sectorName)).toLowerCase() : null,
    p.industries.length ? list(p.industries).toLowerCase() : null,
    p.size ? SIZES.find(([k]) => k === p.size)?.[1].toLowerCase() : null,
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
