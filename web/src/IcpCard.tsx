import { useState } from 'react'
import type { Sector } from './types'
import { PERSONAS, SIZES, icpFilters, type Icp, type Persona, type Size } from './icp'
import { PRODUCTS, SECTORS } from './plays'
import { api, useApi, useDebounced } from './api'
import { MultiSelect, type Option } from './MultiSelect'

const fmt = (n: number) => n.toLocaleString('en-US')

// "Your ideal customer profile" as one sentence in the page, not a dialog: the list below keeps
// working, so a seller who'd rather filter by hand just carries on. Each part opens a picker whose
// badges are counts from the server's count cube (each group's own choice left out), so they cost the
// same at any number of accounts.
export function IcpCard({ initial, first, onSave, onClose }: {
  initial: Icp; first: boolean; onSave: (icp: Icp) => void; onClose: () => void
}) {
  const [p, setP] = useState<Icp>({ ...initial, active: true })
  const set = (patch: Partial<Icp>) => setP((cur) => ({ ...cur, ...patch }))

  const draft = useDebounced(icpFilters(p), 120)
  const key = JSON.stringify(draft)
  const facets = useApi(`icp-facets:${key}`, (s) => api.facets(draft, ['country', 'sector', 'industry', 'size'], s)).data
  const matching = useApi(`counts:${key}`, (s) => api.counts(draft, s)).data?.market
  const total = useApi('counts:{}', (s) => api.counts({}, s)).data?.market
  const n = (dim: 'country' | 'sector' | 'industry' | 'size') => new Map(facets?.[dim] ?? [])
  const nSector = n('sector'), nSize = n('size')

  const countries: Option[] = (facets?.country ?? []).map(([c, k]) => [c, c, k])
  const industries: Option[] = (facets?.industry ?? []).filter(([i]) => i !== 'Telecom & hosting').map(([i, k]) => [i, i, k])
  const sectors: Option[] = SECTORS.map(([k, l]) => [k, l, nSector.get(k) ?? 0])
  const sizes: Option[] = SIZES.map(([k, l, hint]) => [k, `${l} (${hint})`, nSize.get(k) ?? 0])

  return (
    <section aria-labelledby="icp-title" className="mb-5 rounded-[var(--radius-card)] border border-rule-2 bg-paper-2 px-5 py-4">
      <div className="flex items-baseline justify-between gap-4">
        <h2 id="icp-title" className="text-lg text-ink">Your ideal customer profile</h2>
        <button type="button" className="text-sm text-muted underline underline-offset-4 hover:text-ink" onClick={onClose}>
          {first ? 'Skip for now' : 'Close'}
        </button>
      </div>
      <p className="text-sm text-muted">Tell Recon what you sell and who you sell to.</p>

      <p className="mt-3 max-w-[80ch] text-md leading-8 text-ink-2">
        I sell{' '}
        <MultiSelect inline single label="What you sell" placeholder="any security product" values={p.product ? [p.product] : []}
          options={PRODUCTS.map(([k, l]) => [k, l])} onChange={(v) => set({ product: v[0] ?? '' })} />
        {' '}to{' '}
        <MultiSelect inline label="Sector" placeholder="any sector" values={p.sectors} options={sectors}
          onChange={(v) => set({ sectors: v as Sector[] })} />
        {' '}organisations in{' '}
        <MultiSelect inline label="Country" placeholder="any country" values={p.countries} options={countries}
          onChange={(v) => set({ countries: v })} />
        , in{' '}
        <MultiSelect inline label="Industry" placeholder="any industry" values={p.industries} options={industries}
          onChange={(v) => set({ industries: v })} />
        , with{' '}
        <MultiSelect inline label="Estate size" placeholder="an estate of any size" values={p.sizes} options={sizes}
          onChange={(v) => set({ sizes: v as Size[] })} />
        . I usually reach the{' '}
        <MultiSelect inline label="Who you reach" placeholder="CISO" values={p.personas} options={PERSONAS.map(([k, l]) => [k, l])}
          onChange={(v) => set({ personas: v as Persona[] })} />
        .
      </p>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
        <p className="text-sm text-muted" aria-live="polite">
          <span className="measured text-ink">{matching === undefined ? '…' : fmt(matching)}</span>
          {total !== undefined && <> of {fmt(total)}</>} ranked accounts match
        </p>
        <button type="button" className="btn btn-primary" disabled={!matching} onClick={() => onSave(p)}>Personalise my search</button>
      </div>
    </section>
  )
}
