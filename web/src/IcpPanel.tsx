import { useEffect, useMemo, useRef, useState } from 'react'
import type { Account, Sector } from './types'
import { PERSONAS, SIZES, inIcp, type Icp } from './icp'
import { PRODUCTS, SECTORS } from './plays'

const fmt = (n: number) => n.toLocaleString('en-US')

function Toggle({ on, onClick, children }: { on: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button type="button" aria-pressed={on} onClick={onClick}
      className={`min-h-8 rounded-[var(--radius-ctl)] border px-2.5 text-sm transition-colors duration-[var(--dur-micro)] ${
        on ? 'border-accent bg-accent-soft font-medium text-ink' : 'border-rule-2 bg-paper-3 text-ink-2 hover:bg-paper-2'
      }`}>
      {children}
    </button>
  )
}

const flip = <T,>(xs: T[], x: T) => (xs.includes(x) ? xs.filter((y) => y !== x) : [...xs, x])

export function IcpPanel({ initial, accounts, first, onSave, onClose }: {
  initial: Icp; accounts: Account[]; first: boolean; onSave: (icp: Icp) => void; onClose: () => void
}) {
  const [p, setP] = useState<Icp>({ ...initial, active: true })
  const set = (patch: Partial<Icp>) => setP((cur) => ({ ...cur, ...patch }))
  const card = useRef<HTMLDivElement>(null)

  const { countries, industries } = useMemo(() => {
    const c = new Map<string, number>(), i = new Map<string, number>()
    accounts.forEach((a) => {
      if (a.country) c.set(a.country, (c.get(a.country) ?? 0) + 1)
      if (a.industry && a.industry !== 'Telecom & hosting') i.set(a.industry, (i.get(a.industry) ?? 0) + 1)
    })
    const sort = (m: Map<string, number>) => [...m.entries()].sort((x, y) => y[1] - x[1]).map(([k]) => k)
    return { countries: sort(c), industries: sort(i) }
  }, [accounts])
  const shownCountries = [...new Set([...countries.slice(0, 14), ...p.countries])]
  const matching = useMemo(() => accounts.filter((a) => inIcp(p, a)).length, [accounts, p])

  useEffect(() => card.current?.focus(), [])
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopImmediatePropagation()
        onClose()
      }
    }
    window.addEventListener('keydown', k, true)
    return () => window.removeEventListener('keydown', k, true)
  }, [onClose])

  return (
    <div className="fixed inset-0 z-40 flex items-start justify-center overflow-y-auto bg-ink/30 px-4 py-8" role="dialog" aria-modal="true" aria-labelledby="icp-title">
      <div ref={card} tabIndex={-1} className="w-full max-w-[44rem] rounded-[var(--radius-card)] border border-rule-2 bg-paper outline-none">
        <div className="border-b border-rule px-6 py-5">
          <h2 id="icp-title" className="text-2xl text-ink">Your ideal customer profile</h2>
          <p className="mt-1 max-w-[60ch] text-sm text-muted">
            Tell Recon what you sell and who you sell to. It narrows the market to your accounts and puts the signal templates for your product first. You can change it or switch it off at any time.
          </p>
        </div>

        <div className="space-y-6 px-6 py-5">
          <fieldset>
            <legend className="mb-2 text-md font-medium text-ink">What do you sell?</legend>
            <div className="flex flex-wrap gap-2">
              <Toggle on={!p.product} onClick={() => set({ product: '' })}>Any security product</Toggle>
              {PRODUCTS.map(([k, l]) => <Toggle key={k} on={p.product === k} onClick={() => set({ product: k })}>{l}</Toggle>)}
            </div>
          </fieldset>

          <fieldset>
            <legend className="mb-2 text-md font-medium text-ink">Where do you sell?</legend>
            <div className="flex flex-wrap gap-2">
              {shownCountries.map((c) => <Toggle key={c} on={p.countries.includes(c)} onClick={() => set({ countries: flip(p.countries, c) })}><span className="measured">{c}</span></Toggle>)}
              <span className="relative inline-flex">
                <label className="sr-only" htmlFor="icp-more">Add another country</label>
                <select id="icp-more" value="" onChange={(e) => e.target.value && set({ countries: [...p.countries, e.target.value] })}
                  className="field min-h-8 appearance-none pl-3 pr-9">
                  <option value="">More countries</option>
                  {countries.filter((c) => !shownCountries.includes(c)).map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              </span>
            </div>
            <p className="mt-1.5 text-xs text-muted">None selected means everywhere.</p>
          </fieldset>

          <fieldset>
            <legend className="mb-2 text-md font-medium text-ink">Who do you sell to?</legend>
            <div className="flex flex-wrap gap-2">
              {SECTORS.map(([k, l]) => <Toggle key={k} on={p.sectors.includes(k)} onClick={() => set({ sectors: flip(p.sectors, k as Sector) })}>{l}</Toggle>)}
            </div>
            <p className="mb-2 mt-4 text-sm text-ink-2">Industries</p>
            <div className="flex flex-wrap gap-2">
              {industries.map((i) => <Toggle key={i} on={p.industries.includes(i)} onClick={() => set({ industries: flip(p.industries, i) })}>{i}</Toggle>)}
            </div>
            <p className="mt-1.5 text-xs text-muted">Industry is known for some accounts only, so picking industries narrows the list a lot.</p>
            <p className="mb-2 mt-4 text-sm text-ink-2">Estate size</p>
            <div className="flex flex-wrap gap-2">
              {SIZES.map(([k, l, hint]) => (
                <Toggle key={k || 'any'} on={p.size === k} onClick={() => set({ size: k })}>
                  {l}{hint && <span className="ml-1.5 text-muted">{hint}</span>}
                </Toggle>
              ))}
            </div>
          </fieldset>

          <fieldset>
            <legend className="mb-2 text-md font-medium text-ink">Who do you usually reach out to?</legend>
            <div className="flex flex-wrap gap-2">
              {PERSONAS.map(([k, l]) => <Toggle key={k} on={p.persona === k} onClick={() => set({ persona: k })}>{l}</Toggle>)}
            </div>
            <p className="mt-1.5 text-xs text-muted">Used for the contact searches on each account.</p>
          </fieldset>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-rule px-6 py-4">
          <p className="text-sm text-muted"><span className="measured text-ink">{fmt(matching)}</span> of {fmt(accounts.length)} ranked accounts match</p>
          <div className="flex gap-2">
            <button type="button" className="btn" onClick={onClose}>{first ? 'Skip for now' : 'Cancel'}</button>
            <button type="button" className="btn btn-primary" disabled={!matching} onClick={() => onSave(p)}>Save profile</button>
          </div>
        </div>
      </div>
    </div>
  )
}
