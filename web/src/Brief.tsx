import { useEffect, useMemo, useState } from 'react'
import type { Account, Meta, Evidence } from './types'
import { GUIDANCE } from './guidance'
import { collapse } from './evidence'
import { LogoMark } from './Logo'
import { APP_NAME } from './brand'

import { peerLine } from './peer'
import { api } from './api'

const fmt = (n: number) => n.toLocaleString('en-US')

// The exposure brief: one printable page a seller can send, built only from the scan evidence.
export function Brief({ a, meta }: { a: Account; meta: Meta }) {
  const [ev, setEv] = useState<Evidence[] | null>(null)
  useEffect(() => {
    api.evidence(a.id).then(setEv).catch(() => setEv([]))
  }, [a])
  const groups = useMemo(() => {
    const g = new Map<string, Evidence[]>()
    ev?.forEach((e) => g.set(e.s, [...(g.get(e.s) ?? []), e]))
    return [...g.entries()].sort((x, y) => (meta.signals[y[0]]?.weight ?? 0) - (meta.signals[x[0]]?.weight ?? 0))
  }, [ev, meta])
  const serious = groups.filter(([s]) => (meta.signals[s]?.weight ?? 0) >= 4)
  const minor = groups.filter(([s]) => (meta.signals[s]?.weight ?? 0) < 4)

  return (
    <div className="mx-auto max-w-[52rem] px-6 py-10 print:px-0 print:py-0">
      <div className="mb-8 flex items-center justify-between gap-4 print:hidden">
        <a href={`./?account=${encodeURIComponent(a.id)}`} className="text-sm text-muted underline underline-offset-4 hover:text-ink">Back to the account</a>
        <button type="button" className="btn btn-primary" onClick={() => window.print()}>Print or save as PDF</button>
      </div>

      <header className="flex items-start justify-between gap-6 border-b border-rule-2 pb-5">
        <div>
          <p className="text-sm text-muted">External exposure brief</p>
          <h1 className="mt-1 text-[2rem] leading-tight text-ink">{a.name}</h1>
          <p className="mt-1 text-sm text-ink-2">
            {[a.org !== a.name ? a.org : null, a.industry, a.country].filter(Boolean).join(', ')}. Based on public internet scan data from 1 November 2026.
          </p>
        </div>
        <span className="flex shrink-0 items-center gap-2 text-sm text-muted"><LogoMark className="size-6 text-ink" />{APP_NAME}</span>
      </header>

      <section className="grid gap-6 border-b border-rule py-6 sm:grid-cols-[minmax(0,1fr)_14rem]">
        <div>
          {a.peer ? (
            <>
              <p className="text-xl leading-snug text-ink">{peerLine(a)}.</p>
              <p className="mt-2 text-sm text-muted">Compared with {fmt(a.peer.n)} {a.peer.group} that this scan could identify. Rank 1 is the most exposed.</p>
            </>
          ) : (
            <p className="text-xl text-ink">Too few comparable companies in this scan for a fair benchmark.</p>
          )}
        </div>
        <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm sm:grid-cols-1">
          <div><dt className="text-muted">Internet-facing services</dt><dd className="measured text-lg text-ink">{fmt(a.assets)}</dd></div>
          <div><dt className="text-muted">IP addresses</dt><dd className="measured text-lg text-ink">{fmt(a.ips)}</dd></div>
          <div><dt className="text-muted">Serious findings</dt><dd className="measured text-lg text-ink">{fmt(serious.length)}</dd></div>
        </dl>
      </section>

      <section className="py-6">
        <h2 className="mb-4 text-lg text-ink">What anyone on the internet can see</h2>
        {!ev ? <p className="text-sm text-muted">Loading the findings…</p> : (
          <ol className="space-y-5">
            {serious.map(([sid, items], i) => (
              <li key={sid} className="break-inside-avoid">
                <h3 className="text-md font-medium text-ink"><span className="measured mr-2 text-muted">{i + 1}.</span>{meta.signals[sid]?.label}</h3>
                <p className="mt-1 text-sm text-ink-2">{GUIDANCE[sid]?.means}</p>
                <ul className="measured mt-2 space-y-0.5 text-sm text-ink-2">
                  {collapse(items).slice(0, 4).map(({ e, n }, k) => <li key={k}><span className="text-cool">{e.ip}:{e.port}</span> {e.e ?? e.p}{n > 1 && <span className="text-muted"> ({n} hosts)</span>}</li>)}
                  {collapse(items).length > 4 && <li className="text-muted">and {collapse(items).length - 4} more</li>}
                </ul>
                <p className="mt-2 text-sm text-ink"><span className="text-muted">Usual fix: </span>{GUIDANCE[sid]?.action}</p>
              </li>
            ))}
          </ol>
        )}
        {minor.length > 0 && (
          <p className="mt-6 text-sm text-ink-2">
            Also seen: {minor.map(([sid, items]) => `${meta.signals[sid]?.label} (${items.length})`).join('; ')}.
          </p>
        )}
      </section>

      <footer className="border-t border-rule pt-4 text-xs leading-relaxed text-muted">
        How this was produced: from passive, publicly available internet scan data. Nothing was probed, tested or logged into.
        Vulnerabilities are matched from the software version each service reports, so some may already be patched; this is not a penetration test.
        IP addresses are shown to the /24 network. Peer ranks compare the risk score of companies this scan could identify, in the stated group.
      </footer>
    </div>
  )
}
