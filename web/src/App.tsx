import { useEffect, useMemo, useState } from 'react'
import type { Account, Dataset, Evidence } from './types'
import { PLAYS } from './plays'
import { talkTrack } from './talkTrack'

const fmt = (n: number) => n.toLocaleString('en-US')
const flag = (cc: string | null) =>
  cc && cc.length === 2 ? String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1a5 + c.charCodeAt(0))) : ''

const IDENT: Record<Account['ident'], { label: string; tone: string; hint: string }> = {
  cert: { label: 'TLS cert', tone: 'text-emerald-700 bg-emerald-50 ring-emerald-200', hint: 'Company named in its own TLS certificate' },
  ntlm: { label: 'AD domain', tone: 'text-emerald-700 bg-emerald-50 ring-emerald-200', hint: 'Windows host leaked its Active Directory domain' },
  http_host: { label: 'Web host', tone: 'text-emerald-700 bg-emerald-50 ring-emerald-200', hint: 'HTTP Host header names the company' },
  same_ip: { label: 'Same IP', tone: 'text-sky-700 bg-sky-50 ring-sky-200', hint: 'Identified from another service on the same IP' },
  org: { label: 'IP owner', tone: 'text-amber-700 bg-amber-50 ring-amber-200', hint: 'Company owns the IP block (WHOIS org)' },
  ptr: { label: 'Reverse DNS', tone: 'text-amber-700 bg-amber-50 ring-amber-200', hint: 'Reverse DNS name only: lower confidence' },
}
const TIER_TONE = { P1: 'bg-rose-600 text-white', P2: 'bg-orange-500 text-white', P3: 'bg-slate-300 text-slate-800' }
const CAT_TONE: Record<string, string> = {
  edge: 'bg-rose-50 text-rose-700 ring-rose-200',
  exposure: 'bg-orange-50 text-orange-700 ring-orange-200',
  vuln: 'bg-violet-50 text-violet-700 ring-violet-200',
  eol: 'bg-amber-50 text-amber-800 ring-amber-200',
  hygiene: 'bg-slate-100 text-slate-600 ring-slate-200',
}

export default function App() {
  const [data, setData] = useState<Dataset | null>(null)
  const [play, setPlay] = useState('all')
  const [q, setQ] = useState('')
  const [country, setCountry] = useState('')
  const [industry, setIndustry] = useState('')
  const [highConf, setHighConf] = useState(false)
  const [limit, setLimit] = useState(100)
  const [sel, setSel] = useState<Account | null>(null)

  useEffect(() => {
    fetch('./data/accounts.json').then((r) => r.json()).then(setData)
  }, [])
  useEffect(() => setLimit(100), [play, q, country, industry, highConf])

  const playCounts = useMemo(
    () => Object.fromEntries(PLAYS.map((p) => [p.id, data ? data.accounts.filter(p.match).length : 0])),
    [data],
  )
  const options = useMemo(() => {
    const c = new Map<string, number>(), i = new Map<string, number>()
    data?.accounts.forEach((a) => {
      if (a.country) c.set(a.country, (c.get(a.country) ?? 0) + 1)
      if (a.industry) i.set(a.industry, (i.get(a.industry) ?? 0) + 1)
    })
    const sort = (m: Map<string, number>) => [...m.entries()].sort((a, b) => b[1] - a[1])
    return { countries: sort(c), industries: sort(i) }
  }, [data])

  const rows = useMemo(() => {
    if (!data) return []
    const p = PLAYS.find((x) => x.id === play)!
    const needle = q.trim().toLowerCase()
    return data.accounts.filter(
      (a) =>
        p.match(a) &&
        (!country || a.country === country) &&
        (!industry || a.industry === industry) &&
        (!highConf || ['cert', 'ntlm', 'http_host', 'same_ip'].includes(a.ident)) &&
        (!needle || a.name.toLowerCase().includes(needle) || (a.org ?? '').toLowerCase().includes(needle)),
    )
  }, [data, play, q, country, industry, highConf])

  if (!data) return <div className="grid h-screen place-items-center text-slate-500">Loading accounts…</div>
  const f = data.funnel as Record<string, number>
  const activePlay = PLAYS.find((x) => x.id === play)!

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-x-8 gap-y-3 px-4 py-4 sm:px-6">
          <div className="flex items-center gap-2.5">
            <div className="grid h-8 w-8 place-items-center rounded-lg bg-slate-900 text-sm font-bold text-white">S</div>
            <div>
              <div className="font-semibold leading-tight">Surface</div>
              <div className="text-xs text-slate-500">Cybersecurity prospecting from internet scan data</div>
            </div>
          </div>
          <Funnel f={f} />
        </div>
      </header>

      <div className="mx-auto flex max-w-[1500px] flex-col gap-6 px-4 py-6 sm:px-6 lg:flex-row">
        <nav className="shrink-0 lg:w-64">
          <div className="mb-2 px-2 text-xs font-medium uppercase tracking-wide text-slate-500">Plays</div>
          <ul className="flex gap-1 overflow-x-auto lg:flex-col">
            {PLAYS.map((p) => (
              <li key={p.id}>
                <button
                  onClick={() => setPlay(p.id)}
                  className={`flex w-full items-center justify-between gap-3 whitespace-nowrap rounded-lg px-3 py-2 text-left text-sm ${
                    play === p.id ? 'bg-slate-900 text-white' : 'text-slate-700 hover:bg-slate-200/60'
                  }`}
                >
                  <span>{p.name}</span>
                  <span className={`tabular-nums text-xs ${play === p.id ? 'text-slate-300' : 'text-slate-400'}`}>
                    {fmt(playCounts[p.id])}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </nav>

        <main className="min-w-0 flex-1">
          <div className="mb-4">
            <h1 className="text-lg font-semibold">{activePlay.name}</h1>
            <p className="text-sm text-slate-500">{activePlay.blurb}</p>
          </div>
          <div className="mb-3 flex flex-wrap items-center gap-2">
            <input
              value={q}
              onChange={(e) => setQ(e.target.value)}
              placeholder="Search company or org…"
              className="h-9 w-full rounded-lg border border-slate-300 bg-white px-3 text-sm outline-none focus:border-slate-500 sm:w-64"
            />
            <Select value={country} onChange={setCountry} all="All countries"
              options={options.countries.map(([c, n]) => [c, `${flag(c)} ${c} (${n})`])} />
            <Select value={industry} onChange={setIndustry} all="All industries"
              options={options.industries.map(([c, n]) => [c, `${c} (${n})`])} />
            <label className="flex h-9 items-center gap-2 rounded-lg border border-slate-300 bg-white px-3 text-sm">
              <input type="checkbox" checked={highConf} onChange={(e) => setHighConf(e.target.checked)} />
              High-confidence identity only
            </label>
            <div className="ml-auto flex items-center gap-3 text-sm text-slate-500">
              <span className="tabular-nums">{fmt(rows.length)} accounts</span>
              <button onClick={() => exportCsv(rows, data)}
                className="h-9 rounded-lg border border-slate-300 bg-white px-3 font-medium text-slate-700 hover:bg-slate-100">
                Export CSV
              </button>
            </div>
          </div>

          <div className="overflow-x-auto rounded-xl border border-slate-200 bg-white">
            <table className="w-full min-w-[820px] text-sm">
              <thead className="border-b border-slate-200 text-left text-xs uppercase tracking-wide text-slate-500">
                <tr>
                  <th className="px-4 py-2.5 font-medium">Score</th>
                  <th className="px-4 py-2.5 font-medium">Account</th>
                  <th className="px-4 py-2.5 font-medium">Why now</th>
                  <th className="px-4 py-2.5 font-medium">Industry</th>
                  <th className="px-4 py-2.5 text-right font-medium">Footprint</th>
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, limit).map((a) => (
                  <tr key={a.id} onClick={() => setSel(a)}
                    className={`cursor-pointer border-b border-slate-100 last:border-0 hover:bg-slate-50 ${sel?.id === a.id ? 'bg-slate-50' : ''}`}>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${TIER_TONE[a.tier]}`}>{a.tier}</span>
                        <span className="tabular-nums font-semibold">{a.score.toFixed(0)}</span>
                      </div>
                    </td>
                    <td className="max-w-[280px] px-4 py-3">
                      <div className="truncate font-medium">{flag(a.country)} {a.name}</div>
                      <div className="flex items-center gap-1.5 truncate text-xs text-slate-500">
                        <span className={`rounded px-1 py-px ring-1 ring-inset ${IDENT[a.ident].tone}`}>{IDENT[a.ident].label}</span>
                        {a.org && a.org !== a.name && <span className="truncate">{a.org}</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {a.signals.slice(0, 3).map((s) => <SignalChip key={s} id={s} meta={data} />)}
                        {a.signals.length > 3 && <span className="px-1 text-xs text-slate-400">+{a.signals.length - 3}</span>}
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-600">{a.industry ?? <span className="text-slate-300">—</span>}</td>
                    <td className="px-4 py-3 text-right tabular-nums text-slate-600">
                      {fmt(a.assets)} svc · {fmt(a.ips)} IP
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length > limit && (
              <button onClick={() => setLimit(limit + 200)}
                className="w-full border-t border-slate-100 py-3 text-sm font-medium text-slate-600 hover:bg-slate-50">
                Show more ({fmt(rows.length - limit)} remaining)
              </button>
            )}
            {!rows.length && <div className="p-10 text-center text-sm text-slate-500">No accounts match these filters.</div>}
          </div>
        </main>
      </div>
      {sel && <Drawer a={sel} meta={data} onClose={() => setSel(null)} />}
    </div>
  )
}

function Funnel({ f }: { f: Record<string, number> }) {
  const steps = [
    ['Banners scanned', f.raw_records],
    ['After noise filter', f.clean],
    ['Tied to a company', f.attributed_assets],
    ['Companies with risk', f.companies_with_material_signal],
  ] as const
  return (
    <div className="flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500">
      {steps.map(([label, n], i) => (
        <div key={label} className="flex items-center gap-2">
          {i > 0 && <span className="text-slate-300">→</span>}
          <span><span className="font-semibold tabular-nums text-slate-800">{fmt(n ?? 0)}</span> {label.toLowerCase()}</span>
        </div>
      ))}
    </div>
  )
}

function Select({ value, onChange, options, all }: {
  value: string; onChange: (v: string) => void; options: [string, string][]; all: string
}) {
  return (
    <select value={value} onChange={(e) => onChange(e.target.value)}
      className="h-9 max-w-[200px] rounded-lg border border-slate-300 bg-white px-2 text-sm">
      <option value="">{all}</option>
      {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
    </select>
  )
}

function SignalChip({ id, meta }: { id: string; meta: Dataset }) {
  const m = meta.signals[id]
  return (
    <span title={m?.label} className={`whitespace-nowrap rounded-md px-1.5 py-0.5 text-xs ring-1 ring-inset ${CAT_TONE[m?.category ?? 'hygiene']}`}>
      {SHORT[id] ?? m?.label ?? id}
    </span>
  )
}

const SHORT: Record<string, string> = {
  edge_kev: 'Edge + KEV', edge_device: 'Exposed firewall/VPN', exchange_onprem: 'On-prem Exchange',
  remote_access: 'Remote access', database_exposed: 'Open database', smb_exposed: 'SMB exposed',
  open_directory: 'Open directory', mgmt_exposed: 'Mgmt interface', ot_exposed: 'OT protocol',
  iot_camera: 'Camera/DVR', kev_cve: 'KEV CVE', high_epss: 'High EPSS', critical_cve: 'Critical CVE',
  eol_os: 'EOL OS', eol_product: 'EOL software', ntlm_leak: 'AD name leak', cert_expired: 'Expired cert',
  cert_expiring: 'Cert expiring', weak_tls: 'TLS 1.0/1.1', self_signed_web: 'Self-signed',
}

function Drawer({ a, meta, onClose }: { a: Account; meta: Dataset; onClose: () => void }) {
  const [ev, setEv] = useState<Evidence[] | null>(null)
  const [copied, setCopied] = useState(false)
  useEffect(() => {
    setEv(null)
    fetch(`./data/evidence/${String(a.shard).padStart(2, '0')}.json`)
      .then((r) => r.json())
      .then((d) => setEv(d[a.id] ?? []))
  }, [a])
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [onClose])
  const track = ev ? talkTrack(a, ev, meta) : ''
  const bySignal = useMemo(() => {
    const g = new Map<string, Evidence[]>()
    ev?.forEach((e) => g.set(e.s, [...(g.get(e.s) ?? []), e]))
    return [...g.entries()].sort((x, y) => (meta.signals[y[0]]?.weight ?? 0) - (meta.signals[x[0]]?.weight ?? 0))
  }, [ev, meta])

  return (
    <div className="fixed inset-0 z-20 flex justify-end bg-slate-900/20" onClick={onClose}>
      <aside onClick={(e) => e.stopPropagation()}
        className="h-full w-full max-w-2xl overflow-y-auto bg-white shadow-2xl">
        <div className="sticky top-0 z-10 border-b border-slate-200 bg-white px-6 py-4">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <span className={`rounded px-1.5 py-0.5 text-[11px] font-semibold ${TIER_TONE[a.tier]}`}>{a.tier}</span>
                <h2 className="truncate text-lg font-semibold">{flag(a.country)} {a.name}</h2>
              </div>
              <div className="mt-0.5 text-sm text-slate-500">
                {[a.org !== a.name ? a.org : null, a.industry, a.country].filter(Boolean).join(' · ')}
              </div>
            </div>
            <button onClick={onClose} className="rounded-lg px-2 py-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700">✕</button>
          </div>
        </div>

        <div className="space-y-6 px-6 py-5">
          <section className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Stat label="Score" value={a.score.toFixed(0)} sub="percentile" />
            <Stat label="Need" value={a.need.toFixed(1)} sub="risk points" />
            <Stat label="Urgency" value={`×${a.urgency.toFixed(2)}`} sub={[a.kev && 'KEV', a.eol && 'EOL'].filter(Boolean).join(' + ') || 'none'} />
            <Stat label="Fit" value={`×${a.fit.toFixed(2)}`} sub={`${a.ips} IPs`} />
          </section>

          <section className="rounded-lg bg-slate-50 p-3 text-xs text-slate-600">
            <span className={`mr-2 rounded px-1 py-px ring-1 ring-inset ${IDENT[a.ident].tone}`}>{IDENT[a.ident].label}</span>
            {IDENT[a.ident].hint}.
          </section>

          {track && (
            <section>
              <div className="mb-2 flex items-center justify-between">
                <h3 className="text-sm font-semibold">Opening line</h3>
                <button onClick={() => { navigator.clipboard.writeText(track); setCopied(true); setTimeout(() => setCopied(false), 1500) }}
                  className="text-xs font-medium text-slate-500 hover:text-slate-900">{copied ? 'Copied' : 'Copy'}</button>
              </div>
              <p className="rounded-lg border border-slate-200 p-3 text-sm leading-relaxed text-slate-700">{track}</p>
              <p className="mt-1 text-[11px] text-slate-400">Filled in from observed scan facts only: no generated claims.</p>
            </section>
          )}

          <section>
            <h3 className="mb-2 text-sm font-semibold">Evidence</h3>
            {!ev && <div className="text-sm text-slate-400">Loading…</div>}
            <div className="space-y-3">
              {bySignal.map(([sid, items]) => (
                <div key={sid} className="rounded-lg border border-slate-200">
                  <div className="flex items-center justify-between gap-2 border-b border-slate-100 px-3 py-2">
                    <div className="flex items-center gap-2">
                      <SignalChip id={sid} meta={meta} />
                      <span className="text-sm text-slate-700">{meta.signals[sid]?.label}</span>
                    </div>
                    <span className="text-xs tabular-nums text-slate-400">{items.length} asset{items.length > 1 ? 's' : ''}</span>
                  </div>
                  <ul className="divide-y divide-slate-100 font-mono text-xs">
                    {items.slice(0, 6).map((e, i) => (
                      <li key={i} className="flex gap-3 px-3 py-1.5">
                        <span className="w-36 shrink-0 text-slate-500">{e.ip}:{e.port}</span>
                        <span className="min-w-0 break-words text-slate-700">{e.e ?? e.p}</span>
                      </li>
                    ))}
                    {items.length > 6 && <li className="px-3 py-1.5 text-slate-400">+{items.length - 6} more</li>}
                  </ul>
                </div>
              ))}
            </div>
          </section>

          {a.maturity.length > 0 && (
            <section>
              <h3 className="mb-2 text-sm font-semibold">Security maturity</h3>
              <ul className="space-y-1 text-sm text-slate-600">
                {a.maturity.map((m) => <li key={m}>✓ {meta.maturity[m]}</li>)}
              </ul>
              <p className="mt-1 text-xs text-slate-500">Already buys some security, so pitch consolidation or coverage gaps rather than a first purchase.</p>
            </section>
          )}

          {a.products.length > 0 && (
            <section>
              <h3 className="mb-2 text-sm font-semibold">Observed tech</h3>
              <div className="flex flex-wrap gap-1.5">
                {a.products.map((p) => <span key={p} className="rounded-md bg-slate-100 px-2 py-0.5 text-xs text-slate-600">{p}</span>)}
              </div>
            </section>
          )}
        </div>
      </aside>
    </div>
  )
}

function Stat({ label, value, sub }: { label: string; value: string; sub: string }) {
  return (
    <div className="rounded-lg border border-slate-200 px-3 py-2">
      <div className="text-[11px] uppercase tracking-wide text-slate-500">{label}</div>
      <div className="text-lg font-semibold tabular-nums">{value}</div>
      <div className="truncate text-[11px] text-slate-400">{sub}</div>
    </div>
  )
}

function exportCsv(rows: Account[], meta: Dataset) {
  const head = ['score', 'tier', 'company', 'org', 'country', 'industry', 'identity', 'signals', 'ips', 'services']
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = rows.map((a) =>
    [a.score, a.tier, a.name, a.org, a.country, a.industry, a.ident,
      a.signals.map((s) => meta.signals[s]?.label ?? s).join('; '), a.ips, a.assets].map(esc).join(','))
  const blob = new Blob([[head.join(','), ...lines].join('\n')], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  Object.assign(document.createElement('a'), { href: url, download: 'accounts.csv' }).click()
  URL.revokeObjectURL(url)
}
