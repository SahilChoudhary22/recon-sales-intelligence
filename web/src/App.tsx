import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { Account, Dataset, Evidence, Play } from './types'
import { PLAYS } from './plays'
import { talkTrack } from './talkTrack'
import { APP_NAME, PRODUCT_LINE } from './brand'
import { STATUSES, statusLabel, useShortlist, type Saved, type Status } from './shortlist'
import { Tour } from './Tour'
import { guideSeen } from './tourSteps'

const fmt = (n: number) => n.toLocaleString('en-US')
const CRITICAL_WEIGHT = 8

const IDENT: Record<Account['ident'], { label: string; strong: boolean; hint: string }> = {
  cert: { label: 'TLS certificate', strong: true, hint: 'The company named itself in its own TLS certificate.' },
  ntlm: { label: 'Windows domain', strong: true, hint: 'A Windows server leaked its Active Directory domain.' },
  http_host: { label: 'Web host', strong: true, hint: 'The web server answered for this company’s hostname.' },
  same_ip: { label: 'Same IP', strong: true, hint: 'Named by another service running on the same IP address.' },
  org: { label: 'IP owner', strong: false, hint: 'The organisation registered as owner of the IP block (WHOIS).' },
  ptr: { label: 'Reverse DNS', strong: false, hint: 'Only a reverse-DNS name points here, the weakest evidence.' },
}

const SHORT: Record<string, string> = {
  edge_kev: 'Edge device + KEV', edge_device: 'Exposed firewall/VPN', exchange_onprem: 'On-prem Exchange',
  remote_access: 'Remote access open', database_exposed: 'Open database', smb_exposed: 'SMB exposed',
  open_directory: 'Open directory', mgmt_exposed: 'Management interface', ot_exposed: 'OT protocol',
  iot_camera: 'Camera or DVR', kev_cve: 'Known-exploited CVE', high_epss: 'Likely-exploited CVE',
  critical_cve: 'Critical CVE', eol_os: 'End-of-life OS', eol_product: 'End-of-life software',
  ntlm_leak: 'Leaks AD domain', cert_expired: 'Expired certificate', cert_expiring: 'Certificate expiring',
  weak_tls: 'TLS 1.0/1.1', self_signed_web: 'Self-signed certificate',
}

type Filters = { play: string; q: string; country: string; industry: string; strong: boolean; id: string | null }

function readUrl(): Filters {
  const p = new URLSearchParams(window.location.search)
  return {
    play: p.get('play') ?? 'all', q: p.get('q') ?? '', country: p.get('country') ?? '',
    industry: p.get('industry') ?? '', strong: p.get('strong') === '1', id: p.get('account'),
  }
}

function writeUrl(f: Filters) {
  const p = new URLSearchParams()
  if (f.play !== 'all') p.set('play', f.play)
  if (f.q) p.set('q', f.q)
  if (f.country) p.set('country', f.country)
  if (f.industry) p.set('industry', f.industry)
  if (f.strong) p.set('strong', '1')
  if (f.id) p.set('account', f.id)
  const qs = p.toString()
  window.history.replaceState(null, '', qs ? `?${qs}` : window.location.pathname)
}

export default function App() {
  const [data, setData] = useState<Dataset | null>(null)
  const [failed, setFailed] = useState(false)
  const [f, setF] = useState<Filters>(readUrl)
  const [limit, setLimit] = useState(100)
  const [guide, setGuide] = useState(() => !guideSeen())
  const shortlist = useShortlist()
  const set = (patch: Partial<Filters>) => {
    setF((cur) => ({ ...cur, ...patch }))
    if (!('id' in patch)) setLimit(100) // a new filter starts the list from the top
  }

  const load = useCallback(() => {
    fetch('./data/accounts.json')
      .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
      .then(setData)
      .catch(() => setFailed(true))
  }, [])
  useEffect(load, [load])
  useEffect(() => writeUrl(f), [f])

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

  const myList: Play = {
    id: 'list', name: 'My list',
    blurb: 'Accounts you saved from the account panel, with where each one stands. Export it for your CRM.',
    match: (a) => !!shortlist.list[a.id],
  }
  const play = f.play === 'list' ? myList : PLAYS.find((x) => x.id === f.play) ?? PLAYS[0]
  const rows = useMemo(() => {
    if (!data) return []
    const needle = f.q.trim().toLowerCase()
    return data.accounts.filter(
      (a) =>
        play.match(a) &&
        (!f.country || a.country === f.country) &&
        (!f.industry || a.industry === f.industry) &&
        (!f.strong || IDENT[a.ident].strong) &&
        (!needle || a.name.toLowerCase().includes(needle) || (a.org ?? '').toLowerCase().includes(needle)),
    )
  }, [data, play, f.q, f.country, f.industry, f.strong])
  const selected = useMemo(() => data?.accounts.find((a) => a.id === f.id) ?? null, [data, f.id])
  const filtered = f.q || f.country || f.industry || f.strong
  const nSaved = Object.keys(shortlist.list).length

  const navButton = (p: Play, count: number) => {
    const on = p.id === play.id
    return (
      <button type="button" aria-current={on ? 'page' : undefined} onClick={() => set({ play: p.id })}
        className={`flex w-full min-h-9 items-center justify-between gap-3 rounded-[var(--radius-ctl)] px-2.5 text-left text-sm transition-colors duration-[var(--dur-micro)] ${
          on ? 'bg-accent-soft font-medium text-ink' : 'text-ink-2 hover:bg-paper-2'
        }`}>
        <span className="whitespace-nowrap lg:whitespace-normal">{p.name}</span>
        <span className="measured text-xs text-muted">{data ? fmt(count) : ''}</span>
      </button>
    )
  }

  return (
    <div className="min-h-screen">
      <Header data={data} onGuide={() => setGuide(true)} />
      <div className="mx-auto max-w-[112rem] lg:grid lg:grid-cols-[16rem_minmax(0,1fr)] 2xl:grid-cols-[16rem_minmax(0,1fr)_minmax(0,34rem)]">
        <nav aria-label="Views" className="flex gap-4 overflow-x-auto border-b border-rule px-4 py-3 lg:block lg:overflow-visible lg:border-b-0 lg:border-r lg:px-3 lg:py-5">
          <div data-tour="mylist" className="shrink-0 lg:mb-5">
            <h2 className="mb-2 hidden px-2 text-sm text-muted lg:block">Your work</h2>
            {navButton(myList, nSaved)}
          </div>
          <div data-tour="plays" className="min-w-0">
            <h2 className="mb-2 hidden px-2 text-sm text-muted lg:block">Plays</h2>
            <ul className="flex gap-1 lg:flex-col">
              {PLAYS.map((p) => <li key={p.id} className="shrink-0">{navButton(p, playCounts[p.id])}</li>)}
            </ul>
          </div>
        </nav>

        <main className="min-w-0 px-4 py-5 sm:px-6">
          <div className="mb-4 max-w-[70ch]">
            <h1 className="text-xl text-ink">{play.name}</h1>
            <p className="mt-1 text-sm text-muted">{play.blurb}</p>
          </div>

          <div data-tour="filters" className="mb-4 flex flex-wrap items-center gap-2">
            <label className="sr-only" htmlFor="q">Search accounts</label>
            <input id="q" type="search" name="q" autoComplete="off" value={f.q} onChange={(e) => set({ q: e.target.value })}
              placeholder="Search a company or organisation" className="field w-full sm:w-72" />
            <Select id="country" label="Country" value={f.country} onChange={(v) => set({ country: v })} all="All countries"
              options={options.countries.map(([c, n]) => [c, `${c} (${fmt(n)})`])} />
            <Select id="industry" label="Industry" value={f.industry} onChange={(v) => set({ industry: v })} all="All industries"
              options={options.industries.map(([c, n]) => [c, `${c} (${fmt(n)})`])} />
            <label className="flex min-h-9 items-center gap-2 px-1 text-sm text-ink-2">
              <input type="checkbox" checked={f.strong} onChange={(e) => set({ strong: e.target.checked })} className="size-4 accent-[var(--color-accent)]" />
              Strong identity only
            </label>
            <div className="ml-auto flex items-center gap-3">
              <span className="text-sm text-muted"><span className="measured text-ink">{fmt(rows.length)}</span> {rows.length === 1 ? 'account' : 'accounts'}</span>
              <button type="button" className="btn" disabled={!rows.length} onClick={() => data && exportCsv(rows, data, shortlist.list)}>Export CSV</button>
            </div>
          </div>

          <div data-tour="table">
            {failed ? (
              <State title="The account list did not load." body="The data file could not be fetched. Check the connection and try again.">
                <button type="button" className="btn" onClick={() => { setFailed(false); load() }}>Try again</button>
              </State>
            ) : !data ? (
              <SkeletonRows />
            ) : !rows.length && play.id === 'list' && !filtered ? (
              <State title="Your list is empty." body="Open any account and choose Add to my list. Saved accounts collect here with their status, ready to export." >
                <button type="button" className="btn" onClick={() => set({ play: 'p1' })}>Browse the P1 accounts</button>
              </State>
            ) : !rows.length ? (
              <State title="No accounts match these filters." body={`The ${play.name.toLowerCase()} view has ${fmt(play.id === 'list' ? nSaved : playCounts[play.id])} accounts before filtering.`}>
                {filtered && <button type="button" className="btn" onClick={() => set({ q: '', country: '', industry: '', strong: false })}>Clear filters</button>}
              </State>
            ) : (
              <>
                <AccountTable rows={rows.slice(0, limit)} meta={data} saved={shortlist.list} selectedId={f.id} onSelect={(id) => set({ id })} />
                <AccountList rows={rows.slice(0, limit)} meta={data} saved={shortlist.list} onSelect={(id) => set({ id })} />
                {rows.length > limit && (
                  <button type="button" className="btn mt-4" onClick={() => setLimit(limit + 200)}>
                    Show 200 more <span className="measured text-muted">({fmt(rows.length - limit)} left)</span>
                  </button>
                )}
              </>
            )}
          </div>
        </main>

        <Detail key={selected?.id ?? 'none'} account={selected} meta={data} shortlist={shortlist} onClose={() => set({ id: null })} />
      </div>
      {guide && data && <Tour onClose={() => setGuide(false)} />}
    </div>
  )
}

const compact = new Intl.NumberFormat('en-US', { notation: 'compact', maximumSignificantDigits: 3 })
const pct = (part?: number, whole?: number) => (part && whole ? `${(100 * part / whole).toFixed(part / whole < 0.1 ? 1 : 0)}%` : '')

function Header({ data, onGuide }: { data: Dataset | null; onGuide: () => void }) {
  const f = data?.funnel as Record<string, number> | undefined
  const steps: { label: string; n?: number; note: string }[] = [
    { label: 'Banners scanned', n: f?.raw_records, note: 'One day of internet scan data, 1 Nov 2026' },
    { label: 'Real services', n: f?.clean, note: `${pct(f?.clean, f?.raw_records)} kept after removing CDN edges, honeypots and phantom hosts` },
    { label: 'Tied to a company', n: f?.attributed_assets, note: f ? `${pct(f.attributed_assets, f.clean)} of real services, across ${compact.format(f.companies)} companies` : '' },
    { label: 'Companies with real risk', n: f?.companies_with_material_signal, note: data ? `The top ${fmt(data.accounts.length)} are ranked here` : '' },
  ]
  return (
    <header className="border-b border-rule bg-paper-2" data-tour="funnel">
      <div className="mx-auto max-w-[112rem] px-4 pt-4 pb-5 sm:px-6">
        <div className="mb-4 flex items-center justify-between gap-4">
          <p className="flex items-baseline gap-2.5">
            <span className="text-xl font-medium leading-none text-ink">{APP_NAME}</span>
            <span className="text-sm text-muted">{PRODUCT_LINE}</span>
          </p>
          <button type="button" className="btn" onClick={onGuide}>How it works</button>
        </div>
        <dl className="grid grid-cols-2 gap-px overflow-hidden rounded-[var(--radius-card)] border border-rule bg-rule lg:grid-cols-4">
          {steps.map((s) => (
            <div key={s.label} className="bg-paper-3 px-4 py-3">
              <dt className="text-sm text-muted">{s.label}</dt>
              <dd className="measured mt-1 text-[1.75rem] leading-none tracking-[-0.03em] text-ink" title={s.n === undefined ? undefined : fmt(s.n)}>
                {s.n === undefined ? <span className="skeleton inline-block h-7 w-20 align-middle" /> : (
                  <><span aria-hidden>{compact.format(s.n)}</span><span className="sr-only">{fmt(s.n)}</span></>
                )}
              </dd>
              <dd className="mt-1.5 text-xs leading-snug text-muted">{s.note}</dd>
            </div>
          ))}
        </dl>
      </div>
    </header>
  )
}

function Select({ id, label, value, onChange, options, all }: {
  id: string; label: string; value: string; onChange: (v: string) => void; options: [string, string][]; all: string
}) {
  return (
    <span className="relative inline-flex">
      <label className="sr-only" htmlFor={id}>{label}</label>
      <select id={id} name={id} value={value} onChange={(e) => onChange(e.target.value)}
        className="field max-w-[14rem] appearance-none pl-3 pr-9">
        <option value="">{all}</option>
        {options.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
      </select>
      <svg aria-hidden viewBox="0 0 16 16" className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-muted">
        <path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
    </span>
  )
}

function SignalChip({ id, meta }: { id: string; meta: Dataset }) {
  const m = meta.signals[id]
  return <span title={m?.label} className="chip">{SHORT[id] ?? m?.label ?? id}</span>
}

function Tier({ tier }: { tier: Account['tier'] }) {
  if (tier === 'P1') return <span className="chip chip-act">P1</span>
  if (tier === 'P2') return <span className="chip">P2</span>
  return <span className="chip border-transparent text-muted">P3</span>
}

function AccountTable({ rows, meta, saved, selectedId, onSelect }: {
  rows: Account[]; meta: Dataset; saved: Record<string, Saved>; selectedId: string | null; onSelect: (id: string) => void
}) {
  return (
    <div className="hidden overflow-x-auto md:block">
    <table className="w-full min-w-[46rem] border-collapse text-md">
      <thead>
        <tr className="border-b border-rule-2 text-left text-sm text-muted">
          <th scope="col" className="whitespace-nowrap py-2 pr-4 font-medium">Priority</th>
          <th scope="col" className="py-2 pr-4 font-medium">Account</th>
          <th scope="col" className="py-2 pr-4 font-medium">Why now</th>
          <th scope="col" className="hidden py-2 pr-4 font-medium 2xl:table-cell">Industry</th>
          <th scope="col" className="py-2 pr-4 font-medium">Country</th>
          <th scope="col" className="whitespace-nowrap py-2 pr-4 text-right font-medium">Services</th>
          <th scope="col" className="py-2 text-right font-medium">IPs</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((a) => {
          const on = a.id === selectedId
          return (
            <tr key={a.id} onClick={() => onSelect(a.id)}
              className={`cursor-pointer border-b border-rule align-top transition-colors duration-[var(--dur-micro)] ${on ? 'bg-accent-soft' : 'hover:bg-paper-2'}`}>
              <td className="py-3 pr-4">
                <div className="flex items-center gap-2"><Tier tier={a.tier} /><span className="measured text-sm text-ink">{a.score.toFixed(0)}</span></div>
              </td>
              <td className="max-w-[22rem] py-3 pr-4">
                <button type="button" onClick={(e) => { e.stopPropagation(); onSelect(a.id) }}
                  className="block max-w-full truncate text-left font-medium text-ink hover:underline">
                  {a.name}
                </button>
                <div className="mt-0.5 truncate text-sm text-muted">
                  {IDENT[a.ident].label}{a.org && a.org !== a.name ? <>, {a.org}</> : null}
                </div>
                {saved[a.id] && <span className="chip chip-act mt-1.5">{statusLabel(saved[a.id].status)}</span>}
              </td>
              <td className="py-3 pr-4">
                <div className="flex flex-wrap gap-1">
                  {a.signals.slice(0, 3).map((s) => <SignalChip key={s} id={s} meta={meta} />)}
                  {a.signals.length > 3 && <span className="px-1 text-xs leading-6 text-muted">{a.signals.length - 3} more</span>}
                </div>
              </td>
              <td className="hidden py-3 pr-4 text-sm text-ink-2 2xl:table-cell">{a.industry ?? <span className="text-muted">Not known</span>}</td>
              <td className="measured py-3 pr-4 text-sm text-ink-2">{a.country ?? ''}</td>
              <td className="measured py-3 pr-4 text-right text-sm text-ink-2">{fmt(a.assets)}</td>
              <td className="measured py-3 text-right text-sm text-ink-2">{fmt(a.ips)}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
    </div>
  )
}

function AccountList({ rows, meta, saved, onSelect }: { rows: Account[]; meta: Dataset; saved: Record<string, Saved>; onSelect: (id: string) => void }) {
  return (
    <ul className="divide-y divide-rule border-y border-rule md:hidden">
      {rows.map((a) => (
        <li key={a.id}>
          <button type="button" onClick={() => onSelect(a.id)} className="block w-full py-3 text-left">
            <div className="flex items-center gap-2">
              <Tier tier={a.tier} />
              <span className="measured text-sm">{a.score.toFixed(0)}</span>
              <span className="min-w-0 truncate font-medium">{a.name}</span>
            </div>
            {saved[a.id] && <span className="chip chip-act mt-1.5">{statusLabel(saved[a.id].status)}</span>}
            <div className="mt-2 flex flex-wrap gap-1">{a.signals.slice(0, 3).map((s) => <SignalChip key={s} id={s} meta={meta} />)}</div>
            <div className="mt-2 text-sm text-muted">
              <span className="measured">{a.country}</span>, <span className="measured">{fmt(a.assets)}</span> services on <span className="measured">{fmt(a.ips)}</span> IPs
            </div>
          </button>
        </li>
      ))}
    </ul>
  )
}

function SkeletonRows() {
  return (
    <div aria-busy="true" aria-label="Loading accounts" className="border-t border-rule-2">
      {Array.from({ length: 9 }, (_, i) => (
        <div key={i} className="flex items-center gap-6 border-b border-rule py-4">
          <div className="skeleton h-5 w-16" />
          <div className="flex-1 space-y-2"><div className="skeleton h-4 w-56 max-w-full" /><div className="skeleton h-3 w-40 max-w-full" /></div>
          <div className="skeleton hidden h-5 w-64 md:block" />
        </div>
      ))}
    </div>
  )
}

function State({ title, body, children }: { title: string; body: string; children?: React.ReactNode }) {
  return (
    <div className="border-y border-rule py-12">
      <p className="font-medium text-ink">{title}</p>
      <p className="mt-1 max-w-[60ch] text-sm text-muted">{body}</p>
      {children && <div className="mt-4">{children}</div>}
    </div>
  )
}

function Detail({ account: a, meta, shortlist, onClose }: {
  account: Account | null; meta: Dataset | null; shortlist: ReturnType<typeof useShortlist>; onClose: () => void
}) {
  const [ev, setEv] = useState<Evidence[] | null>(null)
  const [evFailed, setEvFailed] = useState(false)
  const [copied, setCopied] = useState(false)
  const heading = useRef<HTMLHeadingElement>(null)

  useEffect(() => {
    if (!a) return
    fetch(`./data/evidence/${String(a.shard).padStart(2, '0')}.json`)
      .then((r) => (r.ok ? r.json() : Promise.reject(r.status)))
      .then((d) => setEv(d[a.id] ?? []))
      .catch(() => setEvFailed(true))
    heading.current?.focus({ preventScroll: true })
  }, [a])
  useEffect(() => {
    const k = (e: KeyboardEvent) => e.key === 'Escape' && onClose()
    window.addEventListener('keydown', k)
    return () => window.removeEventListener('keydown', k)
  }, [onClose])

  const groups = useMemo(() => {
    const g = new Map<string, Evidence[]>()
    ev?.forEach((e) => g.set(e.s, [...(g.get(e.s) ?? []), e]))
    return [...g.entries()].sort((x, y) => (meta?.signals[y[0]]?.weight ?? 0) - (meta?.signals[x[0]]?.weight ?? 0))
  }, [ev, meta])

  if (!a || !meta) {
    return (
      <aside aria-label="Account detail" className="hidden border-l border-rule px-6 py-6 2xl:block">
        <p className="font-medium text-ink">Pick an account</p>
        <p className="mt-1 max-w-[42ch] text-sm text-muted">
          Its evidence opens here: what is exposed, on which IP and port, and an opening line built only from what the scan saw.
        </p>
      </aside>
    )
  }

  const track = ev ? talkTrack(a, ev, meta) : ''
  const facts: [string, React.ReactNode][] = [
    ['Organisation', a.org && a.org !== a.name ? a.org : 'Same as above'],
    ['Industry', a.industry ?? 'Not known'],
    ['Country', <span key="cc" className="measured">{a.country}</span>],
    ['Footprint', <span key="fp"><span className="measured">{fmt(a.assets)}</span> services on <span className="measured">{fmt(a.ips)}</span> IPs</span>],
  ]

  return (
    <>
      <div className="fixed inset-0 z-20 bg-ink/25 2xl:hidden" onClick={onClose} aria-hidden />
      <aside aria-label={`${a.name} detail`}
        className="fixed inset-y-0 right-0 z-30 w-full max-w-[36rem] overflow-y-auto border-l border-rule bg-paper 2xl:sticky 2xl:top-0 2xl:z-auto 2xl:h-screen 2xl:max-w-none">
        <div className="sticky top-0 z-10 flex items-start justify-between gap-4 border-b border-rule bg-paper px-6 py-4">
          <div className="min-w-0">
            <h2 ref={heading} tabIndex={-1} className="truncate text-2xl text-ink outline-none">{a.name}</h2>
            <p className="mt-0.5 text-sm text-muted">Identified by: {IDENT[a.ident].label}</p>
          </div>
          <button type="button" onClick={onClose} className="btn shrink-0">Close</button>
        </div>
        <ListControl id={a.id} shortlist={shortlist} />

        <div className="space-y-8 px-6 py-6">
          <section aria-label="Priority">
            <div className="flex items-end gap-4">
              <span className="measured text-reading leading-none tracking-[-0.04em] text-ink">{a.score.toFixed(0)}</span>
              <div className="pb-1"><Tier tier={a.tier} /><p className="mt-1 text-sm text-muted">score out of 100</p></div>
            </div>
            <p className="measured mt-3 text-sm text-ink-2">
              need {a.need.toFixed(1)} × urgency {a.urgency.toFixed(2)} × fit {a.fit.toFixed(2)}
            </p>
            <p className="mt-1 max-w-[60ch] text-sm text-muted">
              Need is risk points from the evidence below. Urgency rises with known-exploited CVEs and end-of-life software.
              Fit is how sure the match is and how large the estate is.
            </p>
          </section>

          <dl className="grid grid-cols-[8rem_minmax(0,1fr)] gap-x-4 gap-y-2 text-sm">
            {facts.map(([k, v]) => (
              <div key={k} className="contents">
                <dt className="text-muted">{k}</dt>
                <dd className="min-w-0 text-ink">{v}</dd>
              </div>
            ))}
            <dt className="text-muted">How we know</dt>
            <dd className="text-ink">{IDENT[a.ident].hint}</dd>
          </dl>

          <section aria-labelledby="opening">
            <div className="mb-2 flex items-center justify-between gap-3">
              <h3 id="opening" className="text-lg text-ink">Opening line</h3>
              <button type="button" className="btn" disabled={!track}
                onClick={() => { navigator.clipboard.writeText(track); setCopied(true); setTimeout(() => setCopied(false), 1500) }}>
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            {ev === null && !evFailed ? (
              <div className="space-y-2"><div className="skeleton h-4 w-full" /><div className="skeleton h-4 w-5/6" /><div className="skeleton h-4 w-2/3" /></div>
            ) : track ? (
              <p className="max-w-[65ch] border-l border-rule-2 pl-4 text-base leading-relaxed text-ink-2">{track}</p>
            ) : (
              <p className="text-sm text-muted">No signal here is specific enough to open with. Use the evidence below.</p>
            )}
            <p className="mt-2 text-xs text-muted">Built only from what the scan observed; nothing is generated.</p>
          </section>

          <WhoToContact account={a} />

          <section aria-labelledby="evidence">
            <h3 id="evidence" className="mb-3 text-lg text-ink">Evidence</h3>
            {evFailed ? (
              <p className="text-sm text-muted">The evidence for this account did not load. Close and reopen it to try again.</p>
            ) : ev === null ? (
              <div className="space-y-3">{[0, 1, 2].map((i) => <div key={i} className="skeleton h-16 w-full" />)}</div>
            ) : (
              <div className="overflow-hidden rounded-[var(--radius-card)] border border-rule">
                {groups.map(([sid, items], gi) => (
                  <div key={sid} className={gi ? 'border-t border-rule' : ''}>
                    <div className="flex items-center justify-between gap-3 bg-paper-2 px-4 py-2.5">
                      <div className="flex min-w-0 flex-wrap items-center gap-2">
                        <span className="text-sm font-medium text-ink">{meta.signals[sid]?.label}</span>
                        {(meta.signals[sid]?.weight ?? 0) >= CRITICAL_WEIGHT && <span className="chip chip-critical">High severity</span>}
                      </div>
                      <span className="shrink-0 text-xs text-muted"><span className="measured">{items.length}</span> {items.length === 1 ? 'asset' : 'assets'}</span>
                    </div>
                    <ul className="divide-y divide-rule">
                      {items.slice(0, 6).map((e, i) => (
                        <li key={i} className="grid grid-cols-[minmax(0,10.5rem)_minmax(0,1fr)] gap-3 px-4 py-2 text-sm">
                          <span className="measured text-cool">{e.ip}:{e.port}</span>
                          <span className="measured min-w-0 break-words text-ink-2">{e.e ?? e.p}</span>
                        </li>
                      ))}
                      {items.length > 6 && <li className="px-4 py-2 text-xs text-muted">and <span className="measured">{items.length - 6}</span> more</li>}
                    </ul>
                  </div>
                ))}
              </div>
            )}
            <p className="mt-2 text-xs text-muted">IP addresses are masked to the /24 network in this published demo.</p>
          </section>

          {a.maturity.length > 0 && (
            <section aria-labelledby="maturity">
              <h3 id="maturity" className="mb-2 text-lg text-ink">Already invests in security</h3>
              <ul className="list-disc space-y-1 pl-5 text-sm text-ink-2 marker:text-rule-2">
                {a.maturity.map((m) => <li key={m}>{meta.maturity[m]}</li>)}
              </ul>
              <p className="mt-2 max-w-[60ch] text-sm text-muted">Pitch coverage gaps and consolidation rather than a first purchase.</p>
            </section>
          )}

          {a.products.length > 0 && (
            <section aria-labelledby="tech">
              <h3 id="tech" className="mb-2 text-lg text-ink">Software seen</h3>
              <p className="text-sm text-ink-2">{a.products.join(', ')}</p>
            </section>
          )}
        </div>
      </aside>
    </>
  )
}

function ListControl({ id, shortlist }: { id: string; shortlist: ReturnType<typeof useShortlist> }) {
  const saved = shortlist.list[id]
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-rule bg-paper-2 px-6 py-3">
      {saved ? (
        <>
          <span className="relative inline-flex">
            <label className="sr-only" htmlFor="status">Status</label>
            <select id="status" value={saved.status} onChange={(e) => shortlist.setStatus(id, e.target.value as Status)}
              className="field appearance-none pl-3 pr-9">
              {STATUSES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
            </select>
            <svg aria-hidden viewBox="0 0 16 16" className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-muted">
              <path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
            </svg>
          </span>
          <span className="text-sm text-muted">On your list since {new Date(saved.added).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' })}</span>
          <button type="button" className="ml-auto text-sm text-muted underline underline-offset-4 hover:text-ink" onClick={() => shortlist.remove(id)}>Remove</button>
        </>
      ) : (
        <>
          <button type="button" className="btn btn-primary" onClick={() => shortlist.save(id)}>Add to my list</button>
          <span className="text-sm text-muted">Track it from to contact to meeting booked.</span>
        </>
      )}
    </div>
  )
}

function WhoToContact({ account: a }: { account: Account }) {
  const isDomain = !a.id.startsWith('org:')
  // a domain account is searched by its brand ("chevron" for chevron.com); an IP-owner account by its registered name
  const company = isDomain ? a.name.split('.')[0] : a.org ?? a.name
  const roles = '(CISO OR "head of security" OR "IT director" OR "IT manager")'
  const links: [string, string][] = [
    ['Security and IT leads on LinkedIn', `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(`${company} ${roles}`)}`],
    ['Same search through Google', `https://www.google.com/search?q=${encodeURIComponent(`site:linkedin.com/in "${company}" ${roles}`)}`],
  ]
  if (isDomain) links.push(['Company website', `https://${a.name}`])
  if (isDomain && a.maturity.includes('security_txt')) links.push(['Their security contact (security.txt)', `https://${a.name}/.well-known/security.txt`])
  return (
    <section aria-labelledby="contact">
      <h3 id="contact" className="mb-1 text-lg text-ink">Who to contact</h3>
      <p className="mb-2 max-w-[60ch] text-sm text-muted">Recon holds no contact data and does not guess names. These open searches for the people who own this exposure.</p>
      <ul className="space-y-1.5 text-sm">
        {links.map(([label, href]) => (
          <li key={href}><a href={href} target="_blank" rel="noopener noreferrer" className="text-ink underline hover:text-accent">{label}</a></li>
        ))}
      </ul>
    </section>
  )
}

function exportCsv(rows: Account[], meta: Dataset, saved: Record<string, Saved>) {
  const head = ['score', 'tier', 'company', 'organisation', 'country', 'industry', 'identified_by', 'signals', 'ips', 'services', 'list_status']
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = rows.map((a) =>
    [a.score, a.tier, a.name, a.org, a.country, a.industry, IDENT[a.ident].label,
      a.signals.map((s) => meta.signals[s]?.label ?? s).join('; '), a.ips, a.assets,
      saved[a.id] ? statusLabel(saved[a.id].status) : ''].map(esc).join(','))
  const blob = new Blob([[head.join(','), ...lines].join('\n')], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  Object.assign(document.createElement('a'), { href: url, download: 'accounts.csv' }).click()
  URL.revokeObjectURL(url)
}
