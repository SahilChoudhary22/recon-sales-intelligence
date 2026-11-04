import { useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import type { Account, CveResult, Evidence, Meta, Play } from './types'
import { MARKET, PRODUCTS, SECTORS, TEMPLATES, forProduct } from './plays'
import { kevUrl, looksLikeCve, nvdUrl } from './cve'
import { SIGN_IN, api, needsSignIn, useApi, useDebounced, type ApiFilters } from './api'
import { talkTrack } from './talkTrack'
import { APP_NAME, PRODUCT_LINE } from './brand'
import { STATUSES, statusLabel, useWorkspace, type List, type Lists, type SavedSearch, type Schedule, type Status } from './workspace'
import { Login } from './Login'
import { NO_FILTERS, isFiltered, readUrl, toApi, writeUrl, type FilterSet, type ViewState } from './filters'
import { MultiSelect, type Option } from './MultiSelect'
import { Tour } from './Tour'
import { LogoMark } from './Logo'
import { Brief } from './Brief'
import { peerLine } from './peer'
import { guideSeen } from './tourSteps'
import { IcpCard } from './IcpCard'
import { Icon } from './icons'
import { EMPTY_ICP, SIZES, describeIcp, icpFilters, icpIsEmpty, personaRoles, type Icp, type Persona } from './icp'

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
  breach_evidence: 'Signs of a breach', ai_exposed: 'Exposed AI / MCP server',
  edge_kev: 'Edge device + KEV', edge_device: 'Exposed firewall/VPN', exchange_onprem: 'On-prem Exchange',
  remote_access: 'Remote access open', database_exposed: 'Open database', smb_exposed: 'SMB exposed',
  open_directory: 'Open directory', mgmt_exposed: 'Management interface', ot_exposed: 'OT protocol',
  iot_camera: 'Camera or DVR', kev_cve: 'Known-exploited CVE', high_epss: 'Likely-exploited CVE',
  critical_cve: 'Critical CVE', eol_os: 'End-of-life OS', eol_product: 'End-of-life software',
  ntlm_leak: 'Leaks AD domain', cert_expired: 'Expired certificate', cert_expiring: 'Certificate expiring',
  weak_tls: 'TLS 1.0/1.1', self_signed_web: 'Self-signed certificate',
}

const BRIEF_ID = new URLSearchParams(window.location.search).get('brief')

const SIZE_OPTIONS: [string, string][] = SIZES.map(([k, l, hint]) => [k, `${l.replace(' estate', '')}, ${hint}`])
const withCounts = (opts: [string, string][], counts: [string, number][] | undefined): Option[] => {
  const m = new Map(counts ?? [])
  return opts.map(([k, l]) => [k, l, counts ? m.get(k) ?? 0 : undefined])
}

// every route needs a session; a 401 anywhere swaps the app for the sign-in screen
// One question first, "am I signed in?", answered before anything else is drawn: no flash of the app
// before the sign-in page on a slow link, and a plain message when the server can't be reached.
type Session = 'checking' | 'in' | 'out' | 'unreachable'

export default function App() {
  const [session, setSession] = useState<Session>('checking')
  useEffect(() => {
    const ctl = new AbortController()
    const giveUp = setTimeout(() => ctl.abort(), 45_000)
    fetch('./api/me', { signal: ctl.signal })
      .then((r) => setSession(r.ok ? 'in' : r.status === 401 ? 'out' : 'unreachable'))
      .catch(() => setSession('unreachable'))
      .finally(() => clearTimeout(giveUp))
    return () => { clearTimeout(giveUp); ctl.abort() }
  }, [])
  // a session that expires later still lands on sign-in; a layout effect runs before any child's data
  // effects, so the first 401 is never missed
  useLayoutEffect(() => {
    const show = () => setSession('out')
    window.addEventListener(SIGN_IN, show)
    if (needsSignIn()) show()
    return () => window.removeEventListener(SIGN_IN, show)
  }, [])
  if (session === 'out') return <Login onDone={() => window.location.reload()} />
  if (session === 'in') return <Recon />
  return <Splash unreachable={session === 'unreachable'} />
}

function Splash({ unreachable }: { unreachable: boolean }) {
  return (
    <main className="login-backdrop flex min-h-screen items-center justify-center px-4" aria-busy={!unreachable}>
      <div className="max-w-sm text-center">
        <LogoMark className={`mx-auto size-10 text-ink ${unreachable ? '' : 'animate-pulse'}`} />
        {unreachable ? (
          <>
            <p className="mt-4 text-lg text-ink">Recon can’t be reached right now.</p>
            <p className="mt-1 text-sm text-muted">The server didn’t answer. Check the connection and try again.</p>
            <button type="button" className="btn btn-primary mt-5" onClick={() => window.location.reload()}>Try again</button>
          </>
        ) : (
          <p className="mt-4 text-sm text-muted" role="status">Connecting to {APP_NAME}…</p>
        )}
      </div>
    </main>
  )
}

function Recon() {
  const [f, setF] = useState<ViewState>(readUrl)
  // the tour starts by itself on a first visit once the profile card is out of the way; asked for
  // from the header, it always opens
  const [guide, setGuide] = useState<'auto' | 'asked' | null>(() => (guideSeen() ? null : 'auto'))
  const [icpPing, setIcpPing] = useState(0)
  const [naming, setNaming] = useState(false)
  const meta = useApi('meta', () => api.meta())
  const data = meta.data
  const build = data?.build_id ?? ''
  // the user's lists, saved searches and profile, kept by the API
  const work = useWorkspace(build)
  const { lists, saved } = work
  // the ideal customer profile: offered once on a first visit, in the page (never blocking it), then a
  // default layer under every view
  const profile = work.profile.icp ?? EMPTY_ICP
  const profileSeen = work.profile.icp !== null
  const saveProfile = work.profile.save
  const product = profile.product
  const setProduct = (v: string) => saveProfile({ ...profile, product: v })
  const [editingIcp, setEditingIcp] = useState(false)
  const showIcp = editingIcp || (work.ready && !profileSeen && !BRIEF_ID)
  const closeIcp = () => {
    if (!profileSeen) saveProfile({ ...profile, active: false }) // skipped: don't offer it again
    setEditingIcp(false)
  }
  // a filter change starts the list from the top and leaves the saved search it came from
  const set = (patch: Partial<ViewState>) => {
    const filterChange = Object.keys(patch).some((k) => k !== 'id' && k !== 'onlyNew')
    setF((cur) => ({ ...cur, ...(filterChange && !('search' in patch) ? { search: null, onlyNew: false } : {}), ...patch }))
    if (!('id' in patch)) setMore([])
  }
  useEffect(() => { if (!BRIEF_ID) writeUrl(f) }, [f]) // the brief keeps its own ?brief= URL so it can be shared

  const listId = f.play.startsWith('list:') ? f.play.slice(5) : null
  const openSearch = f.search ? saved.searches.find((s) => s.id === f.search) ?? null : null
  const q = useDebounced(f.q, 200)
  // a saved search runs with the profile it was saved with; everything else uses yours. The profile
  // narrows every view except a list, so a saved account never disappears from it.
  const profileQ = useMemo(() => (openSearch ? openSearch.profile : icpFilters(profile)), [openSearch, profile])
  const query: ApiFilters = useMemo(() => {
    const base = toApi({ ...f, q })
    if (listId) return { ...base, template: 'list', list_id: listId }
    const fresh = f.onlyNew && openSearch?.lastRun
    return {
      ...base, ...profileQ, template: f.play,
      exclude_listed: !!(f.hideListed || fresh),
      since_build: fresh ? openSearch!.lastRun! : '',
    }
  }, [f, q, listId, profileQ, openSearch])
  // a list view and "not in my lists" depend on list membership, which the server resolves: re-ask
  // when it changes
  const qKey = JSON.stringify(query) + (query.list_id || query.exclude_listed ? `:v${lists.version}` : '')

  const page = useApi(`search:${qKey}`, (s) => api.search(query, 0, 100, s))
  const [more, setMore] = useState<Account[]>([])
  const [loadingMore, setLoadingMore] = useState(false)
  // rows picked for "add to a list"; a new search starts with nothing picked
  const [pick, setPick] = useState<{ key: string; ids: Set<string> }>({ key: '', ids: new Set() })
  const picked = pick.key === qKey ? pick.ids : new Set<string>()
  const onPick = (ids: string[], on: boolean) => {
    const next = new Set(picked)
    ids.forEach((id) => (on ? next.add(id) : next.delete(id)))
    setPick({ key: qKey, ids: next })
  }
  const [notice, setNotice] = useState('')
  const addAndSay = (ids: string[], listId: string, listName: string) => {
    lists.add(ids, listId)
    setNotice(`Added ${fmt(ids.length)} ${ids.length === 1 ? 'account' : 'accounts'} to ${listName}.`)
  }
  useEffect(() => {
    if (!notice) return
    const t = setTimeout(() => setNotice(''), 5000)
    return () => clearTimeout(t)
  }, [notice])
  const rows = useMemo(() => [...(page.data?.accounts ?? []), ...more], [page.data, more])
  const total = page.data?.total ?? 0
  const showMore = () => {
    setLoadingMore(true)
    api.search(query, rows.length, 200).then((p) => setMore((m) => [...m, ...p.accounts])).finally(() => setLoadingMore(false))
  }
  // template counts in the nav: from the server's count cube, so they cost the same at any size
  const counts = useApi(`counts:${JSON.stringify(profileQ)}`, (s) => api.counts(profileQ, s)).data ?? {}
  // filter options, each with how many accounts it would give here (its own filter left out)
  const facets = useApi(`facets:${qKey}`, (s) => api.facets(query, ['country', 'industry', 'sector', 'size', 'software'], s)).data
  const opts = (k: 'country' | 'industry' | 'software'): Option[] => (facets?.[k] ?? []).map(([v, n]) => [v, v, n])

  // CVE in the news: the server recognises ids and nicknames; a hit switches the page to CVE mode
  const cveAsk = q.trim().length >= 3 && !listId
  const cveQuery = useMemo(() => ({ ...query, q: '', template: 'market' }), [query])
  const cve = useApi(cveAsk ? `cve:${q}:${JSON.stringify(cveQuery)}` : null, (s) => api.cve(q, cveQuery, s))
  const cveIds = cveAsk ? cve.data?.ids ?? [] : []
  const cveMode = cveIds.length > 0

  const listPlay = (l: List): Play => ({
    id: `list:${l.id}`, name: l.name,
    blurb: 'Accounts you saved, with where each one stands. An account can be in several lists. Export it for your CRM.',
  })
  const currentList = listId ? lists.lists.find((l) => l.id === listId) ?? null : null
  const play = currentList ? listPlay(currentList) : [MARKET, ...TEMPLATES].find((x) => x.id === f.play) ?? MARKET
  const isTemplate = TEMPLATES.some((t) => t.id === play.id)
  // the worked example: the top account inside the template's recommended targeting and your profile
  const exampleQ = { template: play.id, sector: play.targeting?.sector ? [play.targeting.sector] : [], strong: !!play.targeting?.strong }
  const example = useApi(isTemplate ? `example:${JSON.stringify([exampleQ, profileQ])}` : null, async (s) =>
    (await api.search({ ...exampleQ, ...profileQ }, 0, 1, s)).accounts[0] ?? (await api.search(exampleQ, 0, 1, s)).accounts[0] ?? null).data

  // the open account: from the list when it's on screen, otherwise asked for by id
  const inRows = rows.find((a) => a.id === f.id) ?? cve.data?.accounts.find((a) => a.id === f.id)
  const fetched = useApi(f.id && !inRows ? `account:${f.id}` : null, () => api.account(f.id!)).data
  const selected = f.id ? inRows ?? (fetched?.id === f.id ? fetched : null) : null

  const filtered = isFiltered(f)
  // 'Newly exposed' needs two or more scans; it stays out of the way until there is something in it
  const shown = TEMPLATES.filter((t) => t.id !== 'new' || (counts[t.id] ?? 0) > 0)
  const mine = shown.filter((t) => forProduct(t, product))
  const others = product ? shown.filter((t) => !forProduct(t, product)) : []

  const navButton = (p: Play, count: number | undefined, extra?: React.ReactNode) => {
    const on = p.id === play.id && !f.search
    return (
      <button type="button" aria-current={on ? 'page' : undefined} onClick={() => set({ play: p.id, search: null, onlyNew: false })}
        className={`group flex w-full min-h-9 items-center gap-2.5 rounded-[var(--radius-ctl)] px-2.5 text-left text-sm transition-colors duration-[var(--dur-micro)] ${
          on ? 'bg-accent-soft font-medium text-ink' : 'text-ink-2 hover:bg-paper-2 hover:text-ink'
        }`}>
        <span className={on ? 'text-accent' : 'text-muted group-hover:text-ink-2'}>
          <Icon name={p.id.startsWith('list:') ? 'list' : p.id === MARKET.id ? 'signals' : p.id} />
        </span>
        <span className="min-w-0 flex-1 truncate whitespace-nowrap lg:whitespace-normal">{p.name}</span>
        {extra ?? <span className="measured text-xs text-muted">{count === undefined ? '' : fmt(count)}</span>}
      </button>
    )
  }
  const filterSet: FilterSet = { play: f.play, q: f.q, country: f.country, industry: f.industry, sector: f.sector,
    software: f.software, size: f.size, strong: f.strong, hideListed: f.hideListed }
  const profileSet = !icpIsEmpty(profile)
  const profileOn = profile.active && profileSet && !openSearch
  const sectorName = (s: string) => SECTORS.find(([k]) => k === s)?.[1] ?? s
  const saveIcp = (p: Icp) => {
    saveProfile(p)
    setEditingIcp(false)
    setMore([])
  }
  const openSaved = (s: SavedSearch) => set({ ...s.filters, id: null, search: s.id, onlyNew: false })

  if (BRIEF_ID) return <BriefPage id={BRIEF_ID} meta={data} />

  return (
    <div className="min-h-screen">
      <Header data={data} onGuide={() => setGuide('asked')} onIcp={() => { setEditingIcp(true); setIcpPing((n) => n + 1) }} icpOn={profileOn} />
      <div className="mx-auto max-w-[112rem] lg:grid lg:grid-cols-[16rem_minmax(0,1fr)] 2xl:grid-cols-[16rem_minmax(0,1fr)_minmax(0,34rem)]">
        <nav aria-label="Views" className="flex gap-4 overflow-x-auto border-b border-rule px-4 py-3 lg:block lg:overflow-visible lg:border-b-0 lg:border-r lg:px-3 lg:py-5">
          <div data-tour="mylist" className="shrink-0 lg:mb-5">
            <NavHeading>Lists</NavHeading>
            <ul className="flex gap-1 lg:block lg:space-y-0.5">
              {lists.lists.map((l) => <li key={l.id} className="shrink-0">{navButton(listPlay(l), lists.idsIn(l.id).length)}</li>)}
            </ul>
            <NewList onCreate={(name) => set({ play: `list:${lists.create(name)}`, search: null })} />
          </div>
          {saved.searches.length > 0 && (
            <div className="hidden shrink-0 lg:mb-5 lg:block lg:border-t lg:border-rule lg:pt-4">
              <NavHeading>Saved searches</NavHeading>
              <ul className="space-y-0.5">
                {saved.searches.map((s) => (
                  <li key={s.id}>
                    <SavedSearchItem s={s} on={f.search === s.id} version={lists.version} onOpen={() => openSaved(s)} />
                  </li>
                ))}
              </ul>
            </div>
          )}
          <div className="shrink-0 lg:mb-5 lg:border-t lg:border-rule lg:pt-4">
            <NavHeading>Prospect</NavHeading>
            {navButton(MARKET, counts[MARKET.id])}
          </div>
          <div data-tour="plays" className="min-w-0 lg:border-t lg:border-rule lg:pt-4">
            <NavHeading>{product ? 'Signal templates for you' : 'Signal templates'}</NavHeading>
            <div className="mb-3 hidden px-2 lg:block">
              <label htmlFor="product" className="text-xs text-muted">Tailored to what you sell</label>
              <span className="relative mt-1 flex">
                <select id="product" value={product} onChange={(e) => setProduct(e.target.value)} className="field w-full appearance-none pl-3 pr-9">
                  <option value="">Any security product</option>
                  {PRODUCTS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
                </select>
                <Chevron />
              </span>
            </div>
            <ul className="flex gap-1 lg:flex-col">
              {mine.map((t) => <li key={t.id} className="shrink-0">{navButton(t, counts[t.id])}</li>)}
            </ul>
            {others.length > 0 && (
              <>
                <NavHeading className="mt-4">Other templates</NavHeading>
                <ul className="flex gap-1 lg:flex-col">
                  {others.map((t) => <li key={t.id} className="shrink-0">{navButton(t, counts[t.id])}</li>)}
                </ul>
              </>
            )}
          </div>
        </nav>

        <main className="min-w-0 px-4 py-5 sm:px-6">
          {showIcp && data && <IcpCard initial={{ ...profile, product }} first={!profileSeen} ping={icpPing} onSave={saveIcp} onClose={closeIcp} />}

          {openSearch ? (
            <SavedSearchBanner s={openSearch} build={build} onlyNew={f.onlyNew} lists={lists}
              onAddNew={(l, name) => lists.addSearch(newQuery(openSearch), l).then((n) => {
                setNotice(`Added ${fmt(n)} new ${n === 1 ? 'account' : 'accounts'} to ${name}.`); saved.markRun(openSearch.id)
              })}
              onOnlyNew={(v) => set({ onlyNew: v })} onRun={() => { saved.markRun(openSearch.id); set({ onlyNew: false }) }}
              onSchedule={(v) => saved.setSchedule(openSearch.id, v)}
              onDelete={() => { saved.remove(openSearch.id); set({ search: null, onlyNew: false }) }} />
          ) : cveMode ? (
            <div className="mb-4 max-w-[75ch]">
              <h1 className="text-xl text-ink">CVE in the news</h1>
              <p className="mt-1 text-sm text-muted">Which accounts run software affected by {cveIds.length === 1 ? 'this vulnerability' : 'these vulnerabilities'}, across the whole market. Your filters and ICP still apply.</p>
            </div>
          ) : isTemplate && data ? (
            <TemplateCard t={play} meta={data} product={product} example={example ?? null}
              applied={(!play.targeting?.sector || (f.sector.length === 1 && f.sector[0] === play.targeting.sector)) && (!play.targeting?.strong || f.strong)}
              // the template's own filters on top of yours: its sector replaces any sector you picked, the rest stays
              onCustomize={() => set({ ...(play.targeting?.sector ? { sector: [play.targeting.sector] } : {}), ...(play.targeting?.strong ? { strong: true } : {}) })}
              onOpen={(id) => set({ id })} />
          ) : (
            <div className="mb-4 flex max-w-[75ch] flex-wrap items-baseline gap-x-4">
              <h1 className="text-xl text-ink">{play.name}</h1>
              {currentList && currentList.id !== lists.lists[0]?.id && (
                <button type="button" className="text-sm text-muted underline underline-offset-4 hover:text-ink"
                  onClick={() => { lists.remove(currentList.id); set({ play: `list:${lists.lists[0]?.id}` }) }}>Delete list</button>
              )}
              <p className="mt-1 w-full text-sm text-muted">{play.blurb}</p>
            </div>
          )}

          <div data-tour="filters" className="mb-4">
            <div className="flex flex-wrap items-center gap-2">
              <label className="sr-only" htmlFor="q">Search accounts</label>
              <input id="q" type="search" name="q" autoComplete="off" value={f.q} onChange={(e) => set({ q: e.target.value })}
                placeholder="Company, or a CVE in the news" className="field w-full sm:w-64" />
              <MultiSelect label="Sector" values={f.sector} options={withCounts(SECTORS, facets?.sector)} onChange={(v) => set({ sector: v })} />
              <MultiSelect label="Country" values={f.country} options={opts('country')} onChange={(v) => set({ country: v })} />
              <MultiSelect label="Industry" values={f.industry} options={opts('industry')} onChange={(v) => set({ industry: v })} />
              <MultiSelect label="Estate size" values={f.size} options={withCounts(SIZE_OPTIONS, facets?.size)} onChange={(v) => set({ size: v })} />
              <MultiSelect label="Software seen" values={f.software} options={opts('software')} onChange={(v) => set({ software: v })} />
              <label className="flex min-h-9 items-center gap-2 px-1 text-sm text-ink-2">
                <input type="checkbox" checked={f.strong} onChange={(e) => set({ strong: e.target.checked })} className="size-4 accent-[var(--color-accent)]" />
                Strong identity only
              </label>
              {!listId && (
                <label className="flex min-h-9 items-center gap-2 px-1 text-sm text-ink-2" title="Leave out accounts already in any of your lists">
                  <input type="checkbox" checked={f.hideListed} onChange={(e) => set({ hideListed: e.target.checked })} className="size-4 accent-[var(--color-accent)]" />
                  Not in my lists
                </label>
              )}
            </div>
            <div className="mt-2 flex flex-wrap items-center gap-3">
              {!cveMode && page.data && <span className="text-sm text-muted"><span className="measured text-ink">{fmt(total)}</span> {total === 1 ? 'account' : 'accounts'}</span>}
              {filtered && <button type="button" className="text-sm text-muted underline underline-offset-4 hover:text-ink" onClick={() => set(NO_FILTERS)}>Clear filters</button>}
              {!listId && !openSearch && (profileSet ? (
                <span className="flex flex-wrap items-center gap-x-2 text-sm text-muted">
                  {profileOn
                    ? <span className="chip max-w-[32rem] truncate" title={`Your ICP: ${describeIcp(profile, sectorName)}`}>Your ICP: {describeIcp(profile, sectorName)}</span>
                    : <span>Your ICP is off</span>}
                  <button type="button" className="underline underline-offset-4 hover:text-ink" onClick={() => setEditingIcp(true)}>Edit</button>
                  <button type="button" className="underline underline-offset-4 hover:text-ink"
                    onClick={() => { saveProfile({ ...profile, active: !profile.active }); setMore([]) }}>
                    {profileOn ? 'Turn off' : 'Turn on'}
                  </button>
                </span>
              ) : !showIcp && (
                <button type="button" className="text-sm text-muted underline underline-offset-4 hover:text-ink" onClick={() => setEditingIcp(true)}>
                  Personalise with your ICP
                </button>
              ))}
              {notice && <span role="status" className="text-sm text-ink">{notice}</span>}
              <div className="ml-auto flex flex-wrap items-center gap-2">
                {!cveMode && picked.size > 0 && (
                  <>
                    <button type="button" className="text-sm text-muted underline underline-offset-4 hover:text-ink" onClick={() => setPick({ key: qKey, ids: new Set() })}>
                      Clear {fmt(picked.size)} selected
                    </button>
                    <ListPicker lists={lists} primary label={`Add ${fmt(picked.size)} to a list`}
                      onPick={(l, name) => { addAndSay([...picked], l, name); setPick({ key: qKey, ids: new Set() }) }} />
                  </>
                )}
                {!cveMode && picked.size === 0 && total > 0 && (
                  <ListPicker lists={lists} label={total > 5000 ? 'Add top 5,000 to a list' : `Add all ${fmt(total)} to a list`}
                    onPick={(l, name) => lists.addSearch(query, l).then((n) => setNotice(`Added ${fmt(n)} ${n === 1 ? 'account' : 'accounts'} to ${name}.`))} />
                )}
                {naming ? (
                  <SaveSearchForm onCancel={() => setNaming(false)}
                    onSave={(name) => { const id = saved.add(name, filterSet, profileQ); setNaming(false); set({ search: id, onlyNew: false }) }}
                    suggestion={[play.name, ...f.sector.map(sectorName), ...f.country, ...f.software].filter(Boolean).slice(0, 4).join(', ')} />
                ) : (
                  <button type="button" className="btn" disabled={!!listId || !!openSearch || !build} onClick={() => setNaming(true)}>Save search</button>
                )}
                {!cveMode && <button type="button" className="btn" disabled={!total}
                  onClick={() => (listId ? api.search(query, 0, 500).then((p) => data && exportList(p.accounts, data, lists)) : api.exportCsv(query))}>Export CSV</button>}
              </div>
            </div>
          </div>

          <div data-tour="table">
            {cveMode && cve.data ? (
              <CveResults result={cve.data} selectedId={f.id} lists={lists}
                onOpen={(id) => set({ id })} onFamily={(fam) => set({ q: '', software: [fam] })} />
            ) : looksLikeCve(f.q) && (cve.loading || f.q !== q) ? (
              <SkeletonRows />
            ) : meta.error || page.error ? (
              <State title="The account list did not load." body="The Recon API could not be reached. Check the connection and try again.">
                <button type="button" className="btn" onClick={() => { meta.retry(); page.retry() }}>Try again</button>
              </State>
            ) : !data || !page.data ? (
              <SkeletonRows />
            ) : !rows.length && listId && !filtered ? (
              <State title="This list is empty." body="Open any account and add it to a list. Saved accounts collect here with their status, ready to export." >
                <button type="button" className="btn" onClick={() => set({ play: 'p1' })}>Browse the P1 accounts</button>
              </State>
            ) : !rows.length && openSearch && f.onlyNew ? (
              <State title="Nothing new since you last ran this search." body={`Every account it finds today was already there on ${shortDate(openSearch.lastRunAt)}, or is in one of your lists. New accounts appear here when a new scan is processed.`}>
                <button type="button" className="btn" onClick={() => set({ onlyNew: false })}>Show all results</button>
              </State>
            ) : !rows.length ? (
              <State title="No accounts match these filters." body={`${play.name} has ${fmt(listId ? lists.idsIn(listId).length : counts[play.id] ?? 0)} accounts${profileOn && !listId ? ' in your ICP' : ''} before filtering.`}>
                {filtered && <button type="button" className="btn" onClick={() => set(NO_FILTERS)}>Clear filters</button>}
                {!filtered && profileOn && <button type="button" className="btn" onClick={() => setEditingIcp(true)}>Edit your ICP</button>}
              </State>
            ) : (
              <>
                <div className={page.loading ? 'opacity-60 transition-opacity' : ''} aria-busy={page.loading}>
                  <AccountTable rows={rows} meta={data} lists={lists} selectedId={f.id} onSelect={(id) => set({ id })} picked={picked} onPick={onPick} />
                  <AccountList rows={rows} meta={data} lists={lists} onSelect={(id) => set({ id })} />
                </div>
                {total > rows.length && (
                  <button type="button" className="btn mt-4" disabled={loadingMore} onClick={showMore}>
                    Show 200 more <span className="measured text-muted">({fmt(total - rows.length)} left)</span>
                  </button>
                )}
              </>
            )}
          </div>
        </main>

        <Detail key={selected?.id ?? 'none'} account={selected} meta={data} lists={lists} highlight={cveIds} personas={profile.personas} onClose={() => set({ id: null })} />
      </div>
      {data && (guide === 'asked' || (guide === 'auto' && !showIcp)) && <Tour onClose={() => setGuide(null)} />}
    </div>
  )
}

// what a saved search finds that is new since its last run and in none of your lists
const newQuery = (s: SavedSearch): ApiFilters =>
  ({ ...toApi(s.filters), ...s.profile, template: s.filters.play, exclude_listed: true, since_build: s.lastRun ?? '' })

const shortDate = (iso: string | null) => (iso ? new Date(iso).toLocaleDateString('en-GB', { day: 'numeric', month: 'short' }) : 'the last run')

// a saved search in the nav, with how many accounts are new since it last ran and in none of your lists
function SavedSearchItem({ s, on, version, onOpen }: { s: SavedSearch; on: boolean; version: number; onOpen: () => void }) {
  const fresh = newQuery(s)
  const n = useApi(s.lastRun ? `new:${JSON.stringify(fresh)}:v${version}` : null, (sig) => api.search(fresh, 0, 1, sig)).data?.total ?? 0
  return (
    <button type="button" onClick={onOpen} aria-current={on ? 'page' : undefined} title={`Saved search: ${s.name}`}
      className={`group flex min-h-9 w-full items-center gap-2.5 rounded-[var(--radius-ctl)] px-2.5 text-left text-sm ${on ? 'bg-accent-soft font-medium text-ink' : 'text-ink-2 hover:bg-paper-2 hover:text-ink'}`}>
      <span className={on ? 'text-accent' : 'text-muted group-hover:text-ink-2'}><Icon name="search" /></span>
      <span className="min-w-0 flex-1 truncate">{s.name}</span>
      {n > 0 && <span className="chip chip-act measured shrink-0">{fmt(n)} new</span>}
    </button>
  )
}

function SavedSearchBanner({ s, build, onlyNew, lists, onAddNew, onOnlyNew, onRun, onSchedule, onDelete }: {
  s: SavedSearch; build: string; onlyNew: boolean; lists: Lists
  onAddNew: (listId: string, name: string) => void
  onOnlyNew: (v: boolean) => void; onRun: () => void; onSchedule: (v: Schedule) => void; onDelete: () => void
}) {
  const fresh = newQuery(s)
  const n = useApi(s.lastRun ? `new:${JSON.stringify(fresh)}:v${lists.version}` : null, (sig) => api.search(fresh, 0, 1, sig)).data?.total
  const upToDate = s.lastRun === build
  return (
    <section aria-labelledby="search-title" className="mb-4 rounded-[var(--radius-card)] border border-rule px-5 py-4">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <div>
          <p className="text-sm text-muted">Saved search</p>
          <h1 id="search-title" className="text-xl text-ink">{s.name}</h1>
        </div>
        <div className="flex flex-wrap items-center gap-3 text-sm">
          <span className="relative inline-flex">
            <label className="sr-only" htmlFor="schedule">Run</label>
            <select id="schedule" value={s.schedule} onChange={(e) => onSchedule(e.target.value as Schedule)} className="field appearance-none pl-3 pr-9">
              <option value="daily">Check for new accounts daily</option>
              <option value="manual">Only when I run it</option>
            </select>
            <Chevron />
          </span>
          {!!n && <ListPicker lists={lists} primary label={`Add ${fmt(n)} new to a list`}
            onPick={(l, name) => onAddNew(l, name)} />}
          <button type="button" className="btn" onClick={onRun} disabled={upToDate && !n}>Mark as reviewed</button>
          <button type="button" className="text-muted underline underline-offset-4 hover:text-ink" onClick={onDelete}>Delete</button>
        </div>
      </div>
      <p className="mt-2 text-sm text-ink-2">
        Last run {shortDate(s.lastRunAt)}.{' '}
        {n === undefined ? '' : n > 0
          ? <><span className="measured text-ink">{fmt(n)}</span> {n === 1 ? 'account is' : 'accounts are'} new since then and in none of your lists.</>
          : upToDate ? 'Nothing new since then: no scan has been processed since.' : 'Nothing new since then that isn’t already in a list.'}
      </p>
      <label className="mt-2 flex min-h-8 items-center gap-2 text-sm text-ink-2">
        <input type="checkbox" checked={onlyNew} onChange={(e) => onOnlyNew(e.target.checked)} className="size-4 accent-[var(--color-accent)]" />
        Only show what’s new since the last run, and not in a list
      </label>
    </section>
  )
}

// a sidebar section label: small caps, so it never reads as one of the rows it heads
function NavHeading({ children, className = '' }: { children: React.ReactNode; className?: string }) {
  return <h2 className={`mb-2 hidden px-2.5 text-[0.6875rem] font-semibold uppercase tracking-[0.08em] text-muted lg:block ${className}`}>{children}</h2>
}

function NewList({ onCreate }: { onCreate: (name: string) => void }) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  if (!open) {
    return (
      <button type="button" className="mt-0.5 hidden min-h-9 w-full items-center gap-2.5 rounded-[var(--radius-ctl)] px-2.5 text-left text-sm text-muted hover:bg-paper-2 hover:text-ink lg:flex" onClick={() => setOpen(true)}>
        <Icon name="plus" />
        New list
      </button>
    )
  }
  return (
    <form className="mt-1 hidden gap-1 px-1 lg:flex" onSubmit={(e) => { e.preventDefault(); if (name.trim()) { onCreate(name); setName(''); setOpen(false) } }}>
      <label className="sr-only" htmlFor="new-list">List name</label>
      <input id="new-list" autoFocus value={name} onChange={(e) => setName(e.target.value)} maxLength={50} placeholder="List name" className="field min-w-0 flex-1"
        onKeyDown={(e) => e.key === 'Escape' && setOpen(false)} />
      <button type="submit" className="btn" disabled={!name.trim()}>Add</button>
    </form>
  )
}

// the shareable exposure brief (?brief=<id>): one account and its evidence, nothing else loaded
function BriefPage({ id, meta }: { id: string; meta: Meta | null }) {
  const acc = useApi(`account:${id}`, () => api.account(id))
  if (acc.error) return <p className="p-10 text-sm text-muted">No such account.</p>
  return meta && acc.data ? <Brief a={acc.data} meta={meta} /> : <p className="p-10 text-sm text-muted">Loading…</p>
}

const pctFmt = (x?: number | null) => (x == null ? 'n/a' : x >= 0.995 ? '>99%' : `${(x * 100).toFixed(x < 0.1 ? 1 : 0)}%`)

function CveResults({ result, selectedId, lists, onOpen, onFamily }: {
  result: CveResult; selectedId: string | null
  lists: Lists; onOpen: (id: string) => void; onFamily: (family: string) => void
}) {
  // the server has already joined the CVE to the accounts inside every filter and the profile
  const { ids, facts, scanDate, kev } = result
  const hits = result.accounts
  const outside = result.outside.top
  const outsideTotal = result.outside.total
  const unsaved = hits.filter((h) => !lists.entries[h.id]).map((h) => h.id)

  return (
    <div className="space-y-5">
      <div className="grid gap-3 xl:grid-cols-2">
        {ids.map((id) => {
          const c = facts[id]
          return (
            <section key={id} aria-label={id} className="rounded-[var(--radius-card)] border border-rule px-4 py-3">
              <div className="flex flex-wrap items-baseline justify-between gap-2">
                <h2 className="measured text-lg text-ink">{id}</h2>
                <span className="text-sm">
                  <a href={nvdUrl(id)} target="_blank" rel="noopener noreferrer" className="text-ink-2 underline hover:text-accent">NVD</a>
                  {c?.kev && <> <span className="text-muted">and</span> <a href={kevUrl(id)} target="_blank" rel="noopener noreferrer" className="text-ink-2 underline hover:text-accent">CISA KEV</a></>}
                </span>
              </div>
              {!c ? (
                <p className="mt-1 text-sm text-muted">Not matched in this scan and not on CISA’s known-exploited list (catalogue {kev.version ?? 'not loaded'}).</p>
              ) : (
                <>
                  {c.title && <p className="mt-1 text-sm text-ink-2">{c.title}</p>}
                  <dl className="mt-2 flex flex-wrap gap-x-5 gap-y-1 text-sm">
                    <div><dt className="inline text-muted">CVSS </dt><dd className="measured inline text-ink">{c.cvss != null ? c.cvss.toFixed(1) : 'n/a'}</dd></div>
                    <div><dt className="inline text-muted">EPSS </dt><dd className="measured inline text-ink">{pctFmt(c.epss)}</dd></div>
                    <div><dt className="inline text-muted">Known exploited </dt><dd className="inline text-ink">{c.kev ? `yes, since ${c.kevAdded ?? 'the scan'}` : 'no'}</dd></div>
                    {c.ransomware && <div><dd className="inline"><span className="chip chip-critical">Used in ransomware campaigns</span></dd></div>}
                  </dl>
                  {c.noise && (
                    <p className="mt-2 text-sm text-bad">Matched on nearly every web server of this type from its version number alone, so it is a weak reason to call. Recon leaves it out of scoring.</p>
                  )}
                  <p className="mt-2 text-sm text-ink-2">
                    {c.inScan ? (
                      <>Matched by software version on <span className="measured text-ink">{fmt(c.companies)}</span> companies in the {scanDate} scan
                        {c.seenProduct ? <>, mostly on {c.seenProduct}</> : null}. That is a version match, not proof the hole is open.</>
                    ) : (
                      <>Not matched in the {scanDate} scan{c.vendor ? <>. CISA lists it for {c.vendor} {c.product}</> : null}.</>
                    )}
                  </p>
                  {!c.inScan && c.family && (
                    <button type="button" className="btn mt-2" onClick={() => onFamily(c.family!)}>Show companies running {c.family}</button>
                  )}
                </>
              )}
            </section>
          )
        })}
      </div>

      {hits.length > 0 && (
        <section aria-labelledby="cve-hits">
          <div className="mb-2 flex flex-wrap items-center gap-3">
            <h2 id="cve-hits" className="text-lg text-ink">Affected accounts</h2>
            <span className="text-sm text-muted"><span className="measured text-ink">{fmt(result.total)}</span> ranked accounts, inside your filters and ICP</span>
            <span className="ml-auto">
              {unsaved.length
                ? <ListPicker lists={lists} label={`Add ${fmt(unsaved.length)} to a list`} primary onPick={(l) => lists.add(unsaved, l)} />
                : <span className="text-sm text-muted">All of them are in your lists</span>}
            </span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[46rem] border-collapse text-md">
              <thead>
                <tr className="border-b border-rule-2 text-left text-sm text-muted">
                  <th scope="col" className="py-2 pr-4 font-medium">Priority</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Account</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Affected</th>
                  <th scope="col" className="py-2 pr-4 font-medium">Country</th>
                  <th scope="col" className="py-2 text-right font-medium">Services</th>
                </tr>
              </thead>
              <tbody>
                {hits.map((a) => (
                  <tr key={a.id} onClick={() => onOpen(a.id)}
                    className={`cursor-pointer border-b border-rule align-top ${a.id === selectedId ? 'bg-accent-soft' : 'hover:bg-paper-2'}`}>
                    <td className="py-3 pr-4"><div className="flex items-center gap-2"><Tier tier={a.tier} /><span className="measured text-sm">{a.score.toFixed(0)}</span></div></td>
                    <td className="max-w-[20rem] py-3 pr-4">
                      <button type="button" onClick={(e) => { e.stopPropagation(); onOpen(a.id) }} className="block max-w-full truncate text-left font-medium text-ink hover:underline">{a.name}</button>
                      <div className="truncate text-sm text-muted">{IDENT[a.ident].label}{a.org && a.org !== a.name ? <>, {a.org}</> : null}</div>
                      <InLists id={a.id} lists={lists} />
                    </td>
                    <td className="py-3 pr-4 text-sm">
                      <div className="text-ink">{a.affected_product ?? 'Unknown software'}{a.affected_new && <span className="chip chip-act ml-2">New this scan</span>}</div>
                      <div className="measured text-ink-2">{a.example_services.join(', ')}</div>
                      {ids.length > 1 && <div className="measured text-xs text-muted">{a.cves.join(', ')}</div>}
                    </td>
                    <td className="measured py-3 pr-4 text-sm text-ink-2">{a.country ?? ''}</td>
                    <td className="measured py-3 text-right text-sm text-ink-2">{fmt(a.affected)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {result.total > hits.length && <p className="mt-2 text-sm text-muted">Showing the top {fmt(hits.length)} of {fmt(result.total)}. Narrow with filters or your ICP.</p>}
        </section>
      )}

      {outsideTotal > 0 && (
        <section aria-labelledby="cve-outside">
          <h2 id="cve-outside" className="text-lg text-ink">Also affected, with no other material risk</h2>
          <p className="mb-2 mt-1 text-sm text-muted">
            <span className="measured">{fmt(outsideTotal)}</span> more companies run it, but nothing else about them is serious enough to rank them as accounts. Filters do not apply to this list; the top {fmt(outside.length)} are shown.
          </p>
          <ul className="divide-y divide-rule border-y border-rule text-sm">
            {outside.map(({ name, country: cc, score, n, product }, i) => (
              <li key={`${name}-${i}`} className="grid grid-cols-[3rem_minmax(0,1fr)_3rem_minmax(0,12rem)_4rem] gap-3 py-2">
                <span className="measured text-ink-2">{score.toFixed(0)}</span>
                <span className="truncate text-ink">{name}</span>
                <span className="measured text-muted">{cc}</span>
                <span className="truncate text-ink-2">{product}</span>
                <span className="measured text-right text-muted">{fmt(n)}</span>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  )
}

function Chevron() {
  return (
    <svg aria-hidden viewBox="0 0 16 16" className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-muted">
      <path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  )
}

function SaveSearchForm({ suggestion, onSave, onCancel }: { suggestion: string; onSave: (name: string) => void; onCancel: () => void }) {
  const [name, setName] = useState(suggestion)
  return (
    <form className="flex items-center gap-2" onSubmit={(e) => { e.preventDefault(); if (name.trim()) onSave(name) }}>
      <label className="sr-only" htmlFor="search-name">Search name</label>
      <input id="search-name" autoFocus value={name} onChange={(e) => setName(e.target.value)} maxLength={60}
        className="field w-64" placeholder="Name this search" />
      <button type="submit" className="btn btn-primary" disabled={!name.trim()}>Save</button>
      <button type="button" className="btn" onClick={onCancel}>Cancel</button>
    </form>
  )
}

function TemplateCard({ t, meta, product, example, applied, onCustomize, onOpen }: {
  t: Play; meta: Meta; product: string; example: Account | null; applied: boolean; onCustomize: () => void; onOpen: (id: string) => void
}) {
  const productNames = (t.forProducts ?? []).map((k) => PRODUCTS.find(([id]) => id === k)?.[1]).filter(Boolean)
  const targeting = [
    t.targeting?.sector && SECTORS.find(([k]) => k === t.targeting?.sector)?.[1],
    t.targeting?.strong && 'Strong identity only',
  ].filter(Boolean) as string[]
  // show the finding this template is about, not just the account's strongest signal
  const keyed = example && (t.keys?.find((k) => example.signals.includes(k)) ?? example.signals[0])
  const top = keyed ? meta.signals[keyed]?.label : undefined
  return (
    <section aria-labelledby="template-title" className="mb-5 overflow-hidden rounded-[var(--radius-card)] border border-rule">
      <div className="bg-paper-2 px-5 py-4">
        <p className="text-sm text-muted">Signal template</p>
        <h1 id="template-title" className="mt-0.5 text-xl text-ink">{t.name}</h1>
        <p className="mt-1 max-w-[75ch] text-sm text-ink-2">{t.blurb}</p>
      </div>
      <dl className="grid gap-x-6 gap-y-3 px-5 py-4 text-sm md:grid-cols-[9rem_minmax(0,1fr)]">
        <dt className="text-muted">Built for</dt>
        <dd className="text-ink">{productNames.length ? productNames.join(', ') : 'Any security product'}
          {product && t.forProducts && !t.forProducts.includes(product) && <span className="text-muted">, not your product</span>}
        </dd>
        <dt className="text-muted">Pitch</dt>
        <dd className="max-w-[75ch] text-ink">{t.pitch}</dd>
        <dt className="text-muted">Worked example</dt>
        <dd className="text-ink">
          {example ? (
            <>
              <button type="button" className="font-medium underline underline-offset-4 hover:text-accent" onClick={() => onOpen(example.id)}>{example.name}</button>
              <span className="text-muted"> scores <span className="measured">{example.score.toFixed(0)}</span>, the top account for this template and its targeting.</span>
              {top && <span className="mt-0.5 block text-ink-2">{top}</span>}
            </>
          ) : 'No account matches in this scan.'}
        </dd>
        <dt className="text-muted">Recommended targeting</dt>
        <dd className="flex flex-wrap items-center gap-2 text-ink">
          {targeting.length ? targeting.map((x) => <span key={x} className="chip">{x}</span>) : <span className="text-ink-2">The whole market</span>}
          {targeting.length > 0 && (applied
            ? <span className="ml-1 text-ink-2">Targeting applied</span>
            : <button type="button" className="btn ml-1" onClick={onCustomize} title="Adds these to your current filters">Apply targeting</button>)}
        </dd>
        <dt className="text-muted">Watching</dt>
        <dd className="max-w-[75ch] text-ink-2">When the next scan file is ingested, accounts that newly match this template show up under Newly exposed.</dd>
      </dl>
    </section>
  )
}

const compact = new Intl.NumberFormat('en-US', { notation: 'compact', maximumSignificantDigits: 3 })

function Header({ data, onGuide, onIcp, icpOn }: { data: Meta | null; onGuide: () => void; onIcp: () => void; icpOn: boolean }) {
  const f = data?.funnel as Record<string, number> | undefined
  return (
    <header className="border-b border-rule bg-paper-2" data-tour="funnel">
      <div className="mx-auto flex max-w-[112rem] flex-wrap items-center justify-between gap-x-6 gap-y-2 px-4 py-3 sm:px-6">
        <p className="flex items-center gap-2.5">
          <LogoMark className="size-7 shrink-0 text-ink" />
          {/* the two names share a baseline; the mark centres on the pair */}
          <span className="flex items-baseline gap-2.5">
            <span className="text-xl font-medium leading-none text-ink">{APP_NAME}</span>
            <span className="text-sm leading-none text-muted">{PRODUCT_LINE}</span>
          </span>
        </p>
        <div className="flex items-center gap-4">
          {/* provenance in one quiet line; the full funnel lives in the README and the MCP server */}
          {f && (
            <p className="hidden text-sm text-muted md:block"
              title={`${fmt(f.raw_records)} banners, ${fmt(f.clean)} after noise removal, ${fmt(f.attributed_assets)} tied to a company`}>
              <span className="measured text-ink-2">{compact.format(f.companies_with_material_signal)}</span> companies with real risk, from{' '}
              <span className="measured text-ink-2">{compact.format(f.raw_records)}</span> scan records
            </p>
          )}
          <button type="button" className="btn" onClick={onIcp} aria-label={icpOn ? 'Your ICP (on)' : 'Your ICP'}>
            Your ICP{icpOn && <span aria-hidden="true" className="size-1.5 rounded-full bg-accent" />}
          </button>
          <button type="button" className="btn" onClick={onGuide}>How it works</button>
          <button type="button" className="text-sm text-muted underline underline-offset-4 hover:text-ink"
            onClick={() => api.logout().finally(() => window.location.reload())}>Sign out</button>
        </div>
      </div>
    </header>
  )
}

function SignalChip({ id, meta }: { id: string; meta: Meta }) {
  const m = meta.signals[id]
  return <span title={m?.label} className="chip">{SHORT[id] ?? m?.label ?? id}</span>
}

function Tier({ tier }: { tier: Account['tier'] }) {
  if (tier === 'P1') return <span className="chip chip-act">P1</span>
  if (tier === 'P2') return <span className="chip">P2</span>
  return <span className="chip border-transparent text-muted">P3</span>
}

function AccountTable({ rows, meta, lists, selectedId, onSelect, picked, onPick }: {
  rows: Account[]; meta: Meta; lists: Lists; selectedId: string | null; onSelect: (id: string) => void
  picked: Set<string>; onPick: (ids: string[], on: boolean) => void
}) {
  const allOn = rows.length > 0 && rows.every((a) => picked.has(a.id))
  return (
    <div className="hidden overflow-x-auto md:block">
    <table className="w-full min-w-[46rem] border-collapse text-md">
      <thead>
        <tr className="border-b border-rule-2 text-left text-sm text-muted">
          <th scope="col" className="w-8 py-2 pr-2">
            <input type="checkbox" aria-label="Select every account on this page" checked={allOn}
              onChange={(e) => onPick(rows.map((a) => a.id), e.target.checked)} className="size-4 accent-[var(--color-accent)]" />
          </th>
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
              <td className="py-3 pr-2" onClick={(e) => e.stopPropagation()}>
                <input type="checkbox" aria-label={`Select ${a.name}`} checked={picked.has(a.id)}
                  onChange={(e) => onPick([a.id], e.target.checked)} className="size-4 accent-[var(--color-accent)]" />
              </td>
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
                <InLists id={a.id} lists={lists} />
              </td>
              <td className="py-3 pr-4">
                <div className="flex flex-wrap gap-1">
                  {a.new && <span className="chip chip-act">New this scan</span>}
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

function AccountList({ rows, meta, lists, onSelect }: { rows: Account[]; meta: Meta; lists: Lists; onSelect: (id: string) => void }) {
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
            <InLists id={a.id} lists={lists} />
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

function Detail({ account: a, meta, lists, highlight, personas, onClose }: {
  account: Account | null; meta: Meta | null; lists: Lists; highlight: string[]; personas: Persona[]; onClose: () => void
}) {
  const [ev, setEv] = useState<Evidence[] | null>(null)
  const [evFailed, setEvFailed] = useState(false)
  const [copied, setCopied] = useState(false)
  const heading = useRef<HTMLHeadingElement>(null)

  useEffect(() => {
    if (!a) return
    api.evidence(a.id).then(setEv).catch(() => setEvFailed(true))
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
          <div className="flex shrink-0 gap-2">
            <a href={`./?brief=${encodeURIComponent(a.id)}`} target="_blank" rel="noopener" className="btn">Exposure brief</a>
            <button type="button" onClick={onClose} className="btn">Close</button>
          </div>
        </div>
        <ListControl id={a.id} lists={lists} />

        <div className="space-y-8 px-6 py-6">
          <section aria-label="Priority">
            <div className="flex items-end gap-4">
              <span className="measured text-reading leading-none tracking-[-0.04em] text-ink">{a.score.toFixed(0)}</span>
              <div className="pb-1"><Tier tier={a.tier} /><p className="mt-1 text-sm text-muted">score out of 100</p></div>
            </div>
            {a.peer && <p className="mt-3 text-md text-ink">{peerLine(a)}.</p>}
            <p className="measured mt-3 text-sm text-ink-2">
              need {a.need.toFixed(1)} × urgency {a.urgency.toFixed(2)} × fit {a.fit.toFixed(2)}
            </p>
            <p className="mt-1 max-w-[60ch] text-sm text-muted">
              Need is risk points from the evidence below. Urgency rises with known-exploited CVEs and end-of-life software.
              Fit is how sure the match is and how large the estate is (estimated from its IPs here; firmographic enrichment would give real headcount).
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

          <WhoToContact account={a} personas={personas} />

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
                        <li key={i} className={`grid grid-cols-[minmax(0,10.5rem)_minmax(0,1fr)] gap-3 px-4 py-2 text-sm ${
                          highlight.some((id) => e.e?.includes(id)) ? 'bg-accent-soft' : ''}`}>
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

          {(a.software.length > 0 || a.products.length > 0) && (
            <section aria-labelledby="tech">
              <h3 id="tech" className="mb-2 text-lg text-ink">Software seen</h3>
              <p className="text-sm text-ink-2">{(a.software.length ? a.software : a.products).join(', ')}</p>
            </section>
          )}
        </div>
      </aside>
    </>
  )
}

// which lists an account is in, and its status, under its name in any table
function InLists({ id, lists }: { id: string; lists: Lists }) {
  const e = lists.entries[id]
  if (!e) return null
  const names = e.lists.map(lists.name)
  return (
    <span className="mt-1.5 flex flex-wrap gap-1" title={`In ${names.join(', ')}`}>
      <span className="chip chip-act">{statusLabel(e.status)}</span>
      <span className="chip max-w-[14rem] truncate">{names.length <= 2 ? names.join(', ') : `${names[0]} +${names.length - 1}`}</span>
    </span>
  )
}

// pick a list to add to, or make a new one
function ListPicker({ lists, label, onPick, primary = false }: { lists: Lists; label: string; onPick: (listId: string, name: string) => void; primary?: boolean }) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const box = useRef<HTMLSpanElement>(null)
  useEffect(() => {
    if (!open) return
    const away = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false) }
    document.addEventListener('mousedown', away)
    return () => document.removeEventListener('mousedown', away)
  }, [open])
  const pick = (id: string, name: string) => { onPick(id, name); setOpen(false); setName('') }
  return (
    <span ref={box} className="relative inline-flex">
      <button type="button" className={`btn ${primary ? 'btn-primary' : ''}`} aria-expanded={open} onClick={() => setOpen(!open)}>{label}</button>
      {open && (
        <div role="dialog" aria-label="Choose a list" className="absolute right-0 top-full z-50 mt-1 w-64 rounded-[var(--radius-card)] border border-rule-2 bg-paper p-2 shadow-lg">
          <ul className="max-h-60 overflow-y-auto">
            {lists.lists.map((l) => (
              <li key={l.id}>
                <button type="button" className="flex min-h-8 w-full items-center justify-between rounded-[var(--radius-ctl)] px-2 text-left text-sm text-ink-2 hover:bg-paper-2" onClick={() => pick(l.id, l.name)}>
                  <span className="truncate">{l.name}</span><span className="measured text-xs text-muted">{fmt(lists.idsIn(l.id).length)}</span>
                </button>
              </li>
            ))}
          </ul>
          <form className="mt-1 flex gap-1 border-t border-rule pt-2" onSubmit={(e) => { e.preventDefault(); if (name.trim()) pick(lists.create(name), name.trim()) }}>
            <label className="sr-only" htmlFor="picker-new">New list name</label>
            <input id="picker-new" value={name} onChange={(e) => setName(e.target.value)} maxLength={50} placeholder="New list" className="field min-w-0 flex-1" />
            <button type="submit" className="btn" disabled={!name.trim()}>Add</button>
          </form>
        </div>
      )}
    </span>
  )
}

function ListControl({ id, lists }: { id: string; lists: Lists }) {
  const e = lists.entries[id]
  const notIn = lists.lists.filter((l) => !e?.lists.includes(l.id))
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-rule bg-paper-2 px-6 py-3">
      {e && (
        <span className="relative inline-flex">
          <label className="sr-only" htmlFor="status">Status</label>
          <select id="status" value={e.status} onChange={(ev) => lists.setStatus(id, ev.target.value as Status)}
            className="field appearance-none pl-3 pr-9">
            {STATUSES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
          </select>
          <Chevron />
        </span>
      )}
      {e?.lists.map((l) => (
        <span key={l} className="chip inline-flex items-center gap-1">
          {lists.name(l)}
          <button type="button" aria-label={`Remove from ${lists.name(l)}`} className="text-muted hover:text-ink" onClick={() => lists.removeFrom(id, l)}>×</button>
        </span>
      ))}
      <span className={e ? 'ml-auto' : ''}>
        <ListPicker lists={{ ...lists, lists: notIn.length ? notIn : lists.lists }} label={e ? 'Add to another list' : 'Add to a list'} primary={!e}
          onPick={(l) => lists.add([id], l)} />
      </span>
      {!e && <span className="text-sm text-muted">Track it from to contact to meeting booked.</span>}
    </div>
  )
}

function WhoToContact({ account: a, personas }: { account: Account; personas: Persona[] }) {
  const isDomain = !a.id.startsWith('org:')
  // a domain account is searched by its brand ("chevron" for chevron.com); an IP-owner account by its registered name
  const company = isDomain ? a.name.split('.')[0] : a.org ?? a.name
  // the roles come from "who you usually reach out to" in your ICP
  const { who, roles } = personaRoles(personas)
  const links: [string, string][] = [
    [`${who} on LinkedIn`, `https://www.linkedin.com/search/results/people/?keywords=${encodeURIComponent(`${company} ${roles}`)}`],
    ['Same search through Google', `https://www.google.com/search?q=${encodeURIComponent(`site:linkedin.com/in "${company}" ${roles}`)}`],
  ]
  if (isDomain) links.push(['Company website', `https://${a.name}`])
  if (isDomain && a.maturity.includes('security_txt')) links.push(['Their security contact (security.txt)', `https://${a.name}/.well-known/security.txt`])
  return (
    <section aria-labelledby="contact">
      <h3 id="contact" className="mb-1 text-lg text-ink">Who to contact</h3>
      <p className="mb-2 max-w-[60ch] text-sm text-muted">This scan data has no people in it, and Recon never guesses names. These open searches for the people who own this exposure. In production, named and verified contacts come from an enrichment source joined on the company domain.</p>
      <ul className="space-y-1.5 text-sm">
        {links.map(([label, href]) => (
          <li key={href}><a href={href} target="_blank" rel="noopener noreferrer" className="text-ink underline hover:text-accent">{label}</a></li>
        ))}
      </ul>
    </section>
  )
}

// My list exports in the browser, because the status of each account lives here; other views export on the server
function exportList(rows: Account[], meta: Meta, lists: Lists) {
  const head = ['score', 'tier', 'company', 'organisation', 'country', 'industry', 'identified_by', 'signals', 'ips', 'services', 'list_status', 'lists']
  const esc = (v: unknown) => `"${String(v ?? '').replace(/"/g, '""')}"`
  const lines = rows.map((a) =>
    [a.score, a.tier, a.name, a.org, a.country, a.industry, IDENT[a.ident].label,
      a.signals.map((s) => meta.signals[s]?.label ?? s).join('; '), a.ips, a.assets,
      lists.entries[a.id] ? statusLabel(lists.entries[a.id].status) : '',
      (lists.entries[a.id]?.lists ?? []).map(lists.name).join('; ')].map(esc).join(','))
  const blob = new Blob([[head.join(','), ...lines].join('\n')], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  Object.assign(document.createElement('a'), { href: url, download: 'accounts.csv' }).click()
  URL.revokeObjectURL(url)
}
