import type { Account, Meta, Evidence } from './types'

// Opening lines filled in from observed facts only. No LLM, so nothing gets invented.
const LINES: Record<string, (e: Evidence) => string> = {
  breach_evidence: (e) => `${e.e ?? 'a service'} at ${e.ip} shows signs of an existing compromise, which usually means someone is already inside.`,
  ai_exposed: (e) => `a self-hosted AI service (${e.e ?? 'an AI app'}) at ${e.ip} answers on the public internet, where model gateways and agent servers can leak keys, data and tool access.`,
  edge_kev: (e) => `${e.p ?? 'Your edge appliance'} at ${e.ip}:${e.port} is reachable from the internet and runs a version affected by ${cves(e)}, which CISA lists as actively exploited.`,
  edge_device: (e) => `${e.p ?? 'your firewall/VPN appliance'} (${e.ip}:${e.port}) answers on the public internet. These appliances are the most common ransomware entry point.`,
  exchange_onprem: (e) => `${e.e ?? 'an on-prem Exchange server'} is internet-facing at ${e.ip}.`,
  remote_access: (e) => `${e.e} at ${e.ip} is open to anyone on the internet.`,
  winrm_exposed: (e) => `Windows Remote Management (WinRM) at ${e.ip}:${e.port} answers on the public internet.`,
  debug_exposed: (e) => `a public page at ${e.ip}:${e.port} shows ${e.e?.startsWith('phpinfo') ? 'a phpinfo() page' : 'a stack trace'}, giving away software versions and file paths.`,
  database_exposed: (e) => `a database (${e.e}) at ${e.ip} accepts connections from the internet.`,
  smb_exposed: (e) => `Windows file sharing is exposed at ${e.ip}:${e.port}.`,
  ot_exposed: (e) => `an industrial/operational protocol (${e.e}) is reachable at ${e.ip}.`,
  kev_cve: (e) => confirmed(e)
    ? `the scanner's own test confirmed ${cves(e)} on ${confirmed(e)} at ${e.ip}:${e.port}, which is on CISA's known-exploited list.`
    : `${seen(e) ?? e.p ?? 'a public server'} at ${e.ip}:${e.port} is a version affected by ${cves(e)}, which is on CISA's known-exploited list.`,
  eol_os: (e) => e.e?.includes('support ended') ? `a server at ${e.ip} runs ${e.e}.` : `a server at ${e.ip} runs ${e.e}, past the end of its security support.`,
  ntlm_leak: (e) => `a Windows host at ${e.ip} reveals your internal domain (${e.e}) to anyone who connects.`,
  mgmt_exposed: (e) => `an infrastructure management service (${e.e}) is exposed at ${e.ip}.`,
}

// The evidence names each CVE under its product: "PHP 7.4.33 — CVE-…; Apache httpd 2.4.49 — CVE-…".
// A line uses the first product and only its CVEs, so one product's CVE is never put on another.
const CONFIRMED = "Confirmed by the scanner's own test on "

function first(e: Evidence) {
  const m = e.e?.split('; ')[0].split(' — ')
  return m && m.length > 1 ? { seen: m[0], cves: m[1] } : undefined
}

function seen(e: Evidence) {
  return first(e)?.seen
}

function confirmed(e: Evidence) {
  const s = seen(e)
  return s?.startsWith(CONFIRMED) ? s.slice(CONFIRMED.length) : undefined
}

function cves(e: Evidence) {
  const m = (first(e)?.cves ?? e.e)?.match(/CVE-\d{4}-\d+/g)
  return m ? m.slice(0, 2).join(' / ') : 'a known-exploited CVE'
}

export function talkTrack(a: Account, ev: Evidence[], meta: Meta): string {
  const ranked = [...ev].sort((x, y) => (meta.signals[y.s]?.weight ?? 0) - (meta.signals[x.s]?.weight ?? 0))
  const lines: string[] = []
  const used = new Set<string>()
  for (const e of ranked) {
    const f = LINES[e.s]
    if (!f || used.has(e.s)) continue
    used.add(e.s)
    lines.push(f(e))
    if (lines.length === 2) break
  }
  if (!lines.length) return ''
  const who = a.org && a.ident === 'org' ? a.org : a.name
  const extra = a.assets > lines.length ? ` We counted ${a.assets} internet-facing services across ${a.ips} IPs in the same scan.` : ''
  const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1)
  return `Hi, while mapping ${who}'s external attack surface we noticed that ${lines[0]}${
    lines[1] ? ` ${cap(lines[1])}` : ''
  }${extra} Worth 15 minutes to walk through what an attacker sees?`
}
