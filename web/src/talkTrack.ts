import type { Account, Dataset, Evidence } from './types'

// Opening lines filled in from observed facts only. No LLM, so nothing gets invented.
const LINES: Record<string, (e: Evidence) => string> = {
  edge_kev: (e) => `${e.p ?? 'Your edge appliance'} at ${e.ip}:${e.port} is reachable from the internet and matches ${cves(e)}, which CISA lists as actively exploited.`,
  edge_device: (e) => `the management interface of ${e.p ?? 'your firewall/VPN'} (${e.ip}:${e.port}) answers on the public internet. These appliances are the most common ransomware entry point.`,
  exchange_onprem: (e) => `${e.e ?? 'an on-prem Exchange server'} is internet-facing at ${e.ip}.`,
  remote_access: (e) => `${e.e} at ${e.ip} is open to anyone on the internet.`,
  database_exposed: (e) => `a database (${e.e}) at ${e.ip} accepts connections from the internet.`,
  smb_exposed: (e) => `Windows file sharing is exposed at ${e.ip}:${e.port}.`,
  ot_exposed: (e) => `an industrial/operational protocol (${e.e}) is reachable at ${e.ip}.`,
  kev_cve: (e) => `${e.p ?? 'a public server'} at ${e.ip}:${e.port} matches ${cves(e)}, which is on CISA's known-exploited list.`,
  eol_os: (e) => `${e.e} at ${e.ip} is past end of support and no longer gets security patches.`,
  ntlm_leak: (e) => `a Windows host at ${e.ip} reveals your internal domain (${e.e}) to anyone who connects.`,
  mgmt_exposed: (e) => `an infrastructure management service (${e.e}) is exposed at ${e.ip}.`,
}

function cves(e: Evidence) {
  const m = e.e?.match(/CVE-\d{4}-\d+/g)
  return m ? m.slice(0, 2).join(' / ') : 'a known-exploited CVE'
}

export function talkTrack(a: Account, ev: Evidence[], meta: Dataset): string {
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
