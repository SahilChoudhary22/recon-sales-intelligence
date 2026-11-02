import type { Account, Play } from './types'

const has = (a: Account, ...ids: string[]) => ids.some((id) => a.signals.includes(id))

// saved views = the prospecting motions a security AE actually runs
export const PLAYS: Play[] = [
  { id: 'all', name: 'All accounts', blurb: 'Every company with a material signal, ranked.', match: () => true },
  { id: 'p1', name: 'Call today (P1)', blurb: 'The 500 highest-priority accounts: this week’s call list.', match: (a) => a.tier === 'P1' },
  {
    id: 'edge-kev', name: 'Firewall/VPN + KEV in estate',
    blurb: 'Exposed firewall/VPN admin plane plus CISA known-exploited CVEs in the same estate: the classic ransomware entry path.',
    match: (a) => has(a, 'edge_kev') || (has(a, 'edge_device') && a.kev),
  },
  {
    id: 'edge', name: 'Exposed firewall/VPN admin',
    blurb: 'FortiGate, NetScaler, SonicWall, Pulse and similar, with the management plane reachable from the internet.',
    match: (a) => has(a, 'edge_device', 'edge_kev'),
  },
  {
    id: 'exchange', name: 'On-prem Exchange',
    blurb: 'Self-hosted Exchange/OWA: a ProxyShell-class attack surface and a cloud-email security pitch.',
    match: (a) => has(a, 'exchange_onprem'),
  },
  {
    id: 'remote', name: 'RDP, databases & shares open',
    blurb: 'Remote access, databases or SMB reachable from the internet.',
    match: (a) => has(a, 'remote_access', 'database_exposed', 'smb_exposed', 'open_directory'),
  },
  {
    id: 'legacy', name: 'Legacy Windows estates',
    blurb: 'End-of-life Windows Server, or NTLM leaking internal domain names.',
    match: (a) => has(a, 'eol_os', 'ntlm_leak'),
  },
  {
    id: 'kev', name: 'Known-exploited CVEs',
    blurb: 'Software with CVEs on the CISA KEV list (HTTP/2 Rapid Reset excluded as noise).',
    match: (a) => a.kev,
  },
  {
    id: 'ot', name: 'OT / IoT exposure',
    blurb: 'Industrial, medical or POS protocols and cameras on the internet: a compliance-driven buyer.',
    match: (a) => has(a, 'ot_exposed', 'iot_camera'),
  },
  {
    id: 'mature', name: 'Already investing',
    blurb: 'Has a WAF, security.txt or post-quantum TLS but still has gaps: a consolidation pitch.',
    match: (a) => a.maturity.length > 0,
  },
]
