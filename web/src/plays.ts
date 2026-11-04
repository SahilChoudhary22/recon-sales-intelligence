import type { Account, Play, Sector } from './types'

const has = (a: Account, ...ids: string[]) => ids.some((id) => a.signals.includes(id))
const PUBLIC_NAME = /(universi|college|ministry|municipal|\.edu|\.ac\.|\.gov|\.gob\.|\.mil\b)/i

// ICP: which sector an account sits in, from its industry label and name
export const SECTORS: [Sector, string][] = [
  ['commercial', 'Commercial'],
  ['public', 'Public sector & education'],
  ['infra', 'Telecom & hosting'],
]
export function sectorOf(a: Account): Sector {
  if (a.industry === 'Telecom & hosting') return 'infra'
  if (a.industry === 'Education' || a.industry === 'Government' || PUBLIC_NAME.test(`${a.name} ${a.org ?? ''}`)) return 'public'
  return 'commercial'
}

// "What you sell": each signal template says which product lines it is a buying trigger for
export const PRODUCTS: [string, string][] = [
  ['firewall', 'Firewall & VPN'],
  ['email', 'Email security'],
  ['endpoint', 'Endpoint & EDR'],
  ['vuln', 'Vulnerability management'],
  ['asm', 'Attack surface management'],
  ['mdr', 'MDR & managed security'],
  ['ot', 'OT & IoT security'],
]

// Market signals: the whole ranked market, no list needed (the default view)
export const MARKET: Play = {
  id: 'market', name: 'Market signals',
  blurb: 'Every company in the scan with a material security signal, ranked. Narrow it with ICP filters, or start from a signal template.',
  match: () => true,
}
export const DEFAULT_PLAY = MARKET.id

// Signal templates: a ready-to-run search per sales play, built around one buying trigger
export const TEMPLATES: Play[] = [
  {
    id: 'new', name: 'Newly exposed',
    blurb: 'A risky service that was not in the previous scan: the clearest reason to call this week.',
    pitch: 'It appeared since the last scan, and most incidents start with a change like this.',
    match: (a) => a.new,
  },
  {
    id: 'p1', name: 'Top priority (P1)',
    blurb: 'The 500 highest-priority accounts across every signal: this week’s call list.',
    pitch: 'Lead with the strongest finding on the account; the evidence panel orders it for you.',
    match: (a) => a.tier === 'P1',
  },
  {
    id: 'edge-kev', name: 'Firewall/VPN with exploited CVEs',
    blurb: 'An exposed firewall or VPN admin plane plus CISA known-exploited CVEs in the same estate: the classic ransomware entry path.',
    forProducts: ['firewall', 'mdr', 'asm'],
    pitch: 'Edge devices are the most common way ransomware gets in, and this estate already runs software attackers are exploiting.',
    targeting: { sector: 'commercial', strong: true },
    keys: ['edge_kev', 'edge_device', 'kev_cve'],
    match: (a) => has(a, 'edge_kev') || (has(a, 'edge_device') && a.kev),
  },
  {
    id: 'edge', name: 'Exposed firewall/VPN admin',
    blurb: 'FortiGate, NetScaler, SonicWall, Pulse or BIG-IP with its management interface reachable from the internet.',
    forProducts: ['firewall', 'asm'],
    pitch: 'Their firewall’s admin interface answers on the public internet; that is a configuration problem you can fix with them.',
    targeting: { sector: 'commercial' },
    keys: ['edge_kev', 'edge_device'],
    match: (a) => has(a, 'edge_device', 'edge_kev'),
  },
  {
    id: 'exchange', name: 'On-prem Exchange',
    blurb: 'Self-hosted Exchange or Outlook Web App on the internet: a ProxyShell-class attack surface.',
    forProducts: ['email', 'mdr'],
    pitch: 'On-prem Exchange is one of the most attacked products there is; it opens an email-security or cloud-email conversation.',
    targeting: { sector: 'commercial' },
    keys: ['exchange_onprem'],
    match: (a) => has(a, 'exchange_onprem'),
  },
  {
    id: 'remote', name: 'Open RDP, databases & shares',
    blurb: 'Remote access, databases or Windows file sharing reachable from the internet.',
    forProducts: ['endpoint', 'asm', 'mdr'],
    pitch: 'Anyone on the internet can reach their remote desktop or database today.',
    targeting: { sector: 'commercial' },
    keys: ['remote_access', 'database_exposed', 'smb_exposed', 'open_directory'],
    match: (a) => has(a, 'remote_access', 'database_exposed', 'smb_exposed', 'open_directory'),
  },
  {
    id: 'legacy', name: 'Legacy Windows estates',
    blurb: 'End-of-life Windows Server, or NTLM banners leaking the internal Active Directory domain.',
    forProducts: ['vuln', 'endpoint'],
    pitch: 'Unsupported Windows Server no longer gets security patches, and their servers reveal the internal domain to anyone.',
    keys: ['eol_os', 'ntlm_leak'],
    match: (a) => has(a, 'eol_os', 'ntlm_leak'),
  },
  {
    id: 'kev', name: 'Known-exploited CVEs',
    blurb: 'Software with CVEs on CISA’s Known Exploited Vulnerabilities list (Rapid Reset and jQuery noise excluded).',
    forProducts: ['vuln', 'asm', 'mdr'],
    pitch: 'They run software with vulnerabilities that attackers are exploiting right now, per CISA.',
    targeting: { strong: true },
    keys: ['kev_cve', 'edge_kev'],
    match: (a) => a.kev,
  },
  {
    id: 'ot', name: 'OT & IoT exposure',
    blurb: 'Industrial, medical or point-of-sale protocols and cameras on the internet.',
    forProducts: ['ot'],
    pitch: 'Operational equipment is reachable from the internet; a compliance-led conversation (IEC 62443, NIS2).',
    keys: ['ot_exposed', 'iot_camera'],
    match: (a) => has(a, 'ot_exposed', 'iot_camera'),
  },
  {
    id: 'mature', name: 'Already investing',
    blurb: 'Has a WAF, security.txt or post-quantum TLS but still has gaps.',
    pitch: 'They already buy security; talk coverage gaps and consolidation, not a first purchase.',
    match: (a) => a.maturity.length > 0,
  },
]

// the recommended targeting as a predicate, so a template's worked example sits inside it
export const inTargeting = (t: Play, a: Account) =>
  (!t.targeting?.sector || sectorOf(a) === t.targeting.sector) && (!t.targeting?.strong || !['org', 'ptr'].includes(a.ident))

export const forProduct = (t: Play, product: string) => !product || !t.forProducts || t.forProducts.includes(product)
