// Plain-language guidance per signal for the exposure brief: what the finding means and the usual fix.
// Written once, applied to every account; nothing here is generated per company.
export const GUIDANCE: Record<string, { means: string; action: string }> = {
  breach_evidence: {
    means: 'A database the scanner found already ransomed, or a remote-access trojan or cryptominer running on the company’s address: signs the network has already been breached.',
    action: 'Treat it as an incident: isolate the host, preserve logs, and bring in incident response before cleaning up.',
  },
  ai_exposed: {
    means: 'A self-hosted AI app (a model gateway, chat UI or agent builder) or an MCP server answers on the public internet, often with no login in front of it.',
    action: 'Put it behind single sign-on or a VPN, rotate any API keys it holds, and review which tools an exposed agent can call.',
  },
  edge_kev: {
    means: 'A firewall or VPN appliance is reachable from the internet and runs software with vulnerabilities CISA lists as actively exploited.',
    action: 'Patch the appliance to a fixed release and move its management interface off the public internet.',
  },
  edge_device: {
    means: 'The management interface of a firewall or VPN answers on the public internet, the most common way ransomware gets in.',
    action: 'Restrict management access to a VPN or an allow-list of admin addresses.',
  },
  exchange_onprem: {
    means: 'A self-hosted Microsoft Exchange or Outlook Web App server is internet-facing, a long-running target (ProxyShell, ProxyLogon).',
    action: 'Confirm it is fully patched, or move mail to a managed service and retire the on-prem server.',
  },
  remote_access: {
    means: 'Remote desktop, VNC, Telnet or X11 accepts connections from anywhere on the internet.',
    action: 'Put remote access behind a VPN or zero-trust gateway with multi-factor authentication.',
  },
  database_exposed: {
    means: 'A database server accepts connections from the internet.',
    action: 'Bind it to internal networks only and require authentication from known hosts.',
  },
  smb_exposed: { means: 'Windows file sharing (SMB) is reachable from the internet.', action: 'Block SMB at the edge; it should never be internet-facing.' },
  open_directory: { means: 'A directory listing or file share is publicly browsable.', action: 'Remove public listing and review what was exposed.' },
  mgmt_exposed: {
    means: 'An infrastructure management service (SNMP, LDAP, Kubernetes, router admin) is reachable from the internet.',
    action: 'Restrict it to the management network.',
  },
  ot_exposed: {
    means: 'An industrial, medical or point-of-sale protocol is reachable from the internet.',
    action: 'Segment operational equipment from the internet; review against IEC 62443 or NIS2 obligations.',
  },
  iot_camera: { means: 'An IP camera or video recorder is reachable from the internet.', action: 'Take it off the public internet and update its firmware.' },
  kev_cve: {
    means: 'Internet-facing software matches a version with vulnerabilities CISA lists as actively exploited.',
    action: 'Patch to a fixed version; treat as urgent per CISA guidance.',
  },
  high_epss: { means: 'Internet-facing software matches vulnerabilities with a high predicted chance of exploitation (EPSS).', action: 'Prioritise these in the next patch cycle.' },
  critical_cve: { means: 'Internet-facing software matches a critical-severity vulnerability.', action: 'Confirm the version and patch.' },
  eol_os: { means: 'A server runs an operating system that no longer receives security updates.', action: 'Plan an upgrade; isolate the server until then.' },
  eol_product: { means: 'Internet-facing software is past end of life.', action: 'Upgrade to a supported release.' },
  ntlm_leak: { means: 'A Windows service reveals the internal Active Directory domain and host names to anyone who connects.', action: 'Disable NTLM on internet-facing services or put them behind a gateway.' },
  cert_expired: { means: 'A public service presents an expired TLS certificate.', action: 'Renew it and add certificate-expiry monitoring.' },
  cert_expiring: { means: 'A TLS certificate expires within 30 days.', action: 'Renew it before it lapses.' },
  weak_tls: { means: 'A public service still accepts TLS 1.0/1.1 or SSL.', action: 'Disable legacy protocol versions.' },
  self_signed_web: { means: 'A public service uses a self-signed certificate.', action: 'Use a certificate from a trusted authority.' },
}
