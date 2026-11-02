// the in-app guide: one step per region a seller uses, in the order they use them
export type Step = { target: string; title: string; body: string }

export const STEPS: Step[] = [
  {
    target: 'funnel',
    title: 'Where the accounts come from',
    body: 'One day of internet scan data, narrowed down: noise removed, services matched to the company that runs them, and only companies with real risk kept.',
  },
  {
    target: 'plays',
    title: 'Pick a play',
    body: 'Each play is a prospecting motion: exposed firewalls with exploited CVEs, on-prem Exchange, legacy Windows. Commercial accounts drops universities and government.',
  },
  {
    target: 'filters',
    title: 'Narrow it to your patch',
    body: 'Filter by country or industry, or keep only accounts whose identity is strong (the company named itself in its own certificate).',
  },
  {
    target: 'table',
    title: 'Open an account',
    body: 'Rows are ranked by priority. P1 is the 500 to call this week. Open any account to see exactly what is exposed, where, and an opening line built only from what the scan saw.',
  },
  {
    target: 'mylist',
    title: 'Work your list',
    body: 'Add accounts to your list from the account panel, track each one from to contact to meeting booked, and export the list to your CRM.',
  },
]

export const SEEN = 'recon.guide.seen'

export function guideSeen() {
  try {
    return localStorage.getItem(SEEN) === '1'
  } catch {
    return true
  }
}
