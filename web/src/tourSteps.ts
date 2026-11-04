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
    title: 'Start from what you sell',
    body: 'Pick your product and the signal templates built for it come first. Each template is one buying trigger, like an exposed firewall with exploited CVEs, with a worked example and recommended targeting.',
  },
  {
    target: 'filters',
    title: 'Narrow it to your ICP',
    body: 'Filter by sector, country, industry or the software they run, then save the combination as a segment to rerun it next week.',
  },
  {
    target: 'table',
    title: 'Open an account',
    body: 'Rows are ranked by priority. P1 is the 500 to call this week. Open any account to see exactly what is exposed, where, and an opening line built only from what the scan saw.',
  },
  {
    target: 'mylist',
    title: 'Your work',
    body: 'Lists and segments live here. Track each saved account from to contact to meeting booked, and export it for your CRM.',
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
