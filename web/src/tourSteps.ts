// the in-app guide: one step per region a seller uses, in the order they use them
export type Step = { target: string; title: string; body: string }

export const STEPS: Step[] = [
  {
    target: 'funnel',
    title: 'Where the accounts come from',
    body: 'One day of internet scan data: 13.4M records, narrowed by removing noise, matching each service to the company that runs it, and keeping only companies with real risk.',
  },
  {
    target: 'plays',
    title: 'Start from what you sell',
    body: 'Pick your product and the signal templates built for it come first. Each template is one buying trigger, like an exposed firewall with exploited CVEs, with a worked example and recommended targeting.',
  },
  {
    target: 'filters',
    title: 'Narrow it to your ICP',
    body: 'Pick several values in any filter (GB or IE, small or mid-size estates); the badges show what each choice gives. Save the search, and Recon tells you what is new each time it runs.',
  },
  {
    target: 'table',
    title: 'Open an account',
    body: 'Rows are ranked by priority. P1 is the 500 to call this week. Open any account to see exactly what is exposed, where, and an opening line built only from what the scan saw.',
  },
  {
    target: 'mylist',
    title: 'Your work',
    body: 'Your lists and saved searches live here. An account can be in several lists, and every table shows which ones. Saved searches count what is new since you last ran them and not in a list yet.',
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
