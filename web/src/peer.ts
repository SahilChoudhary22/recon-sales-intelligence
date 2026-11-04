import type { Account } from './types'

const fmt = (n: number) => n.toLocaleString('en-US')

// the peer benchmark as one sentence: "Ranks #4 of 112 manufacturing organisations in the US by external exposure"
export const peerLine = (a: Account) =>
  a.peer ? `Ranks #${fmt(a.peer.rank)} of ${fmt(a.peer.n)} ${a.peer.group} by external exposure` : null
