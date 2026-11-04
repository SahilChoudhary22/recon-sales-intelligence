import { useState } from 'react'
import { api } from './api'
import { LogoMark } from './Logo'
import { APP_NAME, PRODUCT_LINE } from './brand'

// Recon names companies with exploitable exposure, so nothing loads before sign-in.
export function Login({ onDone }: { onDone: () => void }) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    setError('')
    api.login(username.trim(), password)
      .then(onDone)
      .catch((err: Error) => setError(err.message.includes('401') ? 'That username and password don’t match.' : 'Sign-in is unavailable right now. Try again in a minute.'))
      .finally(() => setBusy(false))
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-paper px-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-[var(--radius-card)] border border-rule-2 bg-paper-2 px-6 py-7">
        <p className="flex items-center gap-2.5">
          <LogoMark className="size-7 shrink-0 text-ink" />
          <span className="flex items-baseline gap-2.5">
            <span className="text-xl font-medium leading-none text-ink">{APP_NAME}</span>
            <span className="text-sm leading-none text-muted">{PRODUCT_LINE}</span>
          </span>
        </p>
        <h1 className="mt-6 text-lg text-ink">Sign in</h1>
        <label htmlFor="username" className="mt-4 block text-sm text-ink-2">Username</label>
        <input id="username" name="username" autoComplete="username" autoFocus required value={username}
          onChange={(e) => setUsername(e.target.value)} className="field mt-1 w-full" />
        <label htmlFor="password" className="mt-3 block text-sm text-ink-2">Password</label>
        <input id="password" name="password" type="password" autoComplete="current-password" required value={password}
          onChange={(e) => setPassword(e.target.value)} className="field mt-1 w-full" />
        {error && <p role="alert" className="mt-3 text-sm text-bad">{error}</p>}
        <button type="submit" className="btn btn-primary mt-5 w-full" disabled={busy || !username || !password}>
          {busy ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </main>
  )
}
