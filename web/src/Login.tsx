import { useState } from 'react'
import { api } from './api'
import { LogoMark } from './Logo'
import { APP_NAME, PRODUCT_LINE } from './brand'

// Recon names companies with exploitable exposure, so nothing loads before sign-in.
// The backdrop is public/login-bg.webp when it exists, under a tint of the page colour so the form
// reads in either theme; without it, a faint grid of scan points.
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
    <main className="login-backdrop flex min-h-screen items-center justify-center px-4">
      <form onSubmit={submit}
        className="w-full max-w-sm rounded-[var(--radius-card)] border border-rule-2 bg-paper-2/90 px-6 py-7 shadow-lg backdrop-blur-sm">
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
        <button type="submit" className="btn btn-primary mt-5 inline-flex w-full items-center justify-center gap-2" disabled={busy || !username || !password}>
          {busy ? 'Signing in…' : 'Sign in'}
          {!busy && (
            <svg aria-hidden viewBox="0 0 20 20" className="size-4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round">
              <path d="M12 4h2.5A1.5 1.5 0 0 1 16 5.5v9a1.5 1.5 0 0 1-1.5 1.5H12" />
              <path d="M8 6.5 11.5 10 8 13.5" />
              <path d="M11.5 10H4" />
            </svg>
          )}
        </button>
      </form>
    </main>
  )
}
