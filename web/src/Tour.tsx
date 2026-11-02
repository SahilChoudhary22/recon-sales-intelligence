import { useEffect, useLayoutEffect, useRef, useState } from 'react'
import { SEEN, STEPS } from './tourSteps'

export function Tour({ onClose }: { onClose: () => void }) {
  const [i, setI] = useState(0)
  const [rect, setRect] = useState<DOMRect | null>(null)
  const card = useRef<HTMLDivElement>(null)
  const step = STEPS[i]

  const close = () => {
    try {
      localStorage.setItem(SEEN, '1')
    } catch {
      // ignore
    }
    onClose()
  }

  useLayoutEffect(() => {
    const el = document.querySelector(`[data-tour="${step.target}"]`)
    if (!el) return
    el.scrollIntoView({ block: 'nearest' })
    const measure = () => setRect(el.getBoundingClientRect())
    measure()
    window.addEventListener('resize', measure)
    window.addEventListener('scroll', measure, true)
    return () => {
      window.removeEventListener('resize', measure)
      window.removeEventListener('scroll', measure, true)
    }
  }, [step.target])

  useEffect(() => card.current?.focus(), [i])

  // one stable capture-phase listener: the guide owns the keyboard while it is open, so Escape
  // closes the guide only (not the account panel underneath) and is never lost to a re-render
  const closeRef = useRef(close)
  useLayoutEffect(() => {
    closeRef.current = close
  })
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.stopImmediatePropagation()
        closeRef.current()
      }
      if (e.key === 'ArrowRight') setI((n) => Math.min(n + 1, STEPS.length - 1))
      if (e.key === 'ArrowLeft') setI((n) => Math.max(n - 1, 0))
    }
    window.addEventListener('keydown', k, true)
    return () => window.removeEventListener('keydown', k, true)
  }, [])

  // place the card below the target if there is room, otherwise above; clamp to the viewport
  const vw = window.innerWidth, vh = window.innerHeight, w = Math.min(360, vw - 32)
  let top = 16, left = 16
  if (rect) {
    const below = rect.bottom + 12, above = rect.top - 12
    top = below + 220 < vh ? below : Math.max(16, above - 220)
    if (rect.height > vh * 0.6) top = Math.min(vh - 236, rect.top + 24)
    left = Math.min(Math.max(16, rect.left), vw - w - 16)
  }

  return (
    <div className="fixed inset-0 z-40" role="dialog" aria-modal="true" aria-labelledby="tour-title">
      {rect && (
        <div aria-hidden className="pointer-events-none fixed rounded-[var(--radius-card)] outline-2 outline-accent"
          style={{ top: rect.top - 4, left: rect.left - 4, width: rect.width + 8, height: rect.height + 8,
            boxShadow: '0 0 0 9999px color-mix(in oklab, var(--color-ink) 32%, transparent)' }} />
      )}
      <div ref={card} tabIndex={-1} style={{ top, left, width: w }}
        className="fixed rounded-[var(--radius-card)] border border-rule-2 bg-paper-3 p-4 outline-none">
        <p className="measured text-xs text-muted">{i + 1} of {STEPS.length}</p>
        <h2 id="tour-title" className="mt-1 text-lg text-ink">{step.title}</h2>
        <p className="mt-1.5 text-sm leading-relaxed text-ink-2">{step.body}</p>
        <div className="mt-4 flex items-center justify-between gap-2">
          <button type="button" className="text-sm text-muted underline underline-offset-4 hover:text-ink" onClick={close}>Skip</button>
          <div className="flex gap-2">
            {i > 0 && <button type="button" className="btn" onClick={() => setI(i - 1)}>Back</button>}
            {i < STEPS.length - 1
              ? <button type="button" className="btn btn-primary" onClick={() => setI(i + 1)}>Next</button>
              : <button type="button" className="btn btn-primary" onClick={close}>Start</button>}
          </div>
        </div>
      </div>
    </div>
  )
}
