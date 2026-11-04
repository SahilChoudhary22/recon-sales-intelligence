import { useEffect, useId, useRef, useState } from 'react'

const fmt = (n: number) => n.toLocaleString('en-US')
const compact = new Intl.NumberFormat('en-US', { notation: 'compact', maximumFractionDigits: 1 })

export type Option = [value: string, label: string, count?: number]

/** A filter that takes several values (GB or IE or DE). The badge on each option is how many accounts
 *  it would give with every other filter applied, so a seller can see what a choice is worth. */
export function MultiSelect({ label, values, options, onChange, placeholder, inline = false, single = false }: {
  label: string; values: string[]; options: Option[]; onChange: (v: string[]) => void
  placeholder?: string; inline?: boolean; single?: boolean
}) {
  const [open, setOpen] = useState(false)
  const [needle, setNeedle] = useState('')
  const box = useRef<HTMLSpanElement>(null)
  const id = useId()

  useEffect(() => {
    if (!open) return
    const away = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false) }
    const esc = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopImmediatePropagation(); setOpen(false) }
    }
    document.addEventListener('mousedown', away)
    window.addEventListener('keydown', esc, true)
    return () => { document.removeEventListener('mousedown', away); window.removeEventListener('keydown', esc, true) }
  }, [open])

  const name = (v: string) => options.find(([k]) => k === v)?.[1] ?? v
  const summary = values.length === 0 ? placeholder ?? `All` : values.length <= 2 ? values.map(name).join(', ') : `${name(values[0])} +${values.length - 1}`
  const shown = options.filter(([, l]) => !needle || l.toLowerCase().includes(needle.toLowerCase()))
  const toggle = (v: string) => onChange(single ? (values.includes(v) ? [] : [v]) : values.includes(v) ? values.filter((x) => x !== v) : [...values, v])

  return (
    <span ref={box} className="relative inline-flex">
      <button type="button" aria-expanded={open} aria-controls={id} onClick={() => setOpen(!open)}
        className={inline
          ? `rounded-sm px-1 font-medium underline decoration-dotted underline-offset-4 hover:text-accent ${values.length ? 'text-ink' : 'text-ink-2'}`
          : `field inline-flex min-w-0 max-w-[16rem] items-center gap-1.5 pr-8 text-left ${values.length ? 'border-accent text-ink' : ''}`}>
        {!inline && <span className="shrink-0 text-muted">{label}{values.length ? ':' : ''}</span>}
        <span className="truncate">{inline ? summary : values.length ? summary : ''}</span>
        {!inline && (
          <svg aria-hidden viewBox="0 0 16 16" className="pointer-events-none absolute right-3 top-1/2 size-4 -translate-y-1/2 text-muted">
            <path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        )}
      </button>
      {open && (
        <div id={id} role="dialog" aria-label={label}
          className="absolute left-0 top-full z-50 mt-1 w-72 rounded-[var(--radius-card)] border border-rule-2 bg-paper p-2 shadow-lg">
          {options.length > 8 && (
            <input autoFocus value={needle} onChange={(e) => setNeedle(e.target.value)} placeholder={`Find ${label.toLowerCase()}`}
              aria-label={`Find ${label.toLowerCase()}`} className="field mb-2 w-full" />
          )}
          <ul className="max-h-72 overflow-y-auto">
            {shown.map(([v, l, n]) => (
              <li key={v}>
                <label className="flex min-h-8 cursor-pointer items-center gap-2 rounded-[var(--radius-ctl)] px-2 text-sm text-ink-2 hover:bg-paper-2">
                  <input type={single ? 'radio' : 'checkbox'} checked={values.includes(v)} onChange={() => toggle(v)}
                    className="size-4 accent-[var(--color-accent)]" />
                  <span className="min-w-0 flex-1 truncate">{l}</span>
                  {n !== undefined && <span className="measured text-xs text-muted" title={`${fmt(n)} accounts`}>{compact.format(n)}</span>}
                </label>
              </li>
            ))}
            {!shown.length && <li className="px-2 py-1.5 text-sm text-muted">No match</li>}
          </ul>
          {values.length > 0 && (
            <div className="mt-1 flex justify-between border-t border-rule px-2 pt-2 text-sm">
              <span className="text-muted">{values.length} selected{single ? '' : ', any of them'}</span>
              <button type="button" className="text-muted underline underline-offset-4 hover:text-ink" onClick={() => onChange([])}>Clear</button>
            </div>
          )}
        </div>
      )}
    </span>
  )
}
