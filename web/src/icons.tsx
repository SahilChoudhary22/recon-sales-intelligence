// Line icons for the sidebar (24-unit grid, drawn with currentColor so they follow the text colour)
const PATHS: Record<string, string> = {
  list: 'M9 6h11M9 12h11M9 18h11M4.5 6h.01M4.5 12h.01M4.5 18h.01',
  search: 'M18 11a7 7 0 1 1-14 0 7 7 0 0 1 14 0zM20 20l-4-4',
  plus: 'M12 5v14M5 12h14',
  signals: 'M22 12h-4l-3 9L9 3l-3 9H2',
  new: 'M12 3l1.9 5.1L19 10l-5.1 1.9L12 17l-1.9-5.1L5 10l5.1-1.9zM19 16v4M17 18h4',
  p1: 'M5 21V4m0 0h12l-2.5 4.5L17 13H5',
  'edge-kev': 'M12 21.5s7.5-3.6 7.5-9.5V5.5L12 2.5 4.5 5.5V12c0 5.9 7.5 9.5 7.5 9.5zM12 8v4.5M12 16h.01',
  edge: 'M3 5h18v14H3zM3 12h18M9.5 5v7M14.5 12v7',
  exchange: 'M3 6h18v12H3zM3.5 6.5l8.5 6 8.5-6',
  remote: 'M3 4h18v12H3zM8 20h8M12 16v4',
  breach: 'M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0zM12 9v4M12 17h.01',
  ai: 'M7 7h10v10H7zM10 2.5V7M14 2.5V7M10 17v4.5M14 17v4.5M2.5 10H7M2.5 14H7M17 10h4.5M17 14h4.5',
  legacy: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0zM12 7v5l3 2',
  kev: 'M8 9a4 4 0 0 1 8 0v5a4 4 0 0 1-8 0zM12 9v9M4 11h4M16 11h4M4.5 17l3.5-1.5M19.5 17L16 15.5M9.5 4.5L8 3M14.5 4.5L16 3',
  ot: 'M2.5 20.5h19V9l-6 3.5V9l-6 3.5V4h-7zM6 16.5h2M11 16.5h2M16 16.5h2',
  mature: 'M3 17l6-6 4 4 8-8M15 7h6v6',
}

export function Icon({ name, className = 'size-4' }: { name: string; className?: string }) {
  const d = PATHS[name] ?? PATHS.signals
  return (
    <svg aria-hidden viewBox="0 0 24 24" className={`shrink-0 ${className}`} fill="none" stroke="currentColor"
      strokeWidth="1.75" strokeLinecap="round" strokeLinejoin="round">
      <path d={d} />
    </svg>
  )
}
