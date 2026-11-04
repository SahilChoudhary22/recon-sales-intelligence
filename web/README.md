# Recon web app

Static React + Vite + Tailwind app. It reads the scored accounts that `pipeline/export.py` writes to
`public/data/` (IPs masked to /24) and does all filtering in the browser; there is no backend.

```bash
npm install
npm run dev     # http://localhost:5173
npm run build   # dist/, served by deploy/compose.yaml
npm run lint
```

- `src/App.tsx`: plays, filters, account list, account panel
- `src/plays.ts`: the saved views (prospecting motions)
- `src/talkTrack.ts`: the fact-only opening line
- `src/shortlist.ts`: My list (per-browser storage in this demo)
- `src/Tour.tsx`, `src/tourSteps.ts`: the in-app guide
- `src/brand.ts`, `src/Logo.tsx`: name and mark
- `src/index.css`: design tokens (light and dark)
