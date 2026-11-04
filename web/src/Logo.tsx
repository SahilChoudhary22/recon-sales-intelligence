// Recon mark: corner brackets and a split crosshair in the theme's ink, the finding in amber.
// Geometry traced from docs/brand/recon-logo.png (588-unit frame).
export function LogoMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 588 588" className={className} aria-hidden="true" focusable="false">
      <g fill="currentColor">
        <rect x="0" y="0" width="166" height="39"/>
        <rect x="0" y="0" width="39" height="165"/>
        <rect x="422" y="0" width="166" height="39"/>
        <rect x="549" y="0" width="39" height="165"/>
        <rect x="0" y="549" width="166" height="39"/>
        <rect x="0" y="423" width="39" height="165"/>
        <rect x="422" y="549" width="166" height="39"/>
        <rect x="549" y="423" width="39" height="165"/>
        <rect x="276" y="49" width="36" height="172"/>
        <rect x="276" y="367" width="36" height="172"/>
        <rect x="49" y="276" width="172" height="36"/>
        <rect x="367" y="276" width="172" height="36"/>
      </g>
      <rect x="255" y="255" width="78" height="78" fill="var(--color-accent)" />
    </svg>
  )
}
