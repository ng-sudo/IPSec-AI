import { AlertTriangle, CheckCircle2, CircleHelp, LockKeyhole, Minus, ShieldAlert } from 'lucide-react'
import type { Observation } from './api'

type AnyRecord = Record<string, any>

export function StatusPill({ status }: { status: string }) {
  const Icon = status === 'observed' ? CheckCircle2 : status === 'inferred' ? CircleHelp : Minus
  return <span className={`status-pill status-${status}`}><Icon size={13} /> {status}</span>
}

export function ObservationValue({ observation, fallback = 'Unavailable' }: { observation?: Observation<any> | null; fallback?: string }) {
  if (!observation || observation.status === 'unavailable' || observation.value === null || observation.value === undefined) {
    return <span className="value-unavailable"><StatusPill status="unavailable" />{fallback}</span>
  }
  const value = typeof observation.value === 'object' ? JSON.stringify(observation.value) : String(observation.value)
  return <span className="value-wrap"><strong>{value}</strong><StatusPill status={observation.status} /></span>
}

export function Section({ eyebrow, title, children, className = '' }: { eyebrow?: string; title: string; children: React.ReactNode; className?: string }) {
  return <section className={`panel ${className}`}><div className="section-heading">{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2>{title}</h2></div>{children}</section>
}

export function MetricCard({ label, value, detail, tone = '' }: { label: string; value: React.ReactNode; detail?: React.ReactNode; tone?: string }) {
  return <div className={`metric-card ${tone}`}><span className="metric-label">{label}</span><strong className="metric-value">{value}</strong>{detail && <span className="metric-detail">{detail}</span>}</div>
}

export function ScoreHero({ score, riskLevel, scoreStatus, knownWeight }: { score: number | null; riskLevel: string; scoreStatus: string; knownWeight: number }) {
  const scoreLabel = score === null ? '—' : Math.round(score).toString()
  return <div className="score-hero">
    <div className="score-orbit" aria-hidden="true"><div><span>SECURITY</span><strong>{scoreLabel}</strong><small>/ 100</small></div></div>
    <div className="hero-copy"><span className="eyebrow">Assessment posture</span><h1>{riskLevel.replace('_', ' ')}</h1><p>{scoreStatus === 'complete' ? 'All weighted categories are backed by available findings.' : 'Known evidence is scored, but missing inputs remain visible and limit the conclusion.'}</p><div className="hero-meta"><StatusPill status={scoreStatus === 'complete' ? 'observed' : 'unavailable'} /><span>{Math.round(knownWeight * 100)}% of weighted categories known</span></div></div>
  </div>
}

export function FindingsTable({ findings }: { findings: AnyRecord[] }) {
  if (!findings.length) return <div className="empty-inline">No security findings returned.</div>
  return <div className="table-scroll"><table><thead><tr><th>Finding</th><th>Severity</th><th>Status</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>{findings.map((finding) => <tr key={finding.rule_id}><td><strong>{finding.title}</strong><span className="subline">{finding.category}</span></td><td><span className={`severity severity-${finding.severity}`}>{finding.severity}</span></td><td><StatusPill status={finding.status} /></td><td>{finding.evidence}</td><td>{finding.recommendation}</td></tr>)}</tbody></table></div>
}

export function ThreatMatrix({ entries }: { entries: AnyRecord[] }) {
  if (!entries.length) return <div className="empty-inline">No threat matrix data returned.</div>
  return <div className="table-scroll"><table className="matrix-table"><thead><tr><th>Category</th><th>Security score</th><th>Risk</th><th>Likelihood</th><th>Impact</th><th>Status</th></tr></thead><tbody>{entries.map((entry) => <tr key={entry.category}><td><strong>{entry.category.replaceAll('_', ' ')}</strong></td><td>{entry.security_score === null ? '—' : `${Math.round(entry.security_score)}/100`}</td><td><span className={`risk risk-${entry.risk_level}`}>{entry.risk_level.replace('_', ' ')}</span></td><td>{entry.likelihood ?? '—'}</td><td><span className="impact-dot" style={{ '--impact': entry.impact } as React.CSSProperties}>{entry.impact}</span></td><td><StatusPill status={entry.status === 'complete' ? 'observed' : 'unavailable'} /></td></tr>)}</tbody></table></div>
}

export function ErrorState({ message }: { message: string }) {
  return <div className="state-card error-state"><AlertTriangle size={21} /><div><strong>Analysis unavailable</strong><p>{message}</p></div></div>
}

export function EmptyState() {
  return <div className="empty-state"><div className="empty-icon"><LockKeyhole size={28} /></div><h2>Choose a capture to begin</h2><p>Upload or select a PCAP, provide any known VPN context, then run the analysis pipeline.</p></div>
}

export function LoadingState() {
  return <div className="state-card loading-state"><ShieldAlert className="spin" size={22} /><div><strong>Running analysis pipeline</strong><p>Parsing packets, extracting flow features, and assembling deterministic findings.</p></div></div>
}
