import { useEffect, useMemo, useState } from 'react'
import { Activity, ArrowUpRight, FileUp, RefreshCw, Search, ShieldCheck, SlidersHorizontal, UploadCloud } from 'lucide-react'
import { analyzeCapture, listCaptures, uploadCapture, type AnalysisResponse, type CaptureInfo, type Observation } from './api'
import { EmptyState, ErrorState, FindingsTable, LoadingState, MetricCard, ObservationValue, ScoreHero, Section, StatusPill, ThreatMatrix } from './components'
import './App.css'

type FormState = Record<string, string>
const blankForm: FormState = { ipsec_mode: '', ike_version: '', encryption: '', integrity: '', prf: '', dh_group: '', pfs_enabled: '', ip_version: '', auth_method: '', key_lifetime_seconds: '', replay_protection: '' }

function App() {
  const [captures, setCaptures] = useState<CaptureInfo[]>([])
  const [selectedCapture, setSelectedCapture] = useState('')
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null)
  const [form, setForm] = useState<FormState>(blankForm)
  const [loading, setLoading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [error, setError] = useState('')
  const selected = useMemo(() => captures.find((capture) => capture.capture_id === selectedCapture), [captures, selectedCapture])

  useEffect(() => { refreshCaptures() }, [])

  async function refreshCaptures() {
    try { setCaptures(await listCaptures()) } catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'Unable to load captures.') }
  }

  async function handleUpload(event: React.ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0]
    if (!file) return
    setUploading(true); setError('')
    try { const created = await uploadCapture(file); await refreshCaptures(); setSelectedCapture(created.capture_id); setAnalysis(null) }
    catch (requestError) { setError(requestError instanceof Error ? requestError.message : 'Upload failed.') }
    finally { setUploading(false); event.target.value = '' }
  }

  async function runAnalysis() {
    if (!selectedCapture) return
    setLoading(true); setError('')
    try {
      const configuration = Object.fromEntries(Object.entries(form).filter(([, value]) => value !== '').map(([key, value]) => [key, ['ike_version', 'ip_version', 'key_lifetime_seconds'].includes(key) ? Number(value) : ['pfs_enabled', 'replay_protection'].includes(key) ? value === 'true' : value]))
      setAnalysis(await analyzeCapture(selectedCapture, configuration))
    } catch (requestError) { setAnalysis(null); setError(requestError instanceof Error ? requestError.message : 'Analysis failed.') }
    finally { setLoading(false) }
  }

  const setField = (key: string, value: string) => setForm((current) => ({ ...current, [key]: value }))
  return <main className="app-shell">
    <header className="topbar"><div className="brand"><div className="brand-mark"><ShieldCheck size={21} /></div><div><strong>IPSecAI</strong><span>Encrypted traffic intelligence</span></div></div><div className="topbar-status"><span className="live-dot" /> API workspace <span className="divider" /> <span className="mono">v1.0</span></div></header>
    <div className="workspace">
      <aside className="control-rail">
        <div className="rail-heading"><span className="eyebrow">Capture workspace</span><h2>Evidence source</h2></div>
        <label className="upload-button"><UploadCloud size={18} /> {uploading ? 'Uploading…' : 'Upload PCAP'}<input type="file" accept=".pcap,.pcapng" onChange={handleUpload} disabled={uploading} /></label>
        <div className="capture-list"><div className="list-label"><span>Available captures</span><button className="icon-button" onClick={refreshCaptures} title="Refresh captures"><RefreshCw size={15} /></button></div>{captures.length === 0 ? <p className="muted">No captures available.</p> : captures.map((capture) => <button key={capture.capture_id} className={`capture-item ${selectedCapture === capture.capture_id ? 'selected' : ''}`} onClick={() => { setSelectedCapture(capture.capture_id); setAnalysis(null) }}><FileUp size={15} /><span><strong>{capture.filename}</strong><small>{formatBytes(capture.size_bytes)}</small></span><ArrowUpRight size={14} /></button>)}</div>
        <div className="context-form"><div className="list-label"><span>Known VPN context</span><SlidersHorizontal size={15} /></div><p className="form-note">Optional. Blank fields stay unavailable.</p><Field label="Mode" value={form.ipsec_mode} onChange={(value) => setField('ipsec_mode', value)} options={['tunnel', 'transport']} /><Field label="IKE version" value={form.ike_version} onChange={(value) => setField('ike_version', value)} options={['1', '2']} /><Field label="Encryption" value={form.encryption} onChange={(value) => setField('encryption', value)} options={['aes128cbc', 'aes256cbc', 'aes128gcm16', 'aes256gcm16']} /><Field label="Integrity" value={form.integrity} onChange={(value) => setField('integrity', value)} options={['sha256', 'sha384', 'sha512', 'sha1']} /><Field label="DH group" value={form.dh_group} onChange={(value) => setField('dh_group', value)} options={['modp2048', 'ecp256', 'ecp384']} /><Field label="Authentication" value={form.auth_method} onChange={(value) => setField('auth_method', value)} options={['cert', 'psk']} /><Field label="PFS" value={form.pfs_enabled} onChange={(value) => setField('pfs_enabled', value)} options={['true', 'false']} /><Field label="Replay protection" value={form.replay_protection} onChange={(value) => setField('replay_protection', value)} options={['true', 'false']} /></div>
        <button className="analyze-button" disabled={!selectedCapture || loading} onClick={runAnalysis}><Activity size={17} /> {loading ? 'Analyzing…' : 'Run analysis'}<span>↗</span></button>
      </aside>
      <section className="dashboard">
        <div className="dashboard-heading"><div><span className="eyebrow">Security observatory</span><h1>Encrypted traffic, made legible.</h1><p>One view across deterministic protocol facts, flow behavior, AI inference, and security posture.</p></div><div className="selected-chip"><Search size={15} /><span>{selected ? selected.filename : 'No capture selected'}</span></div></div>
        {error && <ErrorState message={error} />}{loading && <LoadingState />}{!loading && !analysis && !error && <EmptyState />}{!loading && analysis && <AnalysisView analysis={analysis} />}
      </section>
    </div>
  </main>
}

function AnalysisView({ analysis }: { analysis: AnalysisResponse }) {
  const packetSummary = analysis.packet_analysis.packet_summary
  const flow = analysis.features.derived_flow_features
  const config = analysis.vpn_configuration
  return <div className="analysis-view">
    <ScoreHero score={analysis.risk_assessment.overall_score} riskLevel={analysis.risk_assessment.risk_level} scoreStatus={analysis.risk_assessment.score_status} knownWeight={analysis.risk_assessment.known_weight} />
    <div className="metric-grid"><MetricCard label="Traffic prediction" value={<ObservationValue observation={analysis.prediction.predicted_traffic_type} />} detail={<><StatusPill status={analysis.prediction.confidence.status} /> {analysis.prediction.confidence.value === null ? 'Confidence unavailable' : `${Math.round(analysis.prediction.confidence.value * 100)}% confidence`}</>} tone="accent-card" /><MetricCard label="IPsec detection" value={<ObservationValue observation={analysis.metadata_inference.ipsec_detected} />} detail="Packet analysis" /><MetricCard label="ESP packets" value={<ObservationValue observation={analysis.packet_analysis.esp_packets} />} detail="Observed protocol traffic" /><MetricCard label="Flow duration" value={<ObservationValue observation={packetSummary.duration_seconds} />} detail="Seconds" /></div>
    <div className="content-grid"><Section eyebrow="Protocol identity" title="VPN / IPsec profile"><div className="fact-grid"><Fact label="IPsec mode" value={config.ipsec_mode} /><Fact label="IKE version" observation={analysis.metadata_inference.ike_version} /><Fact label="Encryption" value={config.encryption} /><Fact label="Authentication" value={config.auth_method} /><Fact label="DH / key exchange" value={config.dh_group} /><Fact label="PFS" value={config.pfs_enabled} /><Fact label="Replay protection" value={config.replay_protection} /><Fact label="Key lifetime" value={config.key_lifetime_seconds ? `${config.key_lifetime_seconds}s` : null} /></div></Section><Section eyebrow="Observed perimeter" title="Metadata exposure"><div className="fact-grid"><Fact label="Source IP" observation={analysis.metadata_inference.source_ip} /><Fact label="Destination IP" observation={analysis.metadata_inference.destination_ip} /><Fact label="Direction" observation={analysis.metadata_inference.flow_direction} /><Fact label="Payload contents" observation={analysis.metadata_inference.encrypted_payload_contents} /></div></Section></div>
    <Section eyebrow="Flow telemetry" title="Traffic statistics"><div className="stats-strip"><Fact label="Packets" observation={flow.packet_count} /><Fact label="Bytes" observation={flow.byte_count} /><Fact label="Mean packet size" observation={flow.packet_size_mean} /><Fact label="Packet size spread" observation={flow.packet_size_stddev} /><Fact label="Mean inter-arrival" observation={flow.inter_arrival_mean} /><Fact label="Packets / second" observation={flow.packets_per_second} /></div></Section>
    <Section eyebrow="Deterministic review" title="Security findings"><FindingsTable findings={analysis.security_assessment.findings} /></Section><Section eyebrow="Weighted posture" title="Threat / risk matrix"><ThreatMatrix entries={analysis.risk_assessment.threat_risk_matrix} /></Section>
  </div>
}

function Field({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: string[] }) { return <label className="field"><span>{label}</span><select value={value} onChange={(event) => onChange(event.target.value)}><option value="">Unavailable</option>{options.map((option) => <option key={option} value={option}>{option}</option>)}</select></label> }
function Fact({ label, value, observation }: { label: string; value?: unknown; observation?: Observation<any> }) { return <div className="fact"><span>{label}</span>{observation ? <ObservationValue observation={observation} /> : value === null || value === undefined || value === '' ? <ObservationValue /> : <span className="value-wrap"><strong>{String(value)}</strong><StatusPill status="observed" /></span>}</div> }
function formatBytes(bytes: number) { return `${(bytes / 1024 / 1024).toFixed(2)} MB` }

export default App
