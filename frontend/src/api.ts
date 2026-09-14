export type Status = 'observed' | 'inferred' | 'unavailable'

export interface Observation<T = unknown> {
  status: Status
  value: T | null
  notes?: string | null
}

export interface CaptureInfo {
  capture_id: string
  filename: string
  size_bytes: number
}

export interface AnalysisResponse {
  capture_id: string
  vpn_configuration: Record<string, unknown>
  packet_analysis: any
  features: any
  prediction: {
    predicted_traffic_type: Observation<string>
    confidence: Observation<number>
    model_version: Observation<string>
  }
  security_assessment: {
    findings: Array<{
      rule_id: string
      category: string
      severity: string
      title: string
      evidence: string
      explanation: string
      recommendation: string
      status: Status
    }>
  }
  risk_assessment: {
    overall_score: number | null
    risk_level: string
    score_status: string
    known_weight: number
    category_scores: Array<{
      category: string
      weight: number
      score: number | null
      status: string
      evidence: string[]
    }>
    threat_risk_matrix: Array<{
      category: string
      security_score: number | null
      risk_level: string
      likelihood: number | null
      impact: number
      status: string
      evidence: string[]
    }>
    evidence: string[]
  }
  metadata_inference: {
    ipsec_detected: Observation<boolean>
    ike_version: Observation<number>
    source_ip: Observation<string>
    destination_ip: Observation<string>
    flow_direction: Observation<string>
    encrypted_payload_contents: Observation<null>
  }
}

const apiBase = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${apiBase}${path}`, init)
  if (!response.ok) {
    let detail = `Request failed (${response.status})`
    try {
      const body = await response.json()
      detail = body.detail ?? detail
    } catch {
      // Keep the HTTP status when the server did not return JSON.
    }
    throw new Error(detail)
  }
  return response.json() as Promise<T>
}

export function listCaptures(): Promise<CaptureInfo[]> {
  return request<CaptureInfo[]>('/api/v1/captures')
}

export function uploadCapture(file: File): Promise<{ capture_id: string; filename: string; size_bytes: number }> {
  const body = new FormData()
  body.append('file', file)
  return request('/api/v1/captures', { method: 'POST', body })
}

export function analyzeCapture(captureId: string, vpnConfiguration: Record<string, unknown>): Promise<AnalysisResponse> {
  return request<AnalysisResponse>(`/api/v1/captures/${captureId}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ vpn_configuration: vpnConfiguration }),
  })
}
