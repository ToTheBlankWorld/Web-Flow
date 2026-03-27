export interface DNSLog {
  type: 'dns_log'
  timestamp: string
  domain: string
  src_ip: string
  dest_ip: string
  query_type: string
  ttl: number
  response_code: string
  alert_level: string
  alert_reason: string
  severity: string
  answers: string[]
  threat_type: string
  confidence: number
  source: string          // "sniffer" | "cache" | "resolver" | "eve.json"
  is_authoritative: boolean
}

export interface PhishingInfo {
  is_phishing: boolean
  original_domain: string
  original_org: string
  confidence: number
}

export interface ThreatAlert {
  id: string
  timestamp: string
  domain: string
  threat_type: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  confidence: number
  description: string
  indicators: Record<string, any>
  src_ip: string
  dest_ip: string
  recommended_action: string
  phishing_info?: PhishingInfo  // For phishing alerts
}

export interface ThreatAlertMessage {
  type: 'threat_alert'
  alert: ThreatAlert
}

export interface DNSValidatedMessage {
  type: 'dns_validated'
  domain: string
  status: 'safe' | 'poisoned'
  cached_ips: string[]
  auth_ips: string[]
  changed_ips: string[]
}

export interface DNSFixedMessage {
  type: 'dns_fixed'
  domain: string
  message: string
}

export type WSMessage = DNSLog | ThreatAlertMessage | DNSValidatedMessage | DNSFixedMessage

export interface Stats {
  totalQueries: number
  totalAlerts: number
  queriesPerMinute: number
  uniqueDomains: number
  uniqueSources: number
  activeConnections: number
  alertRate: number
  threatsByType: Record<string, number>
  queriesByType: Record<string, number>
  queriesByResponse: Record<string, number>
}

export interface NotificationItem {
  id: string
  timestamp: string
  title: string
  message: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  domain: string
  read: boolean
  threat_type: string
}

export const SEVERITY_CONFIG = {
  critical: { label: 'Critical', color: 'red', bg: 'bg-red-500/15', text: 'text-red-400', border: 'border-red-500/30', dot: 'bg-red-400' },
  high: { label: 'High', color: 'orange', bg: 'bg-orange-500/15', text: 'text-orange-400', border: 'border-orange-500/30', dot: 'bg-orange-400' },
  medium: { label: 'Medium', color: 'yellow', bg: 'bg-yellow-500/15', text: 'text-yellow-400', border: 'border-yellow-500/30', dot: 'bg-yellow-400' },
  low: { label: 'Low', color: 'green', bg: 'bg-green-500/15', text: 'text-green-400', border: 'border-green-500/30', dot: 'bg-green-400' },
  info: { label: 'Info', color: 'blue', bg: 'bg-blue-500/15', text: 'text-blue-400', border: 'border-blue-500/30', dot: 'bg-blue-400' },
} as const

export const THREAT_TYPE_LABELS: Record<string, string> = {
  fast_flux: 'Fast-Flux Network',
  cache_poisoning: 'Cache Poisoning',
  dga_domain: 'DGA Domain',
  dns_tunneling: 'DNS Tunneling',
  rogue_nameserver: 'Rogue Nameserver',
  suspicious_tld: 'Suspicious TLD',
  malicious_domain: 'Malicious Domain',
  phishing_typosquat: 'Phishing / Typosquat',
}
