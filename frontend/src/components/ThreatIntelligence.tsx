import React from 'react'
import { AlertTriangle, Shield, ExternalLink, Clock } from 'lucide-react'
import type { ThreatAlert } from '../types'
import { SEVERITY_CONFIG, THREAT_TYPE_LABELS } from '../types'

interface Props {
  alerts: ThreatAlert[]
}

export const ThreatIntelligence: React.FC<Props> = ({ alerts }) => {
  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString('en-US', { hour12: false })
    } catch {
      return ts
    }
  }

  const getThreatIcon = (type: string) => {
    switch (type) {
      case 'fast_flux': return '🔄'
      case 'cache_poisoning': return '💉'
      case 'dga_domain': return '🤖'
      case 'dns_tunneling': return '🕳️'
      case 'rogue_nameserver': return '👤'
      case 'suspicious_tld': return '🔗'
      case 'malicious_domain': return '☠️'
      default: return '⚠️'
    }
  }

  if (alerts.length === 0) {
    return (
      <div className="card p-8 text-center">
        <Shield className="w-12 h-12 text-green-400/30 mx-auto mb-3" />
        <p className="text-surface-400">No threats detected</p>
        <p className="text-surface-500 text-xs mt-1">System is monitoring DNS traffic</p>
      </div>
    )
  }

  return (
    <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
      {alerts.slice(0, 30).map((alert) => {
        const config = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.info

        return (
          <div
            key={alert.id}
            className={`card p-4 animate-slide-up ${config.bg} border ${config.border}`}
          >
            {/* Header */}
            <div className="flex items-start justify-between mb-3">
              <div className="flex items-center gap-2">
                <span className="text-lg">{getThreatIcon(alert.threat_type)}</span>
                <div>
                  <span className={`text-xs font-semibold ${config.text} uppercase tracking-wide`}>
                    {THREAT_TYPE_LABELS[alert.threat_type] || alert.threat_type}
                  </span>
                  <div className="text-sm font-semibold text-surface-200 mt-0.5">{alert.domain}</div>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${config.bg} ${config.text} border ${config.border}`}>
                  {config.label}
                </span>
              </div>
            </div>

            {/* Description */}
            <p className="text-xs text-surface-400 mb-3">{alert.description}</p>

            {/* Indicators */}
            {Object.keys(alert.indicators).length > 0 && (
              <div className="bg-surface-900/50 rounded-lg p-3 mb-3">
                <div className="text-xs font-medium text-surface-400 mb-2">Indicators</div>
                <div className="grid grid-cols-2 gap-2">
                  {Object.entries(alert.indicators).slice(0, 6).map(([key, value]) => (
                    <div key={key} className="text-xs">
                      <span className="text-surface-500">{key.replace(/_/g, ' ')}: </span>
                      <span className="text-surface-300 font-mono">
                        {typeof value === 'object' ? JSON.stringify(value).slice(0, 40) : String(value).slice(0, 40)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Footer */}
            <div className="flex items-center justify-between text-xs">
              <div className="flex items-center gap-4 text-surface-500">
                <span className="flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {formatTime(alert.timestamp)}
                </span>
                <span>Confidence: <span className={config.text}>{(alert.confidence * 100).toFixed(0)}%</span></span>
              </div>
              <div className="flex items-center gap-3 text-surface-500">
                <span>{alert.src_ip}</span>
                <span className="text-surface-600">→</span>
                <span>{alert.dest_ip}</span>
              </div>
            </div>

            {/* Recommended action */}
            {alert.recommended_action && (
              <div className="mt-3 pt-3 border-t border-surface-700/30">
                <div className="flex items-start gap-2 text-xs">
                  <ExternalLink className="w-3 h-3 text-brand-400 mt-0.5 flex-shrink-0" />
                  <span className="text-surface-400">{alert.recommended_action}</span>
                </div>
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}
