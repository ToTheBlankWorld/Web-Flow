import React from 'react'
import { Clock } from 'lucide-react'
import type { ThreatAlert } from '../types'
import { SEVERITY_CONFIG, THREAT_TYPE_LABELS } from '../types'

interface Props {
  alerts: ThreatAlert[]
}

export const DetectionTimeline: React.FC<Props> = ({ alerts }) => {
  const formatTime = (ts: string) => {
    try {
      return new Date(ts).toLocaleTimeString('en-US', { hour12: false })
    } catch {
      return ts
    }
  }

  if (alerts.length === 0) {
    return (
      <div className="card p-8 text-center">
        <Clock className="w-12 h-12 text-surface-500/30 mx-auto mb-3" />
        <p className="text-surface-400">No detection events yet</p>
      </div>
    )
  }

  return (
    <div className="card p-4 max-h-[600px] overflow-y-auto">
      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-[11px] top-2 bottom-2 w-0.5 bg-surface-700/50"></div>

        <div className="space-y-1">
          {alerts.slice(0, 25).map((alert, idx) => {
            const config = SEVERITY_CONFIG[alert.severity] || SEVERITY_CONFIG.info

            return (
              <div key={alert.id || idx} className="relative flex gap-3 py-2 animate-fade-in">
                {/* Timeline dot */}
                <div className="relative z-10 flex-shrink-0 mt-1">
                  <div className={`w-[10px] h-[10px] rounded-full ${config.dot} ring-2 ring-surface-900`}></div>
                </div>

                {/* Content */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className={`text-xs font-semibold ${config.text}`}>
                      {THREAT_TYPE_LABELS[alert.threat_type] || alert.threat_type}
                    </span>
                    <span className="text-[10px] text-surface-500">{formatTime(alert.timestamp)}</span>
                  </div>
                  <div className="text-sm text-surface-200 truncate">{alert.domain}</div>
                  <div className="text-xs text-surface-500 mt-0.5 truncate">{alert.description}</div>
                </div>

                {/* Severity badge */}
                <div className="flex-shrink-0">
                  <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${config.bg} ${config.text}`}>
                    {(alert.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
