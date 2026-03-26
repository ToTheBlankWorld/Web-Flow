import React from 'react'

interface DNSLog {
  timestamp: string
  domain: string
  alert_reason: string
  severity: string
  ttl: number
  src_ip: string
  dest_ip: string
}

export const ThreatIntelligence: React.FC<{ alerts: DNSLog[] }> = ({ alerts }) => {
  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'critical':
        return '🔴'
      case 'warning':
        return '🟠'
      default:
        return '🟡'
    }
  }

  const getThreatType = (reason: string) => {
    if (reason.includes('Fast-flux')) return 'FAST-FLUX'
    if (reason.includes('Low TTL')) return 'CACHE POISON'
    if (reason.includes('Suspicious')) return 'SUSPICIOUS'
    if (reason.includes('NXDOMAIN')) return 'HIJACKING'
    return 'ANOMALY'
  }

  return (
    <div className="space-y-3 max-h-96 overflow-y-auto">
      {alerts.length === 0 ? (
        <div className="text-gray-600 text-center py-12">No threats detected - System secure</div>
      ) : (
        alerts.slice(0, 20).map((alert, idx) => (
          <div key={idx} className="border border-hacker-red bg-red-950/20 rounded p-3">
            <div className="flex justify-between items-start mb-2">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span>{getSeverityIcon(alert.severity)}</span>
                  <span className="font-bold text-hacker-red">{getThreatType(alert.alert_reason)}</span>
                  <span className="text-xs text-gray-500">{alert.severity.toUpperCase()}</span>
                </div>
                <div className="text-sm font-bold text-white">{alert.domain}</div>
              </div>
              <div className="text-xs text-gray-500">{alert.timestamp.split('T')[1].slice(0, 8)}</div>
            </div>

            <div className="text-xs text-gray-400 mb-2">{alert.alert_reason}</div>

            <div className="text-xs text-gray-600 flex gap-4">
              <span>📤 {alert.src_ip}</span>
              <span>→</span>
              <span>📥 {alert.dest_ip}</span>
            </div>
          </div>
        ))
      )}
    </div>
  )
}
