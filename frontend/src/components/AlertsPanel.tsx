import React from 'react'

interface DNSLog {
  timestamp: string
  domain: string
  alert_reason: string
  severity: string
}

interface AlertsPanelProps {
  alerts: DNSLog[]
}

export const AlertsPanel: React.FC<AlertsPanelProps> = ({ alerts }) => {
  const getSeverityColor = (severity: string): string => {
    switch (severity) {
      case 'critical':
        return 'text-hacker-red'
      case 'warning':
        return 'text-yellow-400'
      default:
        return 'text-hacker-green'
    }
  }

  return (
    <div className="space-y-4 max-h-96 overflow-y-auto">
      {alerts.length === 0 ? (
        <div className="text-gray-500 text-center py-8">No threats detected</div>
      ) : (
        alerts.map((alert, idx) => (
          <div key={idx} className="border border-gray-700 p-4 hover:border-hacker-red transition">
            <div className={`text-2xl font-black mb-2 ${getSeverityColor(alert.severity)}`}>
              {alert.domain}
            </div>
            <div className="text-xs text-gray-500 mb-2">{alert.timestamp.split('T')[1].slice(0, 8)}</div>
            <div className={`text-xs ${getSeverityColor(alert.severity)}`}>{alert.alert_reason}</div>
          </div>
        ))
      )}
    </div>
  )
}

