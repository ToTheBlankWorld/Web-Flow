import React from 'react'

interface DNSLog {
  timestamp: string
  domain: string
  severity: string
  alert_reason: string
}

export const DetectionTimeline: React.FC<{ alerts: DNSLog[] }> = ({ alerts }) => {
  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-hacker-red'
      case 'warning':
        return 'bg-yellow-500'
      default:
        return 'bg-hacker-blue'
    }
  }

  const timelineData = alerts.slice(0, 15).map((alert, idx) => ({
    time: alert.timestamp.split('T')[1].slice(0, 8),
    domain: alert.domain,
    severity: alert.severity,
    reason: alert.alert_reason.split('|')[0].trim(),
  }))

  return (
    <div className="space-y-4 max-h-96 overflow-y-auto">
      {timelineData.length === 0 ? (
        <div className="text-gray-600 text-center py-12">No threat timeline</div>
      ) : (
        timelineData.map((item, idx) => (
          <div key={idx} className="flex gap-4">
            {/* Timeline dot and line */}
            <div className="flex flex-col items-center">
              <div className={`w-3 h-3 rounded-full ${getSeverityColor(item.severity)}`}></div>
              {idx < timelineData.length - 1 && <div className="w-0.5 h-12 bg-gray-700 mt-1"></div>}
            </div>

            {/* Content */}
            <div className="flex-1 pb-4">
              <div className="text-xs text-gray-500 mb-1">{item.time}</div>
              <div className="text-sm font-bold text-white">{item.domain}</div>
              <div className="text-xs text-gray-600 mt-1">{item.reason}</div>
            </div>
          </div>
        ))
      )}
    </div>
  )
}
