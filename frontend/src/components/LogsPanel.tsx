import React from 'react'

interface DNSLog {
  timestamp: string
  domain: string
  src_ip: string
  dest_ip: string
  query_type: string
  ttl: number
  alert_level: string
  alert_reason: string
}

interface LogsPanelProps {
  logs: DNSLog[]
}

export const LogsPanel: React.FC<LogsPanelProps> = ({ logs }) => {
  return (
    <div className="border border-gray-700 p-6 bg-black">
      <div className="h-80 overflow-y-auto space-y-3 font-mono text-xs">
        {logs.length === 0 ? (
          <div className="text-gray-500 text-center py-20">// WAITING FOR DNS TRAFFIC...</div>
        ) : (
          logs.map((log, idx) => (
            <div key={idx} className={log.alert_level === 'ALERT' ? 'text-hacker-red' : 'text-hacker-green'}>
              <div className="flex gap-4 mb-1">
                <span className="text-gray-500">[{log.timestamp.split('T')[1]}]</span>
                <span className="text-gray-500">{log.query_type}</span>
                <span className="font-bold">{log.domain}</span>
                <span>{log.alert_level}</span>
              </div>
              {log.alert_level === 'ALERT' && (
                <div className="text-hacker-red text-xs ml-4">→ {log.alert_reason}</div>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  )
}


