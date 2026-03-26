import React from 'react'

interface DNSLog {
  timestamp: string
  domain: string
  src_ip: string
  dest_ip: string
  query_type: string
  ttl: number
  response_code: string
  alert_level: string
  alert_reason: string
}

export const DNSTraffic: React.FC<{ logs: DNSLog[] }> = ({ logs }) => {
  // Filter and group requests and responses
  const filteredLogs = logs.slice(0, 50).filter(log => log.domain !== 'unknown')

  const groupedByDomain = filteredLogs.reduce((acc: any, log) => {
    const key = log.domain
    if (!acc[key]) {
      acc[key] = { requests: 0, responses: 0, ips: new Set(), alert: false, reason: '' }
    }
    if (log.response_code === 'NOERROR' || log.response_code) {
      acc[key].responses++
      acc[key].ips.add(log.dest_ip)
    } else {
      acc[key].requests++
    }
    if (log.alert_level === 'ALERT') {
      acc[key].alert = true
      acc[key].reason = log.alert_reason
    }
    return acc
  }, {})

  return (
    <div className="space-y-3 max-h-96 overflow-y-auto">
      {Object.entries(groupedByDomain).length === 0 ? (
        <div className="text-gray-600 text-center py-12">Waiting for DNS traffic...</div>
      ) : (
        Object.entries(groupedByDomain).map(([domain, data]: any, idx) => (
          <div
            key={idx}
            className={`border rounded p-4 transition ${
              data.alert
                ? 'border-hacker-red bg-red-950/10'
                : 'border-gray-700 bg-gray-950/30 hover:border-hacker-green'
            }`}
          >
            <div className="flex justify-between items-start mb-2">
              <div className="flex-1">
                <div className={`font-bold text-lg ${data.alert ? 'text-hacker-red' : 'text-hacker-green'}`}>
                  {data.alert && '🚨 '} {domain}
                </div>
                <div className="text-xs text-gray-500 mt-1">
                  Requests: <span className="text-hacker-blue">{data.requests}</span> | Responses: <span className="text-hacker-green">{data.responses}</span> | IPs: <span className="text-yellow-400">{data.ips.size}</span>
                </div>
              </div>
              <div className="text-right">
                <div className={`text-xs px-2 py-1 rounded ${data.alert ? 'bg-hacker-red/30 text-hacker-red' : 'bg-gray-700 text-gray-300'}`}>
                  {data.alert ? 'THREAT' : 'CLEAN'}
                </div>
              </div>
            </div>

            {data.alert && (
              <div className="text-xs text-hacker-red mt-2 pl-2 border-l-2 border-hacker-red">
                ⚠️ {data.reason}
              </div>
            )}
          </div>
        ))
      )}
    </div>
  )
}
