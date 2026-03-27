import React, { useMemo } from 'react'
import { ArrowRight, AlertTriangle } from 'lucide-react'
import type { DNSLog } from '../types'

interface Props {
  logs: DNSLog[]
}

export const DNSTraffic: React.FC<Props> = ({ logs }) => {
  const groupedByDomain = useMemo(() => {
    const groups: Record<string, {
      requests: number
      responses: number
      ips: Set<string>
      sources: Set<string>
      alert: boolean
      reasons: string[]
      queryTypes: Set<string>
      lastSeen: string
    }> = {}

    logs.slice(0, 80).forEach(log => {
      if (log.domain === 'unknown') return
      if (!groups[log.domain]) {
        groups[log.domain] = {
          requests: 0,
          responses: 0,
          ips: new Set(),
          sources: new Set(),
          alert: false,
          reasons: [],
          queryTypes: new Set(),
          lastSeen: '',
        }
      }
      const g = groups[log.domain]
      g.requests++
      if (log.response_code === 'NOERROR') g.responses++
      if (log.dest_ip) g.ips.add(log.dest_ip)
      if (log.src_ip) g.sources.add(log.src_ip)
      g.queryTypes.add(log.query_type)
      g.lastSeen = log.timestamp
      if (log.alert_level === 'alert') {
        g.alert = true
        if (log.alert_reason) g.reasons.push(log.alert_reason)
      }
    })

    return Object.entries(groups)
      .sort(([, a], [, b]) => (b.alert ? 1 : 0) - (a.alert ? 1 : 0) || b.requests - a.requests)
      .slice(0, 20)
  }, [logs])

  return (
    <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
      {groupedByDomain.length === 0 ? (
        <div className="text-surface-500 text-center py-12 text-sm">Waiting for DNS traffic...</div>
      ) : (
        groupedByDomain.map(([domain, data]) => (
          <div
            key={domain}
            className={`card-compact p-3 transition-colors ${
              data.alert
                ? 'bg-red-500/5 border-red-500/20 hover:border-red-500/40'
                : 'hover:border-surface-600'
            }`}
          >
            <div className="flex items-center justify-between mb-1.5">
              <div className="flex items-center gap-2 min-w-0">
                {data.alert && <AlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />}
                <span className={`text-sm font-medium truncate ${data.alert ? 'text-red-400' : 'text-surface-200'}`}>
                  {domain}
                </span>
              </div>
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                data.alert
                  ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                  : 'bg-green-500/10 text-green-400/70 border border-green-500/20'
              }`}>
                {data.alert ? 'Threat' : 'Clean'}
              </span>
            </div>

            <div className="flex items-center gap-4 text-xs text-surface-400">
              <span>Queries: <span className="text-brand-400">{data.requests}</span></span>
              <span>OK: <span className="text-green-400">{data.responses}</span></span>
              <span>IPs: <span className="text-purple-400">{data.ips.size}</span></span>
              <span>Sources: <span className="text-cyan-400">{data.sources.size}</span></span>
              <span className="flex items-center gap-1">
                {Array.from(data.queryTypes).map(qt => (
                  <span key={qt} className="px-1 py-0.5 rounded bg-surface-700/30 text-[10px] font-mono">
                    {qt}
                  </span>
                ))}
              </span>
            </div>

            {data.alert && data.reasons.length > 0 && (
              <div className="mt-2 text-xs text-red-400/80 pl-5 border-l-2 border-red-500/30 truncate">
                {data.reasons[data.reasons.length - 1]}
              </div>
            )}
          </div>
        ))
      )}
    </div>
  )
}
