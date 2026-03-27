import React, { useMemo } from 'react'
import { Globe, AlertTriangle, Clock, Server } from 'lucide-react'
import type { DNSLog } from '../types'

interface Props {
  logs: DNSLog[]
}

interface DomainStats {
  domain: string
  queryCount: number
  alertCount: number
  latestTTL: number
  minTTL: number
  maxTTL: number
  uniqueIPs: Set<string>
  uniqueSources: Set<string>
  queryTypes: Set<string>
  responseCodes: Set<string>
  riskScore: number
  lastSeen: string
  threatTypes: Set<string>
}

export const DomainAnalysis: React.FC<Props> = ({ logs }) => {
  const domainStats = useMemo(() => {
    const stats: Map<string, DomainStats> = new Map()

    logs.forEach((log) => {
      if (log.domain === 'unknown') return

      if (!stats.has(log.domain)) {
        stats.set(log.domain, {
          domain: log.domain,
          queryCount: 0,
          alertCount: 0,
          latestTTL: 0,
          minTTL: Infinity,
          maxTTL: 0,
          uniqueIPs: new Set(),
          uniqueSources: new Set(),
          queryTypes: new Set(),
          responseCodes: new Set(),
          riskScore: 0,
          lastSeen: '',
          threatTypes: new Set(),
        })
      }

      const stat = stats.get(log.domain)!
      stat.queryCount++
      stat.latestTTL = log.ttl
      if (log.ttl > 0) {
        stat.minTTL = Math.min(stat.minTTL, log.ttl)
        stat.maxTTL = Math.max(stat.maxTTL, log.ttl)
      }
      stat.uniqueSources.add(log.src_ip)
      stat.queryTypes.add(log.query_type)
      stat.responseCodes.add(log.response_code)
      stat.lastSeen = log.timestamp

      if (log.answers) {
        log.answers.forEach(ip => stat.uniqueIPs.add(ip))
      }

      if (log.alert_level === 'alert') {
        stat.alertCount++
        if (log.threat_type) stat.threatTypes.add(log.threat_type)
      }

      // Calculate risk score
      let score = 0
      if (stat.alertCount > 0) score += Math.min(stat.alertCount * 8, 40)
      if (stat.minTTL < 30 && stat.minTTL > 0) score += 15
      if (stat.uniqueIPs.size > 4) score += 20
      if (stat.maxTTL - stat.minTTL > 200 && stat.minTTL !== Infinity) score += 10
      if (stat.threatTypes.size > 1) score += 15
      stat.riskScore = Math.min(score, 100)
    })

    return Array.from(stats.values())
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 12)
  }, [logs])

  const getRiskColor = (score: number) => {
    if (score >= 70) return { text: 'text-red-400', bg: 'bg-red-400', bar: 'threat-bar-critical' }
    if (score >= 40) return { text: 'text-orange-400', bg: 'bg-orange-400', bar: 'threat-bar-high' }
    if (score >= 20) return { text: 'text-yellow-400', bg: 'bg-yellow-400', bar: 'threat-bar-medium' }
    return { text: 'text-green-400', bg: 'bg-green-400', bar: 'threat-bar-low' }
  }

  if (domainStats.length === 0) {
    return (
      <div className="card p-8 text-center">
        <Globe className="w-12 h-12 text-surface-500/30 mx-auto mb-3" />
        <p className="text-surface-400">Analyzing domains...</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {domainStats.map((stat) => {
        const risk = getRiskColor(stat.riskScore)

        return (
          <div key={stat.domain} className="card p-4 animate-fade-in">
            <div className="flex items-start justify-between mb-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <h4 className="text-sm font-semibold text-surface-200 truncate">{stat.domain}</h4>
                  {stat.alertCount > 0 && (
                    <AlertTriangle className="w-3.5 h-3.5 text-red-400 flex-shrink-0" />
                  )}
                </div>
                <div className="flex items-center gap-3 mt-1 text-xs text-surface-500">
                  <span>{stat.queryCount} queries</span>
                  <span>{stat.uniqueIPs.size} IPs</span>
                  <span>{stat.alertCount} alerts</span>
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    TTL: {stat.minTTL === Infinity ? '-' : `${stat.minTTL}-${stat.maxTTL}s`}
                  </span>
                </div>
              </div>

              {/* Risk score */}
              <div className="text-right flex-shrink-0 ml-4">
                <div className={`text-2xl font-bold ${risk.text}`}>{stat.riskScore}</div>
                <div className="text-[10px] text-surface-500 uppercase">Risk</div>
              </div>
            </div>

            {/* Risk bar */}
            <div className="w-full bg-surface-700/30 rounded-full h-1.5 mb-2">
              <div
                className={`h-1.5 rounded-full ${risk.bar} transition-all duration-500`}
                style={{ width: `${Math.max(stat.riskScore, 2)}%` }}
              ></div>
            </div>

            {/* Tags */}
            <div className="flex flex-wrap gap-1.5">
              {Array.from(stat.queryTypes).map(qt => (
                <span key={qt} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-surface-700/50 text-surface-400">
                  {qt}
                </span>
              ))}
              {Array.from(stat.threatTypes).map(tt => (
                <span key={tt} className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-red-500/10 text-red-400 border border-red-500/20">
                  {tt.replace(/_/g, ' ')}
                </span>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}
