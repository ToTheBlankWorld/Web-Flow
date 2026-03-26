import React, { useMemo } from 'react'

interface DNSLog {
  domain: string
  ttl: number
  alert_level: string
  src_ip: string
}

interface DomainAnalysisProps {
  logs: DNSLog[]
}

interface DomainStats {
  domain: string
  count: number
  latestTTL: number
  alertCount: number
  uniqueIPs: Set<string>
  riskScore: number
}

export const DomainAnalysis: React.FC<DomainAnalysisProps> = ({ logs }) => {
  const domainStats = useMemo(() => {
    const stats: Map<string, DomainStats> = new Map()

    logs.forEach((log) => {
      if (!stats.has(log.domain)) {
        stats.set(log.domain, {
          domain: log.domain,
          count: 0,
          latestTTL: 0,
          alertCount: 0,
          uniqueIPs: new Set(),
          riskScore: 0,
        })
      }

      const stat = stats.get(log.domain)!
      stat.count++
      stat.latestTTL = log.ttl
      stat.uniqueIPs.add(log.src_ip)

      if (log.alert_level === 'ALERT') {
        stat.alertCount++
      }

      let score = 0
      if (log.ttl > 0 && log.ttl < 60) score += 20
      if (stat.uniqueIPs.size > 3) score += 30
      score += stat.alertCount * 10

      stat.riskScore = Math.min(score, 100)
    })

    return Array.from(stats.values())
      .sort((a, b) => b.riskScore - a.riskScore)
      .slice(0, 8)
  }, [logs])

  const getRiskColor = (score: number): string => {
    if (score > 70) return 'text-hacker-red'
    if (score > 40) return 'text-yellow-400'
    return 'text-hacker-green'
  }

  return (
    <div className="space-y-4">
      {domainStats.length === 0 ? (
        <div className="text-gray-500 text-center py-8">Analyzing domains...</div>
      ) : (
        domainStats.map((stat, idx) => (
          <div key={idx} className="border border-gray-700 p-4 hover:border-hacker-blue transition">
            <div className="flex justify-between items-start mb-2">
              <div>
                <div className="font-bold text-lg text-white">{stat.domain}</div>
                <div className="text-xs text-gray-500 mt-1">
                  Queries: {stat.count} | IPs: {stat.uniqueIPs.size} | Alerts: {stat.alertCount}
                </div>
              </div>
              <div className={`text-4xl font-black ${getRiskColor(stat.riskScore)}`}>
                {stat.riskScore}
              </div>
            </div>

            {/* Risk bar */}
            <div className="w-full bg-gray-800 h-1 mt-3">
              <div
                className={`h-1 transition-all ${getRiskColor(stat.riskScore).replace('text-', 'bg-')}`}
                style={{ width: `${stat.riskScore}%` }}
              ></div>
            </div>

            {/* Warnings */}
            {stat.latestTTL > 0 && stat.latestTTL < 60 && (
              <div className="text-xs text-hacker-red mt-2">⚠️ Low TTL: {stat.latestTTL}s</div>
            )}
            {stat.uniqueIPs.size > 3 && (
              <div className="text-xs text-hacker-red mt-1">🔄 Fast-Flux: {stat.uniqueIPs.size} IPs</div>
            )}
          </div>
        ))
      )}
    </div>
  )
}
