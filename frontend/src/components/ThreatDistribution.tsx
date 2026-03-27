import React from 'react'
import type { Stats } from '../types'
import { THREAT_TYPE_LABELS } from '../types'

interface Props {
  stats: Stats
}

const THREAT_COLORS: Record<string, string> = {
  fast_flux: 'bg-red-400',
  cache_poisoning: 'bg-orange-400',
  dga_domain: 'bg-purple-400',
  dns_tunneling: 'bg-cyan-400',
  rogue_nameserver: 'bg-yellow-400',
  suspicious_tld: 'bg-pink-400',
  malicious_domain: 'bg-rose-400',
}

const THREAT_TEXT_COLORS: Record<string, string> = {
  fast_flux: 'text-red-400',
  cache_poisoning: 'text-orange-400',
  dga_domain: 'text-purple-400',
  dns_tunneling: 'text-cyan-400',
  rogue_nameserver: 'text-yellow-400',
  suspicious_tld: 'text-pink-400',
  malicious_domain: 'text-rose-400',
}

export const ThreatDistribution: React.FC<Props> = ({ stats }) => {
  const threats = Object.entries(stats.threatsByType)
    .sort(([, a], [, b]) => b - a)

  const totalThreats = threats.reduce((sum, [, count]) => sum + count, 0)

  const queryTypes = Object.entries(stats.queriesByType)
    .sort(([, a], [, b]) => b - a)

  const totalQueries = queryTypes.reduce((sum, [, count]) => sum + count, 0)

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Threat Types */}
      <div className="card p-4">
        <h3 className="text-sm font-semibold text-surface-200 mb-4">Threats by Type</h3>
        {threats.length === 0 ? (
          <p className="text-surface-500 text-xs text-center py-4">No threats recorded</p>
        ) : (
          <div className="space-y-3">
            {threats.map(([type, count]) => {
              const pct = totalThreats > 0 ? (count / totalThreats) * 100 : 0
              const barColor = THREAT_COLORS[type] || 'bg-surface-400'
              const textColor = THREAT_TEXT_COLORS[type] || 'text-surface-400'

              return (
                <div key={type}>
                  <div className="flex items-center justify-between mb-1">
                    <span className={`text-xs font-medium ${textColor}`}>
                      {THREAT_TYPE_LABELS[type] || type}
                    </span>
                    <span className="text-xs text-surface-400">{count} ({pct.toFixed(1)}%)</span>
                  </div>
                  <div className="w-full bg-surface-700/30 rounded-full h-1.5">
                    <div
                      className={`h-1.5 rounded-full ${barColor} transition-all duration-500`}
                      style={{ width: `${Math.max(pct, 2)}%` }}
                    ></div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Query Types */}
      <div className="card p-4">
        <h3 className="text-sm font-semibold text-surface-200 mb-4">Queries by Record Type</h3>
        {queryTypes.length === 0 ? (
          <p className="text-surface-500 text-xs text-center py-4">No queries recorded</p>
        ) : (
          <div className="space-y-3">
            {queryTypes.map(([type, count]) => {
              const pct = totalQueries > 0 ? (count / totalQueries) * 100 : 0
              return (
                <div key={type}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs font-medium text-surface-300">{type}</span>
                    <span className="text-xs text-surface-400">{count} ({pct.toFixed(1)}%)</span>
                  </div>
                  <div className="w-full bg-surface-700/30 rounded-full h-1.5">
                    <div
                      className="h-1.5 rounded-full bg-brand-400 transition-all duration-500"
                      style={{ width: `${Math.max(pct, 2)}%` }}
                    ></div>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
