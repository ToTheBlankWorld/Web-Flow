import React from 'react'

interface Stats {
  totalQueries: number
  alertRate: string
  totalDomains: number
  activeConnections: number
  threatsBlocked: number
}

export const KeyMetrics: React.FC<{ stats: Stats }> = ({ stats }) => {
  return (
    <div className="border-t border-b border-gray-700 px-12 py-8">
      <div className="grid grid-cols-2 md:grid-cols-5 gap-8">
        <div className="text-center">
          <div className="text-4xl font-black text-hacker-green mb-1">{stats.totalQueries}</div>
          <div className="text-xs text-gray-500">Total Queries</div>
        </div>

        <div className="text-center">
          <div className="text-4xl font-black text-hacker-red mb-1">{stats.threatsBlocked}</div>
          <div className="text-xs text-gray-500">Threats Blocked</div>
        </div>

        <div className="text-center">
          <div className="text-4xl font-black text-hacker-blue mb-1">{stats.alertRate}%</div>
          <div className="text-xs text-gray-500">Threat Rate</div>
        </div>

        <div className="text-center">
          <div className="text-4xl font-black text-yellow-400 mb-1">{stats.totalDomains}</div>
          <div className="text-xs text-gray-500">Unique Domains</div>
        </div>

        <div className="text-center">
          <div className="text-4xl font-black text-cyan-400 mb-1">{stats.activeConnections}</div>
          <div className="text-xs text-gray-500">Active Sessions</div>
        </div>
      </div>
    </div>
  )
}
