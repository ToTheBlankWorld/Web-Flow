import React, { useMemo } from 'react'

interface DNSLog {
  query_type: string
  alert_level: string
}

interface DashboardProps {
  logs: DNSLog[]
}

export const Dashboard: React.FC<DashboardProps> = ({ logs }) => {
  const stats = useMemo(() => {
    const queryTypes: { [key: string]: number } = {}

    logs.forEach((log) => {
      queryTypes[log.query_type] = (queryTypes[log.query_type] || 0) + 1
    })

    return {
      queryTypes: Object.entries(queryTypes)
        .map(([type, count]) => ({ type, count }))
        .sort((a, b) => b.count - a.count),
    }
  }, [logs])

  return (
    <div className="space-y-4">
      {stats.queryTypes.length === 0 ? (
        <div className="text-gray-500 text-center py-8">No query data yet...</div>
      ) : (
        stats.queryTypes.map((qt) => (
          <div key={qt.type} className="border border-gray-700 p-6 hover:border-hacker-green transition">
            <div className="text-4xl font-black text-hacker-green mb-2">{qt.count}</div>
            <div className="text-xs text-gray-500">{qt.type}</div>
          </div>
        ))
      )}
    </div>
  )
}


