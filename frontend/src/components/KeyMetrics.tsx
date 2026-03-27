import React from 'react'
import { Activity, Shield, AlertTriangle, Globe, Users, Zap } from 'lucide-react'
import type { Stats } from '../types'

export const KeyMetrics: React.FC<{ stats: Stats }> = ({ stats }) => {
  const metrics = [
    {
      label: 'Total Queries',
      value: stats.totalQueries.toLocaleString(),
      icon: Activity,
      color: 'text-brand-400',
      bgColor: 'bg-brand-500/10',
      borderColor: 'border-brand-500/20',
    },
    {
      label: 'Threats Detected',
      value: stats.totalAlerts.toLocaleString(),
      icon: AlertTriangle,
      color: 'text-red-400',
      bgColor: 'bg-red-500/10',
      borderColor: 'border-red-500/20',
    },
    {
      label: 'Threat Rate',
      value: `${stats.alertRate.toFixed(1)}%`,
      icon: Shield,
      color: stats.alertRate > 10 ? 'text-red-400' : stats.alertRate > 5 ? 'text-yellow-400' : 'text-green-400',
      bgColor: stats.alertRate > 10 ? 'bg-red-500/10' : stats.alertRate > 5 ? 'bg-yellow-500/10' : 'bg-green-500/10',
      borderColor: stats.alertRate > 10 ? 'border-red-500/20' : stats.alertRate > 5 ? 'border-yellow-500/20' : 'border-green-500/20',
    },
    {
      label: 'Unique Domains',
      value: stats.uniqueDomains.toLocaleString(),
      icon: Globe,
      color: 'text-purple-400',
      bgColor: 'bg-purple-500/10',
      borderColor: 'border-purple-500/20',
    },
    {
      label: 'Queries/min',
      value: stats.queriesPerMinute.toLocaleString(),
      icon: Zap,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-500/10',
      borderColor: 'border-cyan-500/20',
    },
    {
      label: 'Active Sessions',
      value: stats.activeConnections.toLocaleString(),
      icon: Users,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-500/10',
      borderColor: 'border-emerald-500/20',
    },
  ]

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      {metrics.map((metric) => (
        <div
          key={metric.label}
          className={`card p-4 ${metric.bgColor} border ${metric.borderColor}`}
        >
          <div className="flex items-center gap-2 mb-3">
            <metric.icon className={`w-4 h-4 ${metric.color}`} />
            <span className="text-xs font-medium text-surface-400">{metric.label}</span>
          </div>
          <div className={`text-2xl font-bold ${metric.color}`}>
            {metric.value}
          </div>
        </div>
      ))}
    </div>
  )
}
