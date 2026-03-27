import React, { useState, useMemo, useCallback } from 'react'
import { ChevronDown, ChevronUp, Filter, Shield, Globe, Clock, Server, Wifi, AlertTriangle, CheckCircle } from 'lucide-react'
import type { DNSLog } from '../types'
import { SEVERITY_CONFIG, THREAT_TYPE_LABELS } from '../types'

interface Props {
  logs: DNSLog[]
}

const SOURCE_STYLE: Record<string, string> = {
  etw:      'bg-emerald-500/10 text-emerald-400',
  sniffer:  'bg-green-500/10 text-green-400',
  cache:    'bg-blue-500/10 text-blue-400',
  resolver: 'bg-purple-500/10 text-purple-400',
  simulated:'bg-surface-700/50 text-surface-400',
}

const RCODE_STYLE: Record<string, string> = {
  NOERROR:  'text-green-400',
  NXDOMAIN: 'text-yellow-400',
  QUERY:    'text-blue-400',
}

function formatTime(ts: string) {
  try {
    return new Date(ts).toLocaleTimeString('en-US', { hour12: false })
  } catch {
    return ts.split('T')[1]?.slice(0, 8) || ts
  }
}

function formatTimeFull(ts: string) {
  try {
    return new Date(ts).toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      hour12: false,
    })
  } catch {
    return ts
  }
}

// Memoized row component so unchanged rows don't re-render
const DNSRow = React.memo(function DNSRow({
  log, rowKey, isExpanded, onToggle,
}: {
  log: DNSLog
  rowKey: string
  isExpanded: boolean
  onToggle: (key: string) => void
}) {
  const isAlert = log.alert_level === 'alert'
  const severityCfg = isAlert
    ? SEVERITY_CONFIG[log.severity as keyof typeof SEVERITY_CONFIG] || SEVERITY_CONFIG.info
    : null

  return (
    <React.Fragment>
      {/* ── Main row ── */}
      <tr
        className={`cursor-pointer transition-colors ${
          isAlert ? 'bg-red-500/5 hover:bg-red-500/10' : 'hover:bg-surface-800/50'
        }`}
        onClick={() => onToggle(rowKey)}
      >
        <td className="w-8 text-center">
          {isExpanded
            ? <ChevronUp className="w-3.5 h-3.5 text-surface-400 inline" />
            : <ChevronDown className="w-3.5 h-3.5 text-surface-400 inline" />}
        </td>
        <td className="font-mono text-xs text-surface-400">{formatTime(log.timestamp)}</td>
        <td className={`font-medium max-w-[220px] truncate ${isAlert ? 'text-red-400' : 'text-surface-200'}`}>
          {log.domain}
        </td>
        <td>
          <span className="px-1.5 py-0.5 rounded text-xs font-mono bg-surface-700/50 text-surface-300">
            {log.query_type}
          </span>
        </td>
        <td>
          <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${SOURCE_STYLE[log.source] || 'bg-surface-700/50 text-surface-400'}`}>
            {log.source || 'unknown'}
          </span>
        </td>
        <td className="font-mono text-xs text-surface-500">{log.dest_ip || '—'}</td>
        <td className="font-mono text-xs text-surface-500">{log.ttl > 0 ? `${log.ttl}s` : '—'}</td>
        <td>
          <span className={`text-xs font-medium ${RCODE_STYLE[log.response_code] || 'text-red-400'}`}>
            {log.response_code}
          </span>
        </td>
        <td>
          {isAlert && severityCfg ? (
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium ${severityCfg.bg} ${severityCfg.text} border ${severityCfg.border}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${severityCfg.dot}`} />
              {severityCfg.label}
            </span>
          ) : (
            <span className="text-xs text-green-400/60">Clean</span>
          )}
        </td>
      </tr>

      {/* ── Expanded details ── */}
      {isExpanded && (
        <tr className={isAlert ? 'bg-red-950/20' : 'bg-surface-800/20'}>
          <td colSpan={9} className="px-6 py-4">
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3 text-xs">

              {/* Query info */}
              <DetailCard icon={<Globe className="w-3.5 h-3.5 text-brand-400" />} title="Query">
                <Row label="Domain"  value={log.domain} mono />
                <Row label="Type"    value={log.query_type} mono />
                <Row label="Source"  value={log.source || '—'} />
                <Row label="Auth"    value={log.is_authoritative ? 'Authoritative' : 'Cached/Non-auth'} />
              </DetailCard>

              {/* Network */}
              <DetailCard icon={<Wifi className="w-3.5 h-3.5 text-blue-400" />} title="Network">
                <Row label="Client IP"  value={log.src_ip  || '—'} mono />
                <Row label="Resolver"   value={log.dest_ip || '—'} mono />
                <Row label="Response"   value={log.response_code}
                  valueClass={RCODE_STYLE[log.response_code] || 'text-red-400'} />
                <Row label="TTL"        value={log.ttl > 0 ? `${log.ttl}s` : '—'} mono />
              </DetailCard>

              {/* Timing */}
              <DetailCard icon={<Clock className="w-3.5 h-3.5 text-surface-400" />} title="Timing">
                <Row label="Timestamp" value={formatTimeFull(log.timestamp)} mono />
              </DetailCard>

              {/* DNS Answers */}
              <DetailCard
                icon={<Server className="w-3.5 h-3.5 text-purple-400" />}
                title={`DNS Records (${log.answers?.length ?? 0})`}
                wide
              >
                {log.answers && log.answers.length > 0 ? (
                  <div className="flex flex-col gap-0.5 mt-1">
                    {log.answers.map((ans, i) => (
                      <span key={i} className="font-mono text-surface-300 bg-surface-900/60 px-2 py-0.5 rounded">
                        {ans}
                      </span>
                    ))}
                  </div>
                ) : (
                  <span className="text-surface-500">No records</span>
                )}
              </DetailCard>

              {/* Threat info (alerts only) */}
              {isAlert && severityCfg && (
                <DetailCard
                  icon={<AlertTriangle className={`w-3.5 h-3.5 ${severityCfg.text}`} />}
                  title="Threat Intelligence"
                  wide
                  alert
                >
                  <Row label="Threat Type"
                    value={THREAT_TYPE_LABELS[log.threat_type] || log.threat_type || '—'}
                    valueClass="text-red-400 font-medium" />
                  <Row label="Severity"
                    value={severityCfg.label}
                    valueClass={severityCfg.text} />
                  <Row label="Confidence"
                    value={`${(log.confidence * 100).toFixed(0)}%`}
                    valueClass="text-yellow-400" />
                  <Row label="Reason" value={log.alert_reason || '—'} />
                </DetailCard>
              )}

              {/* Clean indicator (non-alerts) */}
              {!isAlert && (
                <DetailCard icon={<CheckCircle className="w-3.5 h-3.5 text-green-400" />} title="Status">
                  <span className="text-green-400 font-medium">No threats detected</span>
                </DetailCard>
              )}

            </div>
          </td>
        </tr>
      )}
    </React.Fragment>
  )
})

// Small helpers for the detail panel
function DetailCard({
  icon, title, children, wide, alert,
}: {
  icon: React.ReactNode
  title: string
  children: React.ReactNode
  wide?: boolean
  alert?: boolean
}) {
  return (
    <div className={`rounded-lg border px-3 py-2.5 ${
      alert
        ? 'bg-red-950/30 border-red-500/20'
        : 'bg-surface-900/60 border-surface-700/40'
    } ${wide ? 'md:col-span-2 xl:col-span-1' : ''}`}>
      <div className="flex items-center gap-1.5 mb-2">
        {icon}
        <span className="text-[10px] font-semibold text-surface-400 uppercase tracking-wider">{title}</span>
      </div>
      <div className="flex flex-col gap-1">{children}</div>
    </div>
  )
}

function Row({ label, value, mono, valueClass }: {
  label: string; value: string; mono?: boolean; valueClass?: string
}) {
  return (
    <div className="flex items-start justify-between gap-2">
      <span className="text-surface-500 shrink-0">{label}</span>
      <span className={`${mono ? 'font-mono' : ''} ${valueClass || 'text-surface-300'} text-right break-all`}>
        {value}
      </span>
    </div>
  )
}

const FILTERS = ['all', 'alerts', 'clean', 'A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT'] as const

export const LiveDNSTable: React.FC<Props> = ({ logs }) => {
  const [expandedKey, setExpandedKey] = useState<string | null>(null)
  const [filter, setFilter] = useState<string>('all')
  const [page, setPage] = useState(0)

  const PAGE_SIZE = 100

  const filteredLogs = useMemo(() => {
    if (filter === 'all')    return logs
    if (filter === 'alerts') return logs.filter(l => l.alert_level === 'alert')
    if (filter === 'clean')  return logs.filter(l => l.alert_level !== 'alert')
    return logs.filter(l => l.query_type === filter)
  }, [logs, filter])

  const pageCount = Math.max(1, Math.ceil(filteredLogs.length / PAGE_SIZE))
  const clampedPage = Math.min(page, pageCount - 1)
  const displayLogs = useMemo(
    () => filteredLogs.slice(clampedPage * PAGE_SIZE, (clampedPage + 1) * PAGE_SIZE),
    [filteredLogs, clampedPage]
  )

  const handleToggle = useCallback((key: string) => {
    setExpandedKey(prev => prev === key ? null : key)
  }, [])

  const handleFilter = useCallback((f: string) => {
    setFilter(f)
    setPage(0)
    setExpandedKey(null)
  }, [])

  return (
    <div className="card overflow-hidden">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-2 px-4 py-3 border-b border-surface-700/50">
        <Filter className="w-4 h-4 text-surface-400 shrink-0" />
        <div className="flex flex-wrap gap-1.5">
          {FILTERS.map(f => (
            <button
              key={f}
              onClick={() => handleFilter(f)}
              className={`px-2.5 py-1 rounded-md text-xs font-medium transition-colors ${
                filter === f
                  ? 'bg-brand-500/20 text-brand-400 border border-brand-500/30'
                  : 'text-surface-400 hover:text-surface-200 hover:bg-surface-700/50'
              }`}
            >
              {f === 'all' ? 'All' : f === 'alerts' ? 'Alerts' : f === 'clean' ? 'Clean' : f}
            </button>
          ))}
        </div>
        <span className="ml-auto text-xs text-surface-500 shrink-0">
          {filteredLogs.length.toLocaleString()} entries
        </span>
      </div>

      {/* Table */}
      <div className="overflow-y-auto max-h-[600px]">
        <table className="dns-table">
          <thead className="sticky top-0 bg-surface-900/95 backdrop-blur z-10">
            <tr>
              <th className="w-8"></th>
              <th>Time</th>
              <th>Domain</th>
              <th>Type</th>
              <th>Source</th>
              <th>Resolver</th>
              <th>TTL</th>
              <th>Response</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {displayLogs.length === 0 ? (
              <tr>
                <td colSpan={9} className="text-center py-12 text-surface-500">
                  Waiting for DNS traffic...
                </td>
              </tr>
            ) : (
              displayLogs.map((log, idx) => {
                const rowKey = `${log.timestamp}-${log.domain}-${clampedPage * PAGE_SIZE + idx}`
                return (
                  <DNSRow
                    key={rowKey}
                    log={log}
                    rowKey={rowKey}
                    isExpanded={expandedKey === rowKey}
                    onToggle={handleToggle}
                  />
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {pageCount > 1 && (
        <div className="flex items-center justify-between px-4 py-2 border-t border-surface-700/50 text-xs text-surface-500">
          <button
            onClick={() => setPage(p => Math.max(0, p - 1))}
            disabled={clampedPage === 0}
            className="px-3 py-1 rounded bg-surface-800 hover:bg-surface-700 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            ← Prev
          </button>
          <span>
            Page {clampedPage + 1} / {pageCount}
            &nbsp;·&nbsp;
            showing {clampedPage * PAGE_SIZE + 1}–{Math.min((clampedPage + 1) * PAGE_SIZE, filteredLogs.length)} of {filteredLogs.length.toLocaleString()}
          </span>
          <button
            onClick={() => setPage(p => Math.min(pageCount - 1, p + 1))}
            disabled={clampedPage >= pageCount - 1}
            className="px-3 py-1 rounded bg-surface-800 hover:bg-surface-700 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            Next →
          </button>
        </div>
      )}
    </div>
  )
}
