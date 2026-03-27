import React, { useEffect, useRef, useState, useCallback } from 'react'
import toast, { Toaster } from 'react-hot-toast'
import {
  Shield, Bell, Volume2, VolumeX, BellRing,
  Activity, LayoutDashboard, Table2,
  AlertTriangle, GitBranch, FileSearch, Globe, CheckCircle, XCircle
} from 'lucide-react'

import { KeyMetrics } from './components/KeyMetrics'
import { LiveDNSTable } from './components/LiveDNSTable'
import { ThreatIntelligence } from './components/ThreatIntelligence'
import { DetectionTimeline } from './components/DetectionTimeline'
import { ThreatDistribution } from './components/ThreatDistribution'
import { DomainAnalysis } from './components/DomainAnalysis'
import { DNSTraffic } from './components/DNSTraffic'
import { NotificationCenter } from './components/NotificationCenter'
import { RecordMonitor } from './components/RecordMonitor'
import { DNSMap } from './components/DNSMap'
import { DomainGraph } from './components/DomainGraph'
import { useNotifications } from './hooks/useNotifications'

import type { DNSLog, ThreatAlert, Stats, DNSValidatedMessage, DNSFixedMessage } from './types'
import { SEVERITY_CONFIG, THREAT_TYPE_LABELS } from './types'

type TabId = 'overview' | 'traffic' | 'threats' | 'domains' | 'records' | 'map' | 'graph'

function App() {
  const [logs, setLogs] = useState<DNSLog[]>([])
  const [alerts, setAlerts] = useState<ThreatAlert[]>([])
  const [stats, setStats] = useState<Stats>({
    totalQueries: 0,
    totalAlerts: 0,
    queriesPerMinute: 0,
    uniqueDomains: 0,
    uniqueSources: 0,
    activeConnections: 0,
    alertRate: 0,
    threatsByType: {},
    queriesByType: {},
    queriesByResponse: {},
  })
  const [connected, setConnected] = useState(false)
  const [activeTab, setActiveTab] = useState<TabId>('overview')
  const [notifPanelOpen, setNotifPanelOpen] = useState(false)
  // Auto-validation results pushed by backend (domain → result)
  const [domainValidations, setDomainValidations] = useState<Record<string, {
    status: 'safe' | 'poisoned'; cached_ips: string[]; auth_ips: string[]; changed_ips: string[]; timestamp: number
  }>>({})
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimeout = useRef<number | null>(null)
  // Buffers so we batch-flush to state every 150 ms instead of re-rendering per event
  const logBuffer = useRef<DNSLog[]>([])
  const alertBuffer = useRef<Array<{ alert: ThreatAlert; toast?: boolean }>>([])
  const flushInterval = useRef<number | null>(null)

  const {
    notifications,
    unreadCount,
    soundEnabled,
    setSoundEnabled,
    browserNotifEnabled,
    requestBrowserPermission,
    addNotification,
    markRead,
    markAllRead,
    clearAll,
  } = useNotifications()

  // WebSocket connection
  const connectWebSocket = useCallback(() => {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
    const host = window.location.hostname || 'localhost'
    const wsUrl = `${protocol}//${host}:9000/ws/logs`

    try {
      const ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        setConnected(true)
        toast.success('Connected to DNS monitor', {
          duration: 2000,
          style: { background: '#1e293b', color: '#e2e8f0', border: '1px solid #334155' },
        })
      }

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          if (data.type === 'dns_log') {
            logBuffer.current.unshift(data as DNSLog)
          } else if (data.type === 'threat_alert') {
            const alert = data.alert as ThreatAlert
            const showToast = ['critical', 'high', 'medium'].includes(alert.severity)
            alertBuffer.current.unshift({ alert, toast: showToast })
            addNotification(alert)
          } else if (data.type === 'dns_validated') {
            const msg = data as DNSValidatedMessage
            setDomainValidations(prev => ({
              ...prev,
              [msg.domain]: {
                status: msg.status,
                cached_ips: msg.cached_ips,
                auth_ips: msg.auth_ips,
                changed_ips: msg.changed_ips,
                timestamp: Date.now(),
              }
            }))
            if (msg.status === 'poisoned') {
              toast(
                () => (
                  <div className="flex items-start gap-3">
                    <XCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                    <div>
                      <div className="text-sm font-semibold text-red-400">Cache Poisoning Detected</div>
                      <div className="text-xs text-surface-400 mt-0.5">{msg.domain}</div>
                      <div className="text-xs text-surface-500 mt-0.5">
                        Cache: {msg.cached_ips.join(', ')} → Real: {msg.auth_ips.join(', ')}
                      </div>
                    </div>
                  </div>
                ),
                { duration: 8000, style: { background: '#1e293b', color: '#e2e8f0', border: '1px solid rgba(239,68,68,0.4)', maxWidth: 420 } }
              )
            }
          } else if (data.type === 'dns_fixed') {
            const msg = data as DNSFixedMessage
            toast(
              () => (
                <div className="flex items-start gap-3">
                  <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 shrink-0" />
                  <div>
                    <div className="text-sm font-semibold text-green-400">DNS Cache Fixed — You're Safe</div>
                    <div className="text-xs text-surface-400 mt-0.5">{msg.domain}</div>
                    <div className="text-xs text-surface-500 mt-0.5">Cache flushed · Next request will use the real record</div>
                  </div>
                </div>
              ),
              { duration: 6000, style: { background: '#1e293b', color: '#e2e8f0', border: '1px solid rgba(34,197,94,0.4)', maxWidth: 420 } }
            )
          } else {
            // Legacy format
            const log = data as DNSLog
            log.type = 'dns_log'
            logBuffer.current.unshift(log)
          }
        } catch (e) {
          console.error('Parse error:', e)
        }
      }

      ws.onerror = () => {
        setConnected(false)
      }

      ws.onclose = () => {
        setConnected(false)
        reconnectTimeout.current = window.setTimeout(connectWebSocket, 3000)
      }

      wsRef.current = ws
    } catch (e) {
      console.error('WebSocket error:', e)
      reconnectTimeout.current = window.setTimeout(connectWebSocket, 3000)
    }
  }, [addNotification])

  // Connect on mount + start flush interval
  useEffect(() => {
    connectWebSocket()

    // Flush buffered events to state every 150 ms — batches rapid bursts into a single render
    flushInterval.current = window.setInterval(() => {
      if (logBuffer.current.length > 0) {
        const incoming = logBuffer.current.splice(0)
        setLogs(prev => [...incoming, ...prev].slice(0, 500))
      }
      if (alertBuffer.current.length > 0) {
        const incoming = alertBuffer.current.splice(0)
        setAlerts(prev => [...incoming.map(i => i.alert), ...prev].slice(0, 200))
        // Fire toasts for alerts that need them
        incoming.forEach(({ alert, toast: showToast }) => {
          if (!showToast) return
          const config = SEVERITY_CONFIG[alert.severity]
          toast(
            (t) => (
              <div
                className="flex items-start gap-3 cursor-pointer"
                onClick={() => { toast.dismiss(t.id); setActiveTab('threats') }}
              >
                <div className={`w-2 h-2 rounded-full mt-1.5 flex-shrink-0 ${config?.dot || 'bg-blue-400'}`} />
                <div>
                  <div className={`text-sm font-semibold ${config?.text || 'text-blue-400'}`}>
                    {THREAT_TYPE_LABELS[alert.threat_type] || alert.threat_type}
                  </div>
                  <div className="text-xs text-surface-400 mt-0.5">{alert.domain}</div>
                  <div className="text-xs text-surface-500 mt-0.5 max-w-xs truncate">{alert.description}</div>
                </div>
              </div>
            ),
            {
              duration: alert.severity === 'critical' ? 8000 : 5000,
              style: {
                background: '#1e293b', color: '#e2e8f0',
                border: `1px solid ${
                  alert.severity === 'critical' ? 'rgba(239,68,68,0.3)' :
                  alert.severity === 'high' ? 'rgba(249,115,22,0.3)' : 'rgba(234,179,8,0.3)'
                }`,
                maxWidth: '400px',
              },
            }
          )
        })
      }
    }, 150)

    return () => {
      if (wsRef.current) wsRef.current.close()
      if (reconnectTimeout.current) clearTimeout(reconnectTimeout.current)
      if (flushInterval.current) clearInterval(flushInterval.current)
    }
  }, [connectWebSocket])

  // Fetch stats periodically
  useEffect(() => {
    const fetchStats = async () => {
      try {
        const host = window.location.hostname || 'localhost'
        const res = await fetch(`http://${host}:9000/api/stats`)
        const data = await res.json()
        setStats({
          totalQueries: data.total_queries || logs.length,
          totalAlerts: data.total_alerts || alerts.length,
          queriesPerMinute: data.queries_per_minute || 0,
          uniqueDomains: data.unique_domains || 0,
          uniqueSources: data.unique_sources || 0,
          activeConnections: data.active_connections || 0,
          alertRate: data.alert_rate || 0,
          threatsByType: data.threats_by_type || {},
          queriesByType: data.queries_by_type || {},
          queriesByResponse: data.queries_by_response || {},
        })
      } catch {
        // Use local state when backend stats unavailable
        const totalQ = logs.length
        const totalA = alerts.length
        setStats(prev => ({
          ...prev,
          totalQueries: totalQ,
          totalAlerts: totalA,
          alertRate: totalQ > 0 ? (totalA / totalQ) * 100 : 0,
        }))
      }
    }

    fetchStats()
    const interval = setInterval(fetchStats, 3000)
    return () => clearInterval(interval)
  }, [logs.length, alerts.length])

  const tabs: { id: TabId; label: string; icon: React.ElementType }[] = [
    { id: 'overview', label: 'Overview',    icon: LayoutDashboard },
    { id: 'traffic',  label: 'DNS Traffic', icon: Table2 },
    { id: 'threats',  label: 'Threats',     icon: AlertTriangle },
    { id: 'records',  label: 'Records',     icon: FileSearch },
    { id: 'domains',  label: 'Domains',     icon: GitBranch },
    { id: 'map',      label: 'Map',         icon: Globe },
    { id: 'graph',    label: 'Graph',       icon: Activity },
  ]

  return (
    <div className="min-h-screen bg-surface-950">
      {/* Toast container */}
      <Toaster
        position="top-right"
        toastOptions={{
          className: 'toast-custom',
        }}
      />

      {/* Notification Panel */}
      <NotificationCenter
        notifications={notifications}
        isOpen={notifPanelOpen}
        onClose={() => setNotifPanelOpen(false)}
        onClear={clearAll}
        onMarkAllRead={markAllRead}
        onMarkRead={markRead}
      />

      {/* Header */}
      <header className="bg-surface-900/80 backdrop-blur-xl border-b border-surface-700/50 sticky top-0 z-30">
        <div className="max-w-[1600px] mx-auto px-6 py-3">
          <div className="flex items-center justify-between">
            {/* Logo */}
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 bg-brand-500/15 border border-brand-500/30 rounded-lg flex items-center justify-center">
                <Shield className="w-5 h-5 text-brand-400" />
              </div>
              <div>
                <h1 className="text-lg font-bold text-surface-100">
                  DNS <span className="text-brand-400">Guardian</span>
                </h1>
                <p className="text-[10px] text-surface-500 -mt-0.5">Security Monitoring Platform</p>
              </div>
            </div>

            {/* Navigation Tabs */}
            <nav className="hidden md:flex items-center gap-1">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center gap-2 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${
                    activeTab === tab.id
                      ? 'bg-brand-500/15 text-brand-400'
                      : 'text-surface-400 hover:text-surface-200 hover:bg-surface-800/50'
                  }`}
                >
                  <tab.icon className="w-4 h-4" />
                  {tab.label}
                </button>
              ))}
            </nav>

            {/* Right side controls */}
            <div className="flex items-center gap-2">
              {/* Connection status */}
              <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs font-medium ${
                connected
                  ? 'bg-green-500/10 text-green-400 border border-green-500/20'
                  : 'bg-red-500/10 text-red-400 border border-red-500/20'
              }`}>
                <span className={`status-dot ${connected ? 'online live-pulse' : 'offline'}`}></span>
                {connected ? 'Live' : 'Offline'}
              </div>

              {/* Sound toggle */}
              <button
                onClick={() => setSoundEnabled(!soundEnabled)}
                className="p-2 rounded-lg text-surface-400 hover:text-surface-200 hover:bg-surface-800/50 transition-colors"
                title={soundEnabled ? 'Mute alerts' : 'Enable alert sounds'}
              >
                {soundEnabled ? <Volume2 className="w-4 h-4" /> : <VolumeX className="w-4 h-4" />}
              </button>

              {/* Browser notification toggle */}
              <button
                onClick={requestBrowserPermission}
                className={`p-2 rounded-lg transition-colors ${
                  browserNotifEnabled
                    ? 'text-brand-400 bg-brand-500/10'
                    : 'text-surface-400 hover:text-surface-200 hover:bg-surface-800/50'
                }`}
                title={browserNotifEnabled ? 'Browser notifications enabled' : 'Enable browser notifications'}
              >
                <BellRing className="w-4 h-4" />
              </button>

              {/* Notification bell */}
              <button
                onClick={() => setNotifPanelOpen(true)}
                className="relative p-2 rounded-lg text-surface-400 hover:text-surface-200 hover:bg-surface-800/50 transition-colors"
              >
                <Bell className="w-4 h-4" />
                {unreadCount > 0 && (
                  <span className="absolute -top-0.5 -right-0.5 bg-red-500 text-white text-[10px] font-bold w-4.5 h-4.5 rounded-full flex items-center justify-center min-w-[18px] px-1">
                    {unreadCount > 99 ? '99+' : unreadCount}
                  </span>
                )}
              </button>
            </div>
          </div>
        </div>

        {/* Mobile tab bar */}
        <div className="md:hidden flex border-t border-surface-700/30 overflow-x-auto">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 text-xs font-medium ${
                activeTab === tab.id
                  ? 'text-brand-400 border-b-2 border-brand-400'
                  : 'text-surface-400'
              }`}
            >
              <tab.icon className="w-3.5 h-3.5" />
              {tab.label}
            </button>
          ))}
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-[1600px] mx-auto px-6 py-6 space-y-6">
        {/* Key Metrics - always visible */}
        <KeyMetrics stats={stats} />

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="space-y-6 animate-fade-in">
            {/* Two column: Traffic + Threats */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <div>
                <h2 className="text-sm font-semibold text-surface-300 mb-3 flex items-center gap-2">
                  <Activity className="w-4 h-4 text-brand-400" />
                  Live DNS Traffic
                </h2>
                <DNSTraffic logs={logs} />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-surface-300 mb-3 flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-400" />
                  Recent Threats
                </h2>
                <ThreatIntelligence alerts={alerts} />
              </div>
            </div>

            {/* Distribution charts */}
            <div>
              <h2 className="text-sm font-semibold text-surface-300 mb-3">Distribution Analysis</h2>
              <ThreatDistribution stats={stats} />
            </div>

            {/* Timeline */}
            <div>
              <h2 className="text-sm font-semibold text-surface-300 mb-3">Detection Timeline</h2>
              <DetectionTimeline alerts={alerts} />
            </div>

            {/* Map preview */}
            <div>
              <div className="flex items-center justify-between mb-3">
                <h2 className="text-sm font-semibold text-surface-300 flex items-center gap-2">
                  <Globe className="w-4 h-4 text-brand-400" /> DNS Traffic Map
                </h2>
                <button onClick={() => setActiveTab('map')} className="text-xs text-brand-400 hover:text-brand-300">
                  Full map →
                </button>
              </div>
              <DNSMap logs={logs} />
            </div>
          </div>
        )}

        {activeTab === 'traffic' && (
          <div className="animate-fade-in">
            <h2 className="text-sm font-semibold text-surface-300 mb-3 flex items-center gap-2">
              <Table2 className="w-4 h-4 text-brand-400" />
              DNS Query Log
            </h2>
            <LiveDNSTable logs={logs} />
          </div>
        )}

        {activeTab === 'threats' && (
          <div className="space-y-6 animate-fade-in">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              <div className="lg:col-span-2">
                <h2 className="text-sm font-semibold text-surface-300 mb-3">Threat Intelligence</h2>
                <ThreatIntelligence alerts={alerts} />
              </div>
              <div>
                <h2 className="text-sm font-semibold text-surface-300 mb-3">Timeline</h2>
                <DetectionTimeline alerts={alerts} />
              </div>
            </div>
            <ThreatDistribution stats={stats} />
          </div>
        )}

        {activeTab === 'records' && (
          <div className="animate-fade-in">
            <h2 className="text-sm font-semibold text-surface-300 mb-3 flex items-center gap-2">
              <FileSearch className="w-4 h-4 text-brand-400" />
              DNS Records Monitor - A, AAAA, CNAME, NS, MX, TXT
            </h2>
            <RecordMonitor validations={domainValidations} />
          </div>
        )}

        {activeTab === 'domains' && (
          <div className="animate-fade-in space-y-6">
            <h2 className="text-sm font-semibold text-surface-300 flex items-center gap-2">
              <GitBranch className="w-4 h-4 text-purple-400" /> Domain Risk Analysis
            </h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <DomainAnalysis logs={logs} />
              <div>
                <h3 className="text-sm font-semibold text-surface-300 mb-3">Record Type Distribution</h3>
                <ThreatDistribution stats={stats} />
              </div>
            </div>
          </div>
        )}

        {activeTab === 'map' && (
          <div className="animate-fade-in space-y-6">
            <h2 className="text-sm font-semibold text-surface-300 flex items-center gap-2">
              <Globe className="w-4 h-4 text-brand-400" /> DNS Traffic World Map
            </h2>
            <p className="text-xs text-surface-500 -mt-4">
              IP addresses resolved from DNS answers, geolocated in real time.
              Red markers = threats detected · Amber = high traffic · Teal = normal
            </p>
            <DNSMap logs={logs} />
          </div>
        )}

        {activeTab === 'graph' && (
          <div className="animate-fade-in space-y-6">
            <h2 className="text-sm font-semibold text-surface-300 flex items-center gap-2">
              <Activity className="w-4 h-4 text-brand-400" /> Domain Relationship Graph
            </h2>
            <p className="text-xs text-surface-500 -mt-4">
              Shows connections between queried domains, their resolved IPs, and CNAME chains.
              Node size reflects query frequency. Drag nodes · scroll to zoom.
            </p>
            <DomainGraph logs={logs} />
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-surface-700/30 px-6 py-3 mt-8">
        <div className="max-w-[1600px] mx-auto flex items-center justify-between text-xs text-surface-500">
          <span>DNS Guardian v2.0 - Security Monitoring Platform</span>
          <span>{connected ? 'Monitoring active' : 'Attempting to reconnect...'}</span>
        </div>
      </footer>
    </div>
  )
}

export default App
