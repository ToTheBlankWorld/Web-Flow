import React, { useEffect, useState, useCallback } from 'react'
import { Search, RefreshCw, CheckCircle, AlertTriangle, Shield, Globe, Clock, Server, XCircle, HelpCircle } from 'lucide-react'
import type { DNSValidatedMessage } from '../types'

interface DomainRecords {
  A: string[]
  AAAA: string[]
  CNAME: string[]
  NS: string[]
  MX: string[]
  TXT: string[]
  first_seen: string
  last_seen: string
  query_count: number
  sources: string[]
}

interface ValidationResult {
  domain: string
  cached: Record<string, { answers: string[], ttl: number, resolver: string }>
  authoritative: Record<string, { answers: string[], ttl: number, nameserver: string }>
  match: boolean
  warnings: string[]
}

// Result pushed by backend auto-validation (dns_validated WS message)
interface AutoValidation {
  status: 'safe' | 'poisoned'
  cached_ips: string[]
  auth_ips: string[]
  changed_ips: string[]
  timestamp: number
}

interface LiveRecord {
  answers: string[]
  ttl: number
  response_code: string
  source: string
}

interface Props {
  /** Auto-validation results pushed via WebSocket from backend */
  validations?: Record<string, AutoValidation>
}

export const RecordMonitor: React.FC<Props> = ({ validations = {} }) => {
  const [domains, setDomains] = useState<Record<string, DomainRecords>>({})
  const [totalDomains, setTotalDomains] = useState(0)
  const [searchDomain, setSearchDomain] = useState('')
  const [selectedDomain, setSelectedDomain] = useState<string | null>(null)
  const [liveRecords, setLiveRecords] = useState<Record<string, LiveRecord> | null>(null)
  const [validation, setValidation] = useState<ValidationResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [validating, setValidating] = useState(false)

  const host = window.location.hostname || 'localhost'
  const apiBase = `http://${host}:9000`

  const fetchDomains = useCallback(async () => {
    try {
      const res = await fetch(`${apiBase}/api/domains`)
      const data = await res.json()
      setDomains(data.domains || {})
      setTotalDomains(data.total || 0)
    } catch {
      // Backend might be down
    }
  }, [apiBase])

  useEffect(() => {
    fetchDomains()
    const interval = setInterval(fetchDomains, 5000)
    return () => clearInterval(interval)
  }, [fetchDomains])

  const lookupDomain = async (domain: string) => {
    if (!domain.trim()) return
    setSelectedDomain(domain)
    setLoading(true)
    setValidation(null)
    setLiveRecords(null)

    try {
      const res = await fetch(`${apiBase}/api/records/${encodeURIComponent(domain)}`)
      const data = await res.json()
      setLiveRecords(data.live_records || null)
    } catch {
      setLiveRecords(null)
    }
    setLoading(false)
  }

  const validateDomain = async (domain: string) => {
    setValidating(true)
    try {
      const res = await fetch(`${apiBase}/api/validate/${encodeURIComponent(domain)}`)
      const data = await res.json()
      setValidation(data)
    } catch {
      setValidation(null)
    }
    setValidating(false)
  }

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault()
    lookupDomain(searchDomain)
  }

  const RECORD_COLORS: Record<string, string> = {
    A: 'text-green-400 bg-green-500/10 border-green-500/20',
    AAAA: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/20',
    CNAME: 'text-purple-400 bg-purple-500/10 border-purple-500/20',
    NS: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    MX: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    TXT: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  }

  const domainList = Object.entries(domains)
    .filter(([d]) => !searchDomain || d.toLowerCase().includes(searchDomain.toLowerCase()))
    .sort(([, a], [, b]) => b.query_count - a.query_count)

  return (
    <div className="space-y-6">
      {/* Search Bar */}
      <div className="card p-4">
        <form onSubmit={handleSearch} className="flex gap-3">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-surface-400" />
            <input
              type="text"
              value={searchDomain}
              onChange={(e) => setSearchDomain(e.target.value)}
              placeholder="Search or lookup a domain (e.g. google.com)..."
              className="w-full bg-surface-800/50 border border-surface-700/50 rounded-lg pl-10 pr-4 py-2.5 text-sm text-surface-200 placeholder-surface-500 focus:outline-none focus:border-brand-500/50 focus:ring-1 focus:ring-brand-500/25"
            />
          </div>
          <button
            type="submit"
            className="px-4 py-2.5 bg-brand-500/15 text-brand-400 border border-brand-500/30 rounded-lg text-sm font-medium hover:bg-brand-500/25 transition-colors flex items-center gap-2"
          >
            <Globe className="w-4 h-4" />
            Lookup
          </button>
        </form>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Domain List */}
        <div className="lg:col-span-1">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-surface-300">
              Tracked Domains ({totalDomains})
            </h3>
            <button onClick={fetchDomains} className="text-surface-400 hover:text-surface-200">
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="card overflow-hidden max-h-[600px] overflow-y-auto">
            {domainList.length === 0 ? (
              <div className="p-8 text-center">
                <Globe className="w-10 h-10 text-surface-600 mx-auto mb-3" />
                <p className="text-surface-400 text-sm">No domains tracked yet</p>
                <p className="text-surface-500 text-xs mt-1">Domains will appear as DNS traffic is captured</p>
              </div>
            ) : (
              domainList.map(([domain, info]) => {
                const recordTypes = ['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT']
                  .filter(rt => info[rt as keyof DomainRecords] && (info[rt as keyof DomainRecords] as string[]).length > 0)

                const av = validations[domain]
                return (
                  <div
                    key={domain}
                    className={`px-4 py-3 border-b border-surface-700/20 cursor-pointer transition-colors hover:bg-surface-800/50 ${
                      selectedDomain === domain ? 'bg-brand-500/5 border-l-2 border-l-brand-400' : ''
                    } ${av?.status === 'poisoned' ? 'bg-red-500/5' : ''}`}
                    onClick={() => lookupDomain(domain)}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="text-sm font-medium text-surface-200 truncate">{domain}</div>
                      {av ? (
                        av.status === 'safe'
                          ? <span title="Verified safe"><CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" /></span>
                          : <span title="Cache poisoning detected!"><XCircle className="w-3.5 h-3.5 text-red-400 shrink-0" /></span>
                      ) : (
                        <span title="Not yet validated"><HelpCircle className="w-3.5 h-3.5 text-surface-600 shrink-0" /></span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="text-xs text-surface-500">{info.query_count} queries</span>
                      <div className="flex gap-1">
                        {recordTypes.map(rt => (
                          <span key={rt} className={`px-1 py-0.5 rounded text-[9px] font-mono border ${RECORD_COLORS[rt] || ''}`}>
                            {rt}
                          </span>
                        ))}
                      </div>
                    </div>
                  </div>
                )
              })
            )}
          </div>
        </div>

        {/* Domain Detail */}
        <div className="lg:col-span-2 space-y-4">
          {selectedDomain ? (
            <>
              {/* Domain header */}
              <div className="card p-4">
                <div className="flex items-center justify-between mb-3">
                  <div>
                    <h3 className="text-lg font-semibold text-surface-200">{selectedDomain}</h3>
                    <div className="flex items-center gap-3 mt-1 text-xs text-surface-500">
                      {domains[selectedDomain] && (
                        <>
                          <span className="flex items-center gap-1">
                            <Clock className="w-3 h-3" />
                            First: {new Date(domains[selectedDomain].first_seen).toLocaleTimeString()}
                          </span>
                          <span>Queries: {domains[selectedDomain].query_count}</span>
                          <span>Sources: {domains[selectedDomain].sources?.join(', ')}</span>
                        </>
                      )}
                    </div>
                  </div>
                  <button
                    onClick={() => validateDomain(selectedDomain)}
                    disabled={validating}
                    className="px-3 py-2 bg-green-500/10 text-green-400 border border-green-500/30 rounded-lg text-xs font-medium hover:bg-green-500/20 transition-colors flex items-center gap-2 disabled:opacity-50"
                  >
                    <Shield className="w-3.5 h-3.5" />
                    {validating ? 'Validating...' : 'Validate Auth vs Cache'}
                  </button>
                </div>

                {/* Auto-Validation status (from WebSocket) */}
                {validations[selectedDomain] && (
                  <div className={`mt-3 p-3 rounded-lg border flex items-start gap-3 ${
                    validations[selectedDomain].status === 'safe'
                      ? 'bg-green-500/5 border-green-500/20'
                      : 'bg-red-500/10 border-red-500/30'
                  }`}>
                    {validations[selectedDomain].status === 'safe' ? (
                      <CheckCircle className="w-4 h-4 text-green-400 mt-0.5 shrink-0" />
                    ) : (
                      <XCircle className="w-4 h-4 text-red-400 mt-0.5 shrink-0" />
                    )}
                    <div className="flex-1 min-w-0">
                      <div className={`text-sm font-semibold ${validations[selectedDomain].status === 'safe' ? 'text-green-400' : 'text-red-400'}`}>
                        {validations[selectedDomain].status === 'safe'
                          ? '✓ Auto-verified — Safe to browse'
                          : '⚠ Cache Poisoning Detected — DNS cache has been flushed'}
                      </div>
                      <div className="mt-1.5 grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
                        <div>
                          <span className="text-surface-500">Cached IPs: </span>
                          <span className="font-mono text-surface-300">{validations[selectedDomain].cached_ips.join(', ') || '—'}</span>
                        </div>
                        <div>
                          <span className="text-surface-500">Real IPs (8.8.8.8): </span>
                          <span className="font-mono text-surface-300">{validations[selectedDomain].auth_ips.join(', ') || '—'}</span>
                        </div>
                        {validations[selectedDomain].changed_ips.length > 0 && (
                          <div className="col-span-2">
                            <span className="text-red-400">Poisoned IPs: </span>
                            <span className="font-mono text-red-300">{validations[selectedDomain].changed_ips.join(', ')}</span>
                          </div>
                        )}
                      </div>
                      <div className="text-[10px] text-surface-600 mt-1">
                        Checked at {new Date(validations[selectedDomain].timestamp).toLocaleTimeString()}
                      </div>
                    </div>
                  </div>
                )}

                {/* Manual Validation Result */}
                {validation && (
                  <div className={`mt-3 p-3 rounded-lg border ${
                    validation.match
                      ? 'bg-green-500/5 border-green-500/20'
                      : 'bg-red-500/5 border-red-500/20'
                  }`}>
                    <div className="flex items-center gap-2 mb-2">
                      {validation.match ? (
                        <>
                          <CheckCircle className="w-4 h-4 text-green-400" />
                          <span className="text-sm font-medium text-green-400">DNS responses match authoritative records</span>
                        </>
                      ) : (
                        <>
                          <AlertTriangle className="w-4 h-4 text-red-400" />
                          <span className="text-sm font-medium text-red-400">MISMATCH: Cached vs Authoritative</span>
                        </>
                      )}
                    </div>

                    {validation.warnings.length > 0 && (
                      <div className="space-y-1">
                        {validation.warnings.map((w, i) => (
                          <div key={i} className="text-xs text-yellow-400">{w}</div>
                        ))}
                      </div>
                    )}

                    <div className="grid grid-cols-2 gap-4 mt-3">
                      <div>
                        <div className="text-xs font-medium text-surface-400 mb-1">Cached Response</div>
                        {Object.entries(validation.cached).map(([type, data]) => (
                          <div key={type} className="text-xs mb-1">
                            <span className="text-surface-500">{type}: </span>
                            <span className="text-surface-300 font-mono">{data.answers?.join(', ') || 'none'}</span>
                            <span className="text-surface-600 ml-2">TTL:{data.ttl}s</span>
                          </div>
                        ))}
                      </div>
                      <div>
                        <div className="text-xs font-medium text-surface-400 mb-1">Authoritative Response</div>
                        {Object.entries(validation.authoritative).map(([type, data]) => (
                          <div key={type} className="text-xs mb-1">
                            <span className="text-surface-500">{type}: </span>
                            <span className="text-surface-300 font-mono">{data.answers?.join(', ') || 'none'}</span>
                            <span className="text-surface-600 ml-2">NS:{data.nameserver}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>

              {/* Live Records */}
              <div className="card p-4">
                <h4 className="text-sm font-semibold text-surface-300 mb-3 flex items-center gap-2">
                  <Server className="w-4 h-4 text-brand-400" />
                  DNS Records
                </h4>

                {loading ? (
                  <div className="text-center py-8 text-surface-500 text-sm">Resolving...</div>
                ) : liveRecords ? (
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    {(['A', 'AAAA', 'CNAME', 'NS', 'MX', 'TXT'] as const).map(rtype => {
                      const record = liveRecords[rtype]
                      const cached = domains[selectedDomain]
                      const cachedRecords = cached ? (cached[rtype as keyof DomainRecords] as string[]) : []
                      const hasData = record?.answers?.length > 0 || cachedRecords?.length > 0

                      if (!hasData) return null

                      return (
                        <div key={rtype} className={`p-3 rounded-lg border ${RECORD_COLORS[rtype] || 'border-surface-700'}`}>
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-xs font-bold uppercase">{rtype} Records</span>
                            {record && (
                              <span className="text-[10px] text-surface-500">
                                TTL: {record.ttl}s | {record.response_code}
                              </span>
                            )}
                          </div>
                          <div className="space-y-1">
                            {(record?.answers || cachedRecords || []).map((ans, i) => (
                              <div key={i} className="text-xs font-mono text-surface-300 bg-surface-900/50 px-2 py-1 rounded">
                                {ans}
                              </div>
                            ))}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div className="text-center py-8 text-surface-500 text-sm">
                    Select a domain or search to view records
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="card p-12 text-center">
              <Search className="w-12 h-12 text-surface-600 mx-auto mb-3" />
              <p className="text-surface-400">Select a domain from the list or search for one</p>
              <p className="text-surface-500 text-xs mt-1">
                View A, AAAA, CNAME, NS, MX, TXT records and validate against authoritative nameservers
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
