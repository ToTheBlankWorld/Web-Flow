import React, { useEffect, useState, useMemo, useRef } from 'react'
import { MapContainer, TileLayer, CircleMarker, Popup, ZoomControl, useMap } from 'react-leaflet'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { Globe, RefreshCw, Wifi, AlertTriangle } from 'lucide-react'
import type { DNSLog } from '../types'

// Fix leaflet icon path issue with Vite
delete (L.Icon.Default.prototype as any)._getIconUrl
L.Icon.Default.mergeOptions({
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
})

interface GeoPoint {
  ip: string
  lat: number
  lon: number
  country: string
  countryCode: string
  city: string
  regionName: string
  isp: string
  org: string
  domains: string[]
  hasAlert: boolean
  queryCount: number
}

interface Props {
  logs: DNSLog[]
}

/** Fit map bounds to all visible markers when data changes. */
function AutoFit({ points }: { points: GeoPoint[] }) {
  const map = useMap()
  useEffect(() => {
    if (points.length === 0) return
    const bounds = L.latLngBounds(points.map(p => [p.lat, p.lon]))
    map.fitBounds(bounds, { padding: [40, 40], maxZoom: 6 })
  }, [points.length]) // eslint-disable-line react-hooks/exhaustive-deps
  return null
}

export const DNSMap: React.FC<Props> = ({ logs }) => {
  const [geoData, setGeoData] = useState<Record<string, GeoPoint>>({})
  const [loading, setLoading] = useState(false)
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null)
  const fetchedIPs = useRef<Set<string>>(new Set())

  // Collect unique destination IPs from logs
  const uniqueIPs = useMemo(() => {
    const ips = new Set<string>()
    logs.forEach(log => {
      log.answers?.forEach(ans => {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(ans)) ips.add(ans)
      })
      if (log.dest_ip && /^\d+\.\d+\.\d+\.\d+$/.test(log.dest_ip)) ips.add(log.dest_ip)
    })
    return Array.from(ips).filter(ip =>
      !ip.startsWith('127.') && !ip.startsWith('192.168.') &&
      !ip.startsWith('10.')  && !ip.startsWith('172.') && ip !== '0.0.0.0'
    )
  }, [logs])

  // Build domain→IP mapping for tooltips
  const ipDomainMap = useMemo(() => {
    const m: Record<string, { domains: string[]; hasAlert: boolean; count: number }> = {}
    logs.forEach(log => {
      const ips = (log.answers ?? []).filter(a => /^\d+\.\d+\.\d+\.\d+$/.test(a))
      ips.forEach(ip => {
        if (!m[ip]) m[ip] = { domains: [], hasAlert: false, count: 0 }
        if (!m[ip].domains.includes(log.domain)) m[ip].domains.push(log.domain)
        if (log.alert_level === 'alert') m[ip].hasAlert = true
        m[ip].count++
      })
    })
    return m
  }, [logs])

  const fetchGeoForNewIPs = async (ips: string[]) => {
    const newIPs = ips.filter(ip => !fetchedIPs.current.has(ip)).slice(0, 20)
    if (newIPs.length === 0) return
    setLoading(true)
    try {
      const host = window.location.hostname || 'localhost'
      const res = await fetch(`http://${host}:9000/api/geoip?ips=${newIPs.join(',')}`)
      const data = await res.json()
      const updates: Record<string, GeoPoint> = {}
      ;(data.results as any[]).forEach(r => {
        if (r?.status !== 'success') return
        const meta = ipDomainMap[r.query] ?? { domains: [], hasAlert: false, count: 0 }
        updates[r.query] = {
          ip: r.query,
          lat: r.lat,
          lon: r.lon,
          country: r.country,
          countryCode: r.countryCode,
          city: r.city,
          regionName: r.regionName,
          isp: r.isp,
          org: r.org,
          domains: meta.domains,
          hasAlert: meta.hasAlert,
          queryCount: meta.count,
        }
        fetchedIPs.current.add(r.query)
      })
      setGeoData(prev => ({ ...prev, ...updates }))
      setLastRefresh(new Date())
    } catch {
      // Backend unreachable — skip silently
    } finally {
      setLoading(false)
    }
  }

  // Auto-fetch when new IPs appear
  useEffect(() => {
    if (uniqueIPs.length > 0) fetchGeoForNewIPs(uniqueIPs)
  }, [uniqueIPs.length]) // eslint-disable-line react-hooks/exhaustive-deps

  const points = Object.values(geoData)
  const alertCount = points.filter(p => p.hasAlert).length

  // Marker colour: red for alerts, amber for high-traffic, teal for normal
  const markerColor = (p: GeoPoint) =>
    p.hasAlert ? '#ef4444' : p.queryCount > 5 ? '#f59e0b' : '#22d3ee'

  return (
    <div className="card overflow-hidden flex flex-col">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-surface-700/50">
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-brand-400" />
          <span className="text-sm font-semibold text-surface-200">DNS Traffic Map</span>
          {points.length > 0 && (
            <span className="ml-1 px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-surface-700/60 text-surface-400">
              {points.length} IPs
            </span>
          )}
          {alertCount > 0 && (
            <span className="px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-red-500/15 text-red-400 border border-red-500/20">
              {alertCount} threat{alertCount > 1 ? 's' : ''} mapped
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          {lastRefresh && (
            <span className="text-[10px] text-surface-500">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
          )}
          <button
            onClick={() => { fetchedIPs.current.clear(); fetchGeoForNewIPs(uniqueIPs) }}
            disabled={loading}
            className="p-1.5 rounded hover:bg-surface-700/50 transition-colors text-surface-400 hover:text-surface-200 disabled:opacity-40"
            title="Refresh geolocation"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 px-4 py-2 text-[10px] text-surface-500 border-b border-surface-700/30">
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block" /> Normal
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block" /> High traffic
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" /> Threat detected
        </span>
      </div>

      {/* Map */}
      <div className="relative flex-1" style={{ height: 420 }}>
        {uniqueIPs.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-surface-500 gap-2">
            <Wifi className="w-8 h-8 opacity-30" />
            <span className="text-sm">Waiting for DNS traffic with IP answers...</span>
          </div>
        ) : (
          <MapContainer
            center={[20, 0]}
            zoom={2}
            zoomControl={false}
            scrollWheelZoom
            style={{ width: '100%', height: '100%', background: '#0f172a' }}
          >
            {/* Dark tile layer */}
            <TileLayer
              url="https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"
              attribution='&copy; <a href="https://carto.com">CARTO</a>'
              maxZoom={19}
            />
            <ZoomControl position="bottomright" />
            {points.length > 0 && <AutoFit points={points} />}

            {points.map(pt => (
              <CircleMarker
                key={pt.ip}
                center={[pt.lat, pt.lon]}
                radius={pt.hasAlert ? 10 : Math.min(6 + pt.queryCount, 14)}
                pathOptions={{
                  color: markerColor(pt),
                  fillColor: markerColor(pt),
                  fillOpacity: 0.8,
                  weight: pt.hasAlert ? 2 : 1,
                }}
              >
                <Popup>
                  <div style={{ minWidth: 200, fontFamily: 'monospace', fontSize: 12, lineHeight: 1.6 }}>
                    {pt.hasAlert && (
                      <div style={{ color: '#ef4444', fontWeight: 700, marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
                        ⚠ Threat Detected
                      </div>
                    )}
                    <div style={{ fontWeight: 700, fontSize: 13, marginBottom: 4, color: '#e2e8f0' }}>{pt.ip}</div>
                    <div style={{ color: '#94a3b8' }}>
                      <div>📍 {pt.city}{pt.city && pt.regionName ? ', ' : ''}{pt.regionName}</div>
                      <div>🌍 {pt.country} ({pt.countryCode})</div>
                      <div>🏢 {pt.org || pt.isp}</div>
                      <div style={{ marginTop: 6, color: '#64748b' }}>Queries: {pt.queryCount}</div>
                      {pt.domains.length > 0 && (
                        <div style={{ marginTop: 4 }}>
                          <div style={{ color: '#64748b', marginBottom: 2 }}>Domains:</div>
                          {pt.domains.slice(0, 5).map(d => (
                            <div key={d} style={{ paddingLeft: 8, color: '#94a3b8' }}>• {d}</div>
                          ))}
                          {pt.domains.length > 5 && (
                            <div style={{ paddingLeft: 8, color: '#64748b' }}>+{pt.domains.length - 5} more</div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                </Popup>
              </CircleMarker>
            ))}
          </MapContainer>
        )}

        {loading && (
          <div className="absolute top-3 left-1/2 -translate-x-1/2 z-[1000] bg-surface-900/90 border border-surface-700 rounded-full px-3 py-1 text-xs text-surface-300 flex items-center gap-2">
            <RefreshCw className="w-3 h-3 animate-spin" /> Looking up IP locations...
          </div>
        )}
      </div>

      {/* Footer stats */}
      {points.length > 0 && (
        <div className="px-4 py-2 border-t border-surface-700/30 flex gap-4 text-[10px] text-surface-500">
          {Array.from(new Set(points.map(p => p.country))).slice(0, 8).map(c => (
            <span key={c}>{c}</span>
          ))}
          {new Set(points.map(p => p.country)).size > 8 && (
            <span>+{new Set(points.map(p => p.country)).size - 8} more countries</span>
          )}
        </div>
      )}
    </div>
  )
}
