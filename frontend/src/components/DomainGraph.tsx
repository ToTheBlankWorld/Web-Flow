import React, { useEffect, useRef, useState, useMemo } from 'react'
import { GitBranch, ZoomIn, ZoomOut, RefreshCw, Maximize2 } from 'lucide-react'
import type { DNSLog } from '../types'

interface GraphNode {
  id: string
  label: string
  type: 'domain' | 'ip' | 'cname'
  x: number
  y: number
  vx: number
  vy: number
  queryCount: number
  hasAlert: boolean
}

interface GraphEdge {
  source: string
  target: string
  label: string
}

interface Props {
  logs: DNSLog[]
}

const NODE_COLORS = {
  domain: { fill: '#3b82f6', stroke: '#60a5fa', text: '#ffffff' },
  ip:     { fill: '#10b981', stroke: '#34d399', text: '#ffffff' },
  cname:  { fill: '#8b5cf6', stroke: '#a78bfa', text: '#ffffff' },
}
const ALERT_COLOR = { fill: '#ef4444', stroke: '#f87171', text: '#ffffff' }

function truncate(s: string, max: number) {
  return s.length > max ? s.slice(0, max - 1) + '…' : s
}

/** Single spring-physics step */
function tickForces(nodes: GraphNode[], edges: GraphEdge[], W: number, H: number) {
  const k = Math.sqrt((W * H) / Math.max(nodes.length, 1)) * 0.9
  const updated = nodes.map(n => ({ ...n }))
  const idx = Object.fromEntries(updated.map((n, i) => [n.id, i]))

  // Repulsion between all node pairs
  for (let i = 0; i < updated.length; i++) {
    for (let j = i + 1; j < updated.length; j++) {
      const dx = updated[j].x - updated[i].x || 0.01
      const dy = updated[j].y - updated[i].y || 0.01
      const dist = Math.sqrt(dx * dx + dy * dy) || 1
      const force = (k * k) / dist
      updated[i].vx -= (dx / dist) * force * 0.05
      updated[i].vy -= (dy / dist) * force * 0.05
      updated[j].vx += (dx / dist) * force * 0.05
      updated[j].vy += (dy / dist) * force * 0.05
    }
  }

  // Attraction along edges
  edges.forEach(e => {
    const si = idx[e.source], ti = idx[e.target]
    if (si == null || ti == null) return
    const dx = updated[ti].x - updated[si].x
    const dy = updated[ti].y - updated[si].y
    const dist = Math.sqrt(dx * dx + dy * dy) || 1
    const force = (dist - k) / dist * 0.08
    updated[si].vx += dx * force
    updated[si].vy += dy * force
    updated[ti].vx -= dx * force
    updated[ti].vy -= dy * force
  })

  // Integrate + dampen + clamp to canvas
  updated.forEach(n => {
    n.vx *= 0.7
    n.vy *= 0.7
    n.x = Math.max(50, Math.min(W - 50, n.x + n.vx))
    n.y = Math.max(50, Math.min(H - 50, n.y + n.vy))
  })

  return updated
}

export const DomainGraph: React.FC<Props> = ({ logs }) => {
  const svgRef = useRef<SVGSVGElement>(null)
  const [dimensions, setDimensions] = useState({ w: 800, h: 480 })
  const [nodes, setNodes] = useState<GraphNode[]>([])
  const [edges, setEdges] = useState<GraphEdge[]>([])
  const [zoom, setZoom] = useState(1)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [dragging, setDragging] = useState<{ nodeId: string; ox: number; oy: number } | null>(null)
  const [panStart, setPanStart] = useState<{ x: number; y: number; px: number; py: number } | null>(null)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const animRef = useRef<number>(0)
  const [settled, setSettled] = useState(false)
  const [filter, setFilter] = useState<'all' | 'alerts'>('all')

  // Resize observer
  useEffect(() => {
    const el = svgRef.current?.parentElement
    if (!el) return
    const ro = new ResizeObserver(entries => {
      const { width, height } = entries[0].contentRect
      setDimensions({ w: Math.max(width, 400), h: Math.max(height, 300) })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  // Build graph from logs
  const { rawNodes, rawEdges } = useMemo(() => {
    const domainMap: Record<string, { ips: Set<string>; cnames: Set<string>; count: number; hasAlert: boolean }> = {}

    logs.forEach(log => {
      if (!domainMap[log.domain]) {
        domainMap[log.domain] = { ips: new Set(), cnames: new Set(), count: 0, hasAlert: false }
      }
      const d = domainMap[log.domain]
      d.count++
      if (log.alert_level === 'alert') d.hasAlert = true
      log.answers?.forEach(ans => {
        if (/^\d+\.\d+\.\d+\.\d+$/.test(ans)) d.ips.add(ans)
        else if (ans.includes('.')) d.cnames.add(ans.replace(/\.$/, ''))
      })
    })

    const ns: GraphNode[] = []
    const es: GraphEdge[] = []
    const domainKeys = Object.keys(domainMap)
      .sort((a, b) => domainMap[b].count - domainMap[a].count)
      .slice(0, 30) // cap at 30 domains for readability

    const addedIds = new Set<string>()
    const addNode = (id: string, label: string, type: GraphNode['type'], meta: { count: number; hasAlert: boolean }) => {
      if (addedIds.has(id)) return
      addedIds.add(id)
      ns.push({
        id, label, type,
        x: Math.random() * 700 + 50,
        y: Math.random() * 400 + 50,
        vx: 0, vy: 0,
        queryCount: meta.count,
        hasAlert: meta.hasAlert,
      })
    }

    domainKeys.forEach(domain => {
      const d = domainMap[domain]
      addNode(domain, domain, 'domain', { count: d.count, hasAlert: d.hasAlert })

      d.ips.forEach(ip => {
        addNode(ip, ip, 'ip', { count: 1, hasAlert: false })
        es.push({ source: domain, target: ip, label: 'A' })
      })

      d.cnames.forEach(cname => {
        addNode(cname, cname, 'cname', { count: 1, hasAlert: d.hasAlert })
        es.push({ source: domain, target: cname, label: 'CNAME' })
      })
    })

    return { rawNodes: ns, rawEdges: es }
  }, [logs, filter]) // eslint-disable-line react-hooks/exhaustive-deps

  // Reset graph when data changes
  useEffect(() => {
    if (rawNodes.length === 0) return
    setNodes(rawNodes)
    setEdges(rawEdges)
    setSettled(false)
    setPan({ x: 0, y: 0 })
    setZoom(1)
  }, [rawNodes.length, rawEdges.length]) // eslint-disable-line react-hooks/exhaustive-deps

  // Run physics simulation for 80 ticks then stop
  useEffect(() => {
    if (settled || nodes.length === 0) return
    let tick = 0
    const step = () => {
      setNodes(prev => tickForces(prev, edges, dimensions.w, dimensions.h))
      tick++
      if (tick < 80) {
        animRef.current = requestAnimationFrame(step)
      } else {
        setSettled(true)
      }
    }
    animRef.current = requestAnimationFrame(step)
    return () => cancelAnimationFrame(animRef.current)
  }, [settled, edges, dimensions]) // eslint-disable-line react-hooks/exhaustive-deps

  const nodeById = useMemo(() => Object.fromEntries(nodes.map(n => [n.id, n])), [nodes])

  // Drag handlers for nodes
  const onNodeMouseDown = (e: React.MouseEvent, id: string) => {
    e.stopPropagation()
    setDragging({ nodeId: id, ox: e.clientX, oy: e.clientY })
    setSettled(true) // pause physics while dragging
  }

  const onSvgMouseMove = (e: React.MouseEvent) => {
    if (dragging) {
      const dx = (e.clientX - dragging.ox) / zoom
      const dy = (e.clientY - dragging.oy) / zoom
      setNodes(prev => prev.map(n =>
        n.id === dragging.nodeId ? { ...n, x: n.x + dx, y: n.y + dy, vx: 0, vy: 0 } : n
      ))
      setDragging(d => d ? { ...d, ox: e.clientX, oy: e.clientY } : null)
    } else if (panStart) {
      setPan({ x: panStart.px + (e.clientX - panStart.x), y: panStart.py + (e.clientY - panStart.y) })
    }
  }

  const onSvgMouseDown = (e: React.MouseEvent) => {
    if (e.button === 0 && !dragging) {
      setPanStart({ x: e.clientX, y: e.clientY, px: pan.x, py: pan.y })
    }
  }

  const displayNodes = filter === 'alerts' ? nodes.filter(n => n.hasAlert || edges.some(e => e.source === n.id && nodeById[e.target]?.hasAlert)) : nodes

  const displayNodeIds = new Set(displayNodes.map(n => n.id))
  const displayEdges = edges.filter(e => displayNodeIds.has(e.source) && displayNodeIds.has(e.target))

  const nodeRadius = (n: GraphNode) => n.type === 'domain' ? Math.min(6 + n.queryCount * 0.8, 18) : 6

  return (
    <div className="card overflow-hidden flex flex-col" style={{ height: 560 }}>
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-surface-700/50">
        <div className="flex items-center gap-2">
          <GitBranch className="w-4 h-4 text-brand-400" />
          <span className="text-sm font-semibold text-surface-200">Domain Relationship Graph</span>
          <span className="px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-surface-700/60 text-surface-400">
            {displayNodes.length} nodes · {displayEdges.length} edges
          </span>
        </div>
        <div className="flex items-center gap-1.5">
          {/* Filter */}
          {['all', 'alerts'].map(f => (
            <button key={f} onClick={() => setFilter(f as any)}
              className={`px-2 py-0.5 rounded text-xs transition-colors ${filter === f ? 'bg-brand-500/20 text-brand-400' : 'text-surface-400 hover:text-surface-200 hover:bg-surface-700/50'}`}>
              {f === 'all' ? 'All' : 'Threats'}
            </button>
          ))}
          <div className="w-px h-4 bg-surface-700 mx-1" />
          {/* Zoom */}
          <button onClick={() => setZoom(z => Math.min(z + 0.25, 3))} className="p-1.5 rounded hover:bg-surface-700/50 text-surface-400 hover:text-surface-200">
            <ZoomIn className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => setZoom(z => Math.max(z - 0.25, 0.25))} className="p-1.5 rounded hover:bg-surface-700/50 text-surface-400 hover:text-surface-200">
            <ZoomOut className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => { setSettled(false) }} title="Re-run layout"
            className="p-1.5 rounded hover:bg-surface-700/50 text-surface-400 hover:text-surface-200">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <button onClick={() => { setPan({ x: 0, y: 0 }); setZoom(1) }} title="Reset view"
            className="p-1.5 rounded hover:bg-surface-700/50 text-surface-400 hover:text-surface-200">
            <Maximize2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-4 px-4 py-1.5 text-[10px] text-surface-500 border-b border-surface-700/30">
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500 inline-block" /> Domain (size = query count)</span>
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-emerald-500 inline-block" /> IP Address</span>
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-violet-500 inline-block" /> CNAME Alias</span>
        <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-red-500 inline-block" /> Threat</span>
        <span className="ml-auto text-surface-600">Drag nodes · Scroll to zoom · Click+drag canvas to pan</span>
      </div>

      {/* SVG Canvas */}
      <div className="flex-1 overflow-hidden bg-surface-950/50 relative cursor-grab active:cursor-grabbing">
        {displayNodes.length === 0 ? (
          <div className="absolute inset-0 flex flex-col items-center justify-center text-surface-500 gap-2">
            <GitBranch className="w-8 h-8 opacity-30" />
            <span className="text-sm">Waiting for DNS traffic to build graph...</span>
          </div>
        ) : (
          <svg
            ref={svgRef}
            width="100%"
            height="100%"
            onMouseMove={onSvgMouseMove}
            onMouseUp={() => { setDragging(null); setPanStart(null) }}
            onMouseLeave={() => { setDragging(null); setPanStart(null) }}
            onMouseDown={onSvgMouseDown}
            onWheel={e => setZoom(z => Math.max(0.25, Math.min(3, z * (e.deltaY > 0 ? 0.9 : 1.1))))}
            style={{ display: 'block', userSelect: 'none' }}
          >
            <defs>
              <marker id="arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto">
                <path d="M0,0 L0,6 L6,3 z" fill="#475569" />
              </marker>
              <filter id="glow">
                <feGaussianBlur stdDeviation="2" result="coloredBlur" />
                <feMerge><feMergeNode in="coloredBlur" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            </defs>

            <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
              {/* Edges */}
              {displayEdges.map((e, i) => {
                const s = nodeById[e.source]
                const t = nodeById[e.target]
                if (!s || !t) return null
                const mx = (s.x + t.x) / 2
                const my = (s.y + t.y) / 2
                return (
                  <g key={i}>
                    <line
                      x1={s.x} y1={s.y} x2={t.x} y2={t.y}
                      stroke={e.label === 'CNAME' ? '#7c3aed' : '#334155'}
                      strokeWidth={e.label === 'CNAME' ? 1.5 : 1}
                      strokeDasharray={e.label === 'CNAME' ? '4 2' : undefined}
                      markerEnd="url(#arrow)"
                      opacity={0.7}
                    />
                    <text x={mx} y={my - 4} fill="#475569" fontSize={8} textAnchor="middle">{e.label}</text>
                  </g>
                )
              })}

              {/* Nodes */}
              {displayNodes.map(n => {
                const colors = n.hasAlert ? ALERT_COLOR : NODE_COLORS[n.type]
                const r = nodeRadius(n)
                const isHovered = hoveredNode === n.id
                return (
                  <g
                    key={n.id}
                    transform={`translate(${n.x},${n.y})`}
                    onMouseDown={ev => onNodeMouseDown(ev, n.id)}
                    onMouseEnter={() => setHoveredNode(n.id)}
                    onMouseLeave={() => setHoveredNode(null)}
                    style={{ cursor: 'grab' }}
                    filter={isHovered ? 'url(#glow)' : undefined}
                  >
                    <circle r={r} fill={colors.fill} stroke={colors.stroke} strokeWidth={isHovered ? 2.5 : 1.5} opacity={0.9} />
                    {/* Label */}
                    <text
                      y={r + 10}
                      fill="#94a3b8"
                      fontSize={isHovered ? 10 : 8}
                      textAnchor="middle"
                      style={{ pointerEvents: 'none' }}
                    >
                      {truncate(n.label, n.type === 'ip' ? 15 : 20)}
                    </text>
                    {n.queryCount > 1 && n.type === 'domain' && (
                      <text y={-r - 4} fill="#64748b" fontSize={7} textAnchor="middle">
                        ×{n.queryCount}
                      </text>
                    )}
                  </g>
                )
              })}
            </g>
          </svg>
        )}

        {/* Hover tooltip */}
        {hoveredNode && nodeById[hoveredNode] && (() => {
          const n = nodeById[hoveredNode]
          const connected = displayEdges.filter(e => e.source === n.id || e.target === n.id)
          return (
            <div className="absolute top-3 left-3 bg-surface-900/95 border border-surface-700 rounded-lg px-3 py-2 text-xs max-w-[240px] z-10 pointer-events-none">
              <div className="font-mono text-surface-200 font-medium mb-1 break-all">{n.id}</div>
              <div className="text-surface-500">Type: <span className="text-surface-300 capitalize">{n.type}</span></div>
              {n.type === 'domain' && <div className="text-surface-500">Queries: <span className="text-brand-400">{n.queryCount}</span></div>}
              {n.hasAlert && <div className="text-red-400 font-medium mt-1">⚠ Threat detected</div>}
              {connected.length > 0 && (
                <div className="text-surface-500 mt-1">
                  Connections: <span className="text-surface-300">{connected.length}</span>
                </div>
              )}
            </div>
          )
        })()}
      </div>
    </div>
  )
}
