import { useMemo, useState } from 'react'
import { SEVERITY_COLORS } from './Badge'
import type { GraphData, GraphNode, GraphNodeLabel } from '../api/types'

// Categorical color per entity identity (fixed order, never cycled) - kept
// deliberately clear of the reserved status hues (SEVERITY_COLORS) below,
// since Incident nodes are colored by risk level (a status), not identity.
const ENTITY_COLORS: Record<GraphNodeLabel, string> = {
  Host: '#3987e5',
  User: '#9085e9',
  IP: '#d55181',
  Incident: '#64748b',
  Indicator: '#c2703d',
  Tag: '#2fa5a0',
  Source: '#9c8465',
}

function nodeColor(node: GraphNode): string {
  if (node.label === 'Incident' && node.risk_level) {
    return SEVERITY_COLORS[node.risk_level]?.bg ?? ENTITY_COLORS.Incident
  }
  return ENTITY_COLORS[node.label]
}

function nodeDisplayName(node: GraphNode): string {
  return node.title ?? node.name ?? node.address ?? node.value ?? (node.id !== undefined ? `#${node.id}` : node.key)
}

interface SimNode extends GraphNode {
  x: number
  y: number
  vx: number
  vy: number
}

const WIDTH = 800
const HEIGHT = 520

function layout(nodes: GraphNode[], edges: GraphData['edges']): SimNode[] {
  const simNodes: SimNode[] = nodes.map((n, i) => {
    const angle = (i / Math.max(nodes.length, 1)) * Math.PI * 2
    return {
      ...n,
      x: WIDTH / 2 + Math.cos(angle) * 150,
      y: HEIGHT / 2 + Math.sin(angle) * 150,
      vx: 0,
      vy: 0,
    }
  })
  const byKey = new Map(simNodes.map((n) => [n.key, n]))
  const simEdges = edges
    .map((e) => ({ source: byKey.get(e.from), target: byKey.get(e.to) }))
    .filter((e): e is { source: SimNode; target: SimNode } => !!e.source && !!e.target)

  const REPULSION = 12000
  const SPRING_LENGTH = 130
  const SPRING_STRENGTH = 0.02
  const CENTER_STRENGTH = 0.01
  const DAMPING = 0.85

  for (let iter = 0; iter < 250; iter++) {
    for (let i = 0; i < simNodes.length; i++) {
      for (let j = i + 1; j < simNodes.length; j++) {
        const a = simNodes[i]
        const b = simNodes[j]
        const dx = a.x - b.x
        const dy = a.y - b.y
        const distSq = Math.max(dx * dx + dy * dy, 1)
        const force = REPULSION / distSq
        const dist = Math.sqrt(distSq)
        const fx = (force * dx) / dist
        const fy = (force * dy) / dist
        a.vx += fx
        a.vy += fy
        b.vx -= fx
        b.vy -= fy
      }
    }

    for (const { source, target } of simEdges) {
      const dx = target.x - source.x
      const dy = target.y - source.y
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1)
      const displacement = dist - SPRING_LENGTH
      const fx = (dx / dist) * displacement * SPRING_STRENGTH
      const fy = (dy / dist) * displacement * SPRING_STRENGTH
      source.vx += fx
      source.vy += fy
      target.vx -= fx
      target.vy -= fy
    }

    for (const n of simNodes) {
      n.vx += (WIDTH / 2 - n.x) * CENTER_STRENGTH
      n.vy += (HEIGHT / 2 - n.y) * CENTER_STRENGTH
      n.vx *= DAMPING
      n.vy *= DAMPING
      n.x += n.vx
      n.y += n.vy
      n.x = Math.min(Math.max(n.x, 30), WIDTH - 30)
      n.y = Math.min(Math.max(n.y, 30), HEIGHT - 30)
    }
  }

  return simNodes
}

interface Props {
  data: GraphData
  onNodeClick?: (node: GraphNode) => void
}

export function AttackGraphView({ data, onNodeClick }: Props) {
  const simNodes = useMemo(() => layout(data.nodes, data.edges), [data])
  const byKey = useMemo(() => new Map(simNodes.map((n) => [n.key, n])), [simNodes])
  const [hoveredKey, setHoveredKey] = useState<string | null>(null)

  const labelsPresent = Array.from(new Set(data.nodes.map((n) => n.label))) as GraphNodeLabel[]

  if (data.nodes.length === 0) {
    return <p className="text-sm text-muted-foreground">No graph data - run a sync or check back after correlating incidents.</p>
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-3 text-xs text-muted-foreground">
        {labelsPresent
          .filter((label) => label !== 'Incident')
          .map((label) => (
            <span key={label} className="inline-flex items-center gap-1.5">
              <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ backgroundColor: ENTITY_COLORS[label] }} />
              {label}
            </span>
          ))}
        {labelsPresent.includes('Incident') && (
          <span className="inline-flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full bg-muted-foreground" />
            Incident (colored by risk level)
          </span>
        )}
      </div>

      <div className="overflow-x-auto rounded-lg border border-secondary bg-background">
        <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`} width="100%" style={{ minWidth: 480, height: 480 }}>
          {data.edges.map((edge, i) => {
            const from = byKey.get(edge.from)
            const to = byKey.get(edge.to)
            if (!from || !to) return null
            const dimmed = hoveredKey !== null && hoveredKey !== edge.from && hoveredKey !== edge.to
            return (
              <line
                key={i}
                x1={from.x}
                y1={from.y}
                x2={to.x}
                y2={to.y}
                stroke="#475569"
                strokeWidth={2}
                opacity={dimmed ? 0.12 : 0.55}
              />
            )
          })}

          {simNodes.map((node) => {
            const dimmed = hoveredKey !== null && hoveredKey !== node.key
            const radius = node.label === 'Incident' ? 10 : 7
            return (
              <g
                key={node.key}
                opacity={dimmed ? 0.35 : 1}
                onMouseEnter={() => setHoveredKey(node.key)}
                onMouseLeave={() => setHoveredKey(null)}
                onClick={() => onNodeClick?.(node)}
                style={{ cursor: onNodeClick && node.label === 'Incident' ? 'pointer' : 'default' }}
              >
                <circle cx={node.x} cy={node.y} r={radius} fill={nodeColor(node)} stroke="#0f172a" strokeWidth={2} />
                <text
                  x={node.x}
                  y={node.y - radius - 5}
                  textAnchor="middle"
                  fontSize={11}
                  fill="#cbd5e1"
                  style={{ pointerEvents: 'none' }}
                >
                  {nodeDisplayName(node).slice(0, 24)}
                </text>
              </g>
            )
          })}
        </svg>
      </div>
    </div>
  )
}
