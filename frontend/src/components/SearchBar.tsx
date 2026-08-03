import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client'
import type { SearchResults } from '../api/types'

export function SearchBar() {
  const [q, setQ] = useState('')
  const [results, setResults] = useState<SearchResults | null>(null)
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (q.trim().length < 2) {
      setResults(null)
      return
    }
    const timer = setTimeout(() => {
      api.search(q.trim()).then((res) => {
        setResults(res)
        setOpen(true)
      })
    }, 250)
    return () => clearTimeout(timer)
  }, [q])

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const hasResults = results && (results.events.length > 0 || results.incidents.length > 0 || results.assets.length > 0)

  return (
    <div ref={containerRef} className="relative w-64">
      <input
        value={q}
        onChange={(e) => setQ(e.target.value)}
        onFocus={() => q.trim().length >= 2 && setOpen(true)}
        placeholder="Search everything..."
        className="w-full rounded-lg bg-secondary border border-border px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary"
      />
      {open && results && (
        <div className="absolute right-0 mt-1 w-96 max-h-96 overflow-y-auto rounded-lg border border-border bg-card shadow-xl z-50">
          {!hasResults && <p className="px-3 py-3 text-sm text-muted-foreground">No matches for "{q}"</p>}

          {results.incidents.length > 0 && (
            <div className="py-1">
              <p className="px-3 py-1 text-xs uppercase tracking-wide text-muted-foreground">Incidents</p>
              {results.incidents.map((incident) => (
                <Link
                  key={incident.id}
                  to={`/incidents/${incident.id}`}
                  onClick={() => setOpen(false)}
                  className="block px-3 py-1.5 text-sm text-foreground hover:bg-secondary truncate"
                >
                  {incident.title}
                </Link>
              ))}
            </div>
          )}

          {results.assets.length > 0 && (
            <div className="py-1 border-t border-secondary">
              <p className="px-3 py-1 text-xs uppercase tracking-wide text-muted-foreground">Assets</p>
              {results.assets.map((asset) => (
                <Link
                  key={asset.id}
                  to={`/assets?q=${encodeURIComponent(asset.host)}`}
                  onClick={() => setOpen(false)}
                  className="block px-3 py-1.5 text-sm text-foreground hover:bg-secondary truncate"
                >
                  {asset.host}
                </Link>
              ))}
            </div>
          )}

          {results.events.length > 0 && (
            <div className="py-1 border-t border-secondary">
              <p className="px-3 py-1 text-xs uppercase tracking-wide text-muted-foreground">Events</p>
              {results.events.map((event) => (
                <Link
                  key={event.id}
                  to={event.incident_id ? `/incidents/${event.incident_id}` : `/events?q=${encodeURIComponent(event.host)}`}
                  onClick={() => setOpen(false)}
                  className="block px-3 py-1.5 text-sm text-foreground hover:bg-secondary truncate"
                  title={event.message}
                >
                  [{event.host}] {event.message}
                </Link>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
