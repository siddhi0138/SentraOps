import { useCallback, useEffect, useRef, useState } from 'react'
import { api, ApiError } from '../api/client'
import { useAuth } from '../auth/AuthContext'
import { canAct as roleCanAct } from '../auth/roles'
import type { KnowledgeDocument } from '../api/types'

export function KnowledgeBasePage() {
  const { user } = useAuth()
  const canAct = roleCanAct(user?.role)

  const [documents, setDocuments] = useState<KnowledgeDocument[]>([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [seeding, setSeeding] = useState(false)
  const [title, setTitle] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [error, setError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.listKnowledgeDocuments()
      setDocuments(res.documents)
      setError(null)
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load documents')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void load()
  }, [load])

  async function handleUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (!file) return

    setUploading(true)
    setMessage(null)
    setError(null)
    try {
      await api.uploadKnowledgeDocument(file, title || undefined)
      setMessage(`Uploaded "${file.name}"`)
      setTitle('')
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Upload failed')
    } finally {
      setUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  async function handleDelete(id: number) {
    setError(null)
    try {
      await api.deleteKnowledgeDocument(id)
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Delete failed')
    }
  }

  async function handleSeed() {
    setSeeding(true)
    setMessage(null)
    setError(null)
    try {
      const res = await api.seedKnowledgeBaseSamples()
      setMessage(
        res.created.length > 0
          ? `Added ${res.created.length} sample document(s)`
          : 'Sample documents are already loaded'
      )
      await load()
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Failed to load samples')
    } finally {
      setSeeding(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold text-foreground">Knowledge Base</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Upload playbooks, runbooks, or policy documents - the AI assistant grounds its chat answers in these
            alongside your real events and incidents, the same retrieval pipeline either way.
          </p>
        </div>
        {canAct && (
          <button
            onClick={() => void handleSeed()}
            disabled={seeding}
            className="rounded-lg border border-border hover:bg-secondary disabled:opacity-50 text-sm px-3 py-1.5 transition shrink-0"
          >
            {seeding ? 'Loading...' : 'Load Sample Docs'}
          </button>
        )}
      </div>

      {message && <p className="text-sm text-severity-low">{message}</p>}
      {error && <p className="text-sm text-destructive bg-destructive/50 border border-destructive rounded-lg px-3 py-2">{error}</p>}

      {canAct && (
        <div className="panel p-4 flex flex-wrap items-center gap-3">
          <input
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            placeholder="Document title (optional - defaults to filename)"
            className="flex-1 min-w-[220px] rounded-lg border border-border bg-card px-3 py-1.5 text-sm text-foreground placeholder:text-muted-foreground"
          />
          <input
            ref={fileInputRef}
            type="file"
            accept=".txt,.md,text/plain,text/markdown"
            onChange={(e) => void handleUpload(e)}
            disabled={uploading}
            className="text-sm text-foreground file:mr-3 file:rounded-lg file:border file:border-border file:bg-secondary file:px-3 file:py-1.5 file:text-sm file:text-foreground hover:file:bg-secondary/80 disabled:opacity-50"
          />
          {uploading && <span className="text-xs text-muted-foreground">Uploading...</span>}
        </div>
      )}

      {loading && <p className="text-muted-foreground text-sm">Loading...</p>}

      {!loading && (
        <div className="panel divide-y divide-secondary">
          {documents.length === 0 && (
            <p className="text-sm text-muted-foreground p-4">
              No documents yet. Upload one, or click "Load Sample Docs" to try search right away.
            </p>
          )}
          {documents.map((doc) => (
            <div key={doc.id} className="p-4 flex items-start justify-between gap-4">
              <div className="min-w-0">
                <p className="text-sm text-foreground truncate">{doc.title}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  {doc.source === 'seed' ? 'Sample document' : doc.filename ?? 'uploaded'} &middot; {doc.chunk_count}{' '}
                  chunk{doc.chunk_count === 1 ? '' : 's'} &middot; added {new Date(doc.created_at).toLocaleDateString()}
                </p>
              </div>
              {canAct && (
                <button
                  onClick={() => void handleDelete(doc.id)}
                  className="text-xs text-destructive hover:underline shrink-0"
                >
                  Delete
                </button>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
