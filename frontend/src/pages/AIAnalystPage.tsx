import { useEffect, useRef, useState } from 'react'
import ReactMarkdown from 'react-markdown'
import { Link } from 'react-router-dom'
import { api, ApiError } from '../api/client'
import type { RagResult } from '../api/types'

interface ChatMessage {
  role: 'user' | 'assistant'
  content: string
  sources?: RagResult[]
  error?: boolean
}

const EXAMPLE_QUESTIONS = [
  'Summarize today\'s attacks.',
  'Why is this incident critical?',
  'Which users look compromised?',
  'What is privilege escalation?',
]

function SourceChip({ source }: { source: RagResult }) {
  const label = source.content_id ? `${source.content_type} #${source.content_id}` : source.content_type
  const inner = (
    <span className="inline-block px-2 py-0.5 rounded bg-secondary border border-border text-xs text-foreground hover:border-primary hover:text-primary transition">
      {label}
    </span>
  )
  return source.content_type === 'incident' && source.content_id ? (
    <Link to={`/incidents/${source.content_id}`}>{inner}</Link>
  ) : (
    inner
  )
}

export function AIAnalystPage() {
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  async function send(question: string) {
    const trimmed = question.trim()
    if (!trimmed || sending) return

    setMessages((prev) => [...prev, { role: 'user', content: trimmed }])
    setInput('')
    setSending(true)

    try {
      const response = await api.chat(trimmed)
      setMessages((prev) => [...prev, { role: 'assistant', content: response.answer, sources: response.sources }])
    } catch (err) {
      const message = err instanceof ApiError ? err.message : 'Failed to reach the AI analyst'
      setMessages((prev) => [...prev, { role: 'assistant', content: message, error: true }])
    } finally {
      setSending(false)
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    void send(input)
  }

  return (
    <div className="flex flex-col h-[calc(100vh-8rem)]">
      <h1 className="text-lg font-semibold text-foreground mb-4">AI Security Analyst</h1>

      <div className="flex-1 overflow-y-auto panel p-4 space-y-4">
        {messages.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center gap-4 py-12">
            <p className="text-muted-foreground text-sm max-w-sm">
              Ask about events, incidents, or general security concepts. Answers are grounded in this platform's own
              data via semantic search - not a generic chatbot.
            </p>
            <div className="flex flex-wrap gap-2 justify-center max-w-md">
              {EXAMPLE_QUESTIONS.map((q) => (
                <button
                  key={q}
                  onClick={() => void send(q)}
                  className="text-xs px-3 py-1.5 rounded-lg border border-border text-foreground hover:border-primary hover:text-primary transition"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((message, i) => (
          <div key={i} className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}>
            <div
              className={`max-w-[85%] rounded-xl px-4 py-2.5 text-sm ${
                message.role === 'user'
                  ? 'bg-primary text-white'
                  : message.error
                    ? 'bg-destructive/50 border border-destructive text-destructive'
                    : 'bg-secondary text-foreground'
              }`}
            >
              {message.role === 'assistant' && !message.error ? (
                <div className="prose prose-invert prose-sm max-w-none prose-p:my-1.5 prose-ul:my-1.5">
                  <ReactMarkdown>{message.content}</ReactMarkdown>
                </div>
              ) : (
                <p className="whitespace-pre-wrap">{message.content}</p>
              )}

              {message.sources && message.sources.length > 0 && (
                <div className="mt-2 pt-2 border-t border-border flex flex-wrap gap-1.5">
                  {message.sources.map((source, j) => (
                    <SourceChip key={j} source={source} />
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}

        {sending && (
          <div className="flex justify-start">
            <div className="rounded-xl px-4 py-2.5 bg-secondary text-muted-foreground text-sm">Thinking...</div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      <form onSubmit={handleSubmit} className="mt-4 flex gap-2">
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask the AI analyst..."
          disabled={sending}
          className="flex-1 rounded-lg bg-secondary border border-border px-4 py-2.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary disabled:opacity-50"
        />
        <button
          type="submit"
          disabled={sending || !input.trim()}
          className="rounded-lg bg-primary hover:bg-primary disabled:opacity-50 text-white text-sm font-medium px-5 py-2.5 transition"
        >
          Send
        </button>
      </form>
    </div>
  )
}
