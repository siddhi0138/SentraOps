import { useEffect, useState } from 'react'

// sessionStorage, not localStorage - this is for caching real AI-generated
// output (incident analysis, briefings, NL search results) across a refresh
// within the same tab session, not permanent data. Clearing on tab close is
// correct: the underlying incident/data can change, and a stale AI answer
// from days ago showing up unprompted would be worse than regenerating.
function readKey<T>(key: string, fallback: T | null): T | null {
  try {
    const raw = sessionStorage.getItem(key)
    return raw ? (JSON.parse(raw) as T) : fallback
  } catch {
    return fallback
  }
}

export function usePersistentState<T>(key: string, initial: T | null = null) {
  const [value, setValue] = useState<T | null>(() => readKey(key, initial))

  // Re-sync from storage when the key itself changes (e.g. navigating from
  // one incident's detail page to another without unmounting) - otherwise
  // this would keep showing the previous key's cached value under the new
  // key until something else overwrote it.
  useEffect(() => {
    setValue(readKey<T>(key, null))
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key])

  useEffect(() => {
    try {
      if (value === null) {
        sessionStorage.removeItem(key)
      } else {
        sessionStorage.setItem(key, JSON.stringify(value))
      }
    } catch {
      // sessionStorage can throw in private-browsing/quota-exceeded cases -
      // losing the cache on refresh is an acceptable degradation, not worth
      // surfacing an error for.
    }
  }, [key, value])

  return [value, setValue] as const
}
