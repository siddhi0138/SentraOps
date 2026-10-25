import { useEffect, useState } from 'react'

// localStorage, so results (AI answers, briefings, action messages, chat) survive a
// refresh, switching tabs, and closing the browser. Three rules keep that safe:
//  - everything is cleared on logout, and whenever a different user signs in, so one
//    person's data is never shown to the next person on the same computer;
//  - each entry expires after 7 days, so a stale AI answer doesn't linger forever;
//  - the underlying records (events, incidents, runs) always come fresh from the
//    server - this only keeps what a screen was last showing.
const PREFIX = 'sentraops:persist:'
const OWNER_KEY = 'sentraops:persist-owner'
const MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000

interface Stored<T> {
  v: T
  t: number
}

function readKey<T>(key: string, fallback: T | null): T | null {
  try {
    const raw = localStorage.getItem(PREFIX + key)
    if (!raw) return fallback
    const stored = JSON.parse(raw) as Stored<T>
    if (typeof stored?.t !== 'number' || Date.now() - stored.t > MAX_AGE_MS) {
      localStorage.removeItem(PREFIX + key)
      return fallback
    }
    return stored.v
  } catch {
    return fallback
  }
}

/** Removes every saved screen result, e.g. on logout. */
export function clearPersistedState() {
  try {
    const keys: string[] = []
    for (let i = 0; i < localStorage.length; i++) {
      const k = localStorage.key(i)
      if (k && k.startsWith(PREFIX)) keys.push(k)
    }
    keys.forEach((k) => localStorage.removeItem(k))
    localStorage.removeItem(OWNER_KEY)
  } catch {
    // storage unavailable - nothing was saved anyway
  }
}

/** Call when a user signs in: clears saved results if they belong to someone else. */
export function adoptPersistedStateFor(userId: number) {
  try {
    const owner = localStorage.getItem(OWNER_KEY)
    if (owner !== String(userId)) {
      clearPersistedState()
      localStorage.setItem(OWNER_KEY, String(userId))
    }
  } catch {
    // storage unavailable - nothing to adopt
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
        localStorage.removeItem(PREFIX + key)
      } else {
        const stored: Stored<T> = { v: value, t: Date.now() }
        localStorage.setItem(PREFIX + key, JSON.stringify(stored))
      }
    } catch {
      // localStorage can throw in private-browsing/quota-exceeded cases -
      // losing the cache on refresh is an acceptable degradation, not worth
      // surfacing an error for.
    }
  }, [key, value])

  return [value, setValue] as const
}
