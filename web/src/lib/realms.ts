import { useEffect, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { api } from './api'
import type { Realm } from '../types'

const STORAGE_KEY = 'resso.admin.realm'

export function useRealms() {
  return useQuery({ queryKey: ['realms'], queryFn: () => api<{ items: Realm[] }>('/api/admin/v1/realms'), staleTime: 30_000 })
}

/**
 * Resolve the Realm an administration page is working in.
 *
 * The selection used to live only in localStorage, so a link to "the users
 * page" opened in whatever Realm the recipient happened to have selected last
 * — which made it impossible to share or bookmark a screen, and made
 * screenshots ambiguous. The Realm name now travels in the query string and is
 * the source of truth; localStorage only remembers the last choice for a fresh
 * visit with no `realm` parameter.
 */
export function useRealmSelection(realms: Realm[] | undefined) {
  const [params, setParams] = useSearchParams()
  const requested = params.get('realm') ?? ''
  const realm = useMemo(() => {
    if (!realms?.length) return undefined
    const fromURL = realms.find((item) => item.name === requested)
    if (fromURL) return fromURL
    const remembered = realms.find((item) => item.id === readStored())
    return remembered ?? realms[0]
  }, [realms, requested])

  useEffect(() => {
    if (!realm) return
    writeStored(realm.id)
    if (params.get('realm') === realm.name) return
    const next = new URLSearchParams(params)
    next.set('realm', realm.name)
    // Replace rather than push: landing on a page should not add a history
    // entry the back button has to step through.
    setParams(next, { replace: true })
  }, [realm, params, setParams])

  const setRealmID = (id: string) => {
    const target = realms?.find((item) => item.id === id)
    if (!target) return
    writeStored(target.id)
    const next = new URLSearchParams(params)
    next.set('realm', target.name)
    setParams(next)
  }

  return { realmID: realm?.id ?? '', setRealmID, realm }
}

// Storage can throw in a locked-down browser profile; a missing preference is
// not worth breaking the page over.
function readStored(): string {
  try {
    return localStorage.getItem(STORAGE_KEY) ?? ''
  } catch {
    return ''
  }
}

function writeStored(value: string): void {
  try {
    localStorage.setItem(STORAGE_KEY, value)
  } catch {
    // Ignore: the URL already carries the selection.
  }
}
