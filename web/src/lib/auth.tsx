import { useEffect, useRef, useState, type ReactNode } from 'react'
import { useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query'
import { api } from './api'
import { AuthContext } from './auth-context'
import { onUnauthenticated } from './session'
import type { Me, Meta } from '../types'

// setQueryData(key, undefined) is a no-op in React Query, and a query that
// fails to refetch keeps its last successful data. Clearing the identity with
// either of those left the console believing the user was still signed in, so
// the cache entry is removed outright.
function forgetIdentity(queryClient: QueryClient): void {
  queryClient.removeQueries({ queryKey: ['me'] })
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const metaQuery = useQuery({ queryKey: ['meta'], queryFn: () => api<Meta>('/api/v1/meta'), staleTime: Infinity })
  const meQuery = useQuery({
    queryKey: ['me'],
    queryFn: () => api<Me>('/api/v1/me'),
    retry: false,
    staleTime: 30_000,
  })
  const [sessionExpired, setSessionExpired] = useState(false)
  // Signing out deliberately also produces rejected requests; only an
  // unexpected rejection while signed in counts as an expiry.
  const signingOut = useRef(false)

  useEffect(() => onUnauthenticated(() => {
    // Read the cache at notification time rather than closing over a value
    // captured during render.
    if (signingOut.current || !queryClient.getQueryData(['me'])) return
    setSessionExpired(true)
    forgetIdentity(queryClient)
  }), [queryClient])

  const logout = async () => {
    signingOut.current = true
    try {
      await api<void>('/api/v1/auth/logout', { method: 'POST' })
    } finally {
      setSessionExpired(false)
      forgetIdentity(queryClient)
      signingOut.current = false
    }
  }
  return (
    <AuthContext.Provider value={{
      me: meQuery.data,
      meta: metaQuery.data,
      loading: meQuery.isLoading,
      authenticated: Boolean(meQuery.data),
      refresh: meQuery.refetch,
      logout,
      sessionExpired,
    }}>
      {children}
    </AuthContext.Provider>
  )
}
