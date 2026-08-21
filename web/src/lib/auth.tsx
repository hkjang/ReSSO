import { type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api } from './api'
import { AuthContext } from './auth-context'
import type { Me, Meta } from '../types'

export function AuthProvider({ children }: { children: ReactNode }) {
  const queryClient = useQueryClient()
  const metaQuery = useQuery({ queryKey: ['meta'], queryFn: () => api<Meta>('/api/v1/meta'), staleTime: Infinity })
  const meQuery = useQuery({
    queryKey: ['me'],
    queryFn: () => api<Me>('/api/v1/me'),
    retry: false,
    staleTime: 30_000,
  })
  const logout = async () => {
    await api<void>('/api/v1/auth/logout', { method: 'POST' })
    queryClient.setQueryData(['me'], undefined)
    await queryClient.invalidateQueries({ queryKey: ['me'] })
  }
  return (
    <AuthContext.Provider value={{
      me: meQuery.data,
      meta: metaQuery.data,
      loading: meQuery.isLoading,
      authenticated: Boolean(meQuery.data),
      refresh: meQuery.refetch,
      logout,
    }}>
      {children}
    </AuthContext.Provider>
  )
}
