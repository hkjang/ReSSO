import { createContext, useContext } from 'react'
import type { Me, Meta } from '../types'

export interface AuthContextValue {
  me?: Me
  meta?: Meta
  loading: boolean
  authenticated: boolean
  refresh: () => Promise<unknown>
  logout: () => Promise<void>
}

// The context and its hook live apart from the provider component so that
// editing either one keeps working with Fast Refresh, which is disabled for a
// module that exports both a component and something else.
export const AuthContext = createContext<AuthContextValue | null>(null)

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext)
  if (!context) throw new Error('useAuth must be used inside AuthProvider')
  return context
}
