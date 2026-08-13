import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { api } from './api'
import type { Realm } from '../types'

export function useRealms() {
  return useQuery({ queryKey: ['realms'], queryFn: () => api<{ items: Realm[] }>('/api/admin/v1/realms'), staleTime: 30_000 })
}

export function useRealmSelection(realms: Realm[] | undefined) {
  const [realmID, setRealmIDState] = useState(() => localStorage.getItem('resso.admin.realm') ?? '')
  useEffect(() => {
    if (!realms?.length) return
    if (!realms.some((realm) => realm.id === realmID)) {
      setRealmIDState(realms[0].id)
      localStorage.setItem('resso.admin.realm', realms[0].id)
    }
  }, [realms, realmID])
  const setRealmID = (value: string) => {
    setRealmIDState(value)
    localStorage.setItem('resso.admin.realm', value)
  }
  return { realmID, setRealmID, realm: realms?.find((realm) => realm.id === realmID) }
}
