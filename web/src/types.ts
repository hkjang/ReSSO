export interface Meta {
  product: string
  version: string
  commit: string
  build_time: string
  go_version: string
}

export interface Realm {
  id: string
  name: string
  display_name: string
  issuer_url: string
  enabled: boolean
  approval_enabled: boolean
  access_token_ttl_seconds: number
  refresh_token_ttl_seconds: number
  session_ttl_seconds: number
  created_at: string
  updated_at: string
}

export interface User {
  id: string
  realm_id: string
  username: string
  email: string
  display_name: string
  enabled: boolean
  platform_admin: boolean
  manager_id?: string
  failed_attempts: number
  locked_until?: string
  password_changed_at: string
  created_at: string
  updated_at: string
}

export interface Client {
  id: string
  realm_id: string
  client_id: string
  name: string
  type: 'public' | 'confidential'
  redirect_uris: string[]
  post_logout_redirect_uris: string[]
  web_origins: string[]
  grant_types: string[]
  default_scopes: string[]
  require_pkce: boolean
  enabled: boolean
  access_token_ttl_seconds: number
  refresh_token_ttl_seconds: number
  backchannel_logout_uri?: string
  created_at: string
  updated_at: string
}

export interface Session {
  id: string
  realm_id: string
  user_id: string
  username?: string
  ip_address: string
  user_agent: string
  auth_method: string
  created_at: string
  last_access: string
  expires_at: string
  revoked_at?: string
}

export interface SigningKey {
  id: string
  realm_id: string
  kid: string
  algorithm: string
  status: string
  created_at: string
  retire_at?: string
}

export interface Role {
  id: string
  realm_id: string
  name: string
  description: string
  created_at: string
}

export interface APIKey {
  id: string
  name: string
  prefix: string
  scopes: string[]
  created_at: string
  expires_at?: string
  last_used_at?: string
  revoked_at?: string
  rotated_from?: string
}

export interface ApprovalRequest {
  id: string
  realm_id: string
  requester_id: string
  reviewer_id?: string
  kind: string
  payload: Record<string, unknown>
  reason: string
  status: string
  decision_note: string
  created_at: string
  decided_at?: string
}

export interface Me {
  user: User
  roles: string[]
  csrf_token: string
  permissions: { platform_admin: boolean }
}
