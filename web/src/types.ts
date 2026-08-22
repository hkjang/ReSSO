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
  idle_timeout_seconds: number
  password_min_length: number
  max_login_attempts: number
  lockout_seconds: number
  created_at: string
  updated_at: string
}

export interface User {
  id: string
  realm_id: string
  username: string
  email: string
  email_verified: boolean
  display_name: string
  enabled: boolean
  platform_admin: boolean
  manager_id?: string
  federation_id?: string
  external_id?: string
  external_dn?: string
  federation_synced_at?: string
  failed_attempts: number
  locked_until?: string
  password_changed_at: string
  created_at: string
  updated_at: string
}

export interface LDAPFederation {
  id: string
  realm_id: string
  name: string
  vendor: 'OTHER' | 'AD'
  priority: number
  enabled: boolean
  connection_url: string
  start_tls: boolean
  ca_certificate?: string
  bind_dn: string
  bind_credential_set: boolean
  users_dn: string
  username_ldap_attribute: string
  rdn_ldap_attribute: string
  uuid_ldap_attribute: string
  user_object_classes: string[]
  user_ldap_filter: string
  search_scope: 'ONE_LEVEL' | 'SUBTREE'
  email_ldap_attribute: string
  first_name_ldap_attribute: string
  last_name_ldap_attribute: string
  display_name_ldap_attribute: string
  member_of_ldap_attribute: string
  group_role_mappings: Record<string, string>
  import_enabled: boolean
  sync_registrations: boolean
  missing_user_action: 'KEEP' | 'DISABLE'
  edit_mode: 'READ_ONLY' | 'WRITABLE' | 'UNSYNCED'
  batch_size: number
  sync_period_seconds: number
  next_sync_at?: string
  last_sync_at?: string
  last_sync_status: 'NEVER' | 'RUNNING' | 'SUCCESS' | 'FAILURE'
  last_sync_error?: string
  last_sync_added: number
  last_sync_updated: number
  last_sync_failed: number
  sync_running: boolean
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
  /** Whether the server would still accept this session. Idle expiry refuses
   *  a session well before expires_at, so this cannot be derived here. */
  active: boolean
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
  assigned_users: number
  builtin: boolean
}

export interface ClientRole {
  id: string
  client_id: string
  client_key: string
  name: string
  description: string
  created_at: string
}

export interface UserRoleMappings {
  available_realm_roles: Role[]
  available_client_roles: ClientRole[]
  realm_role_ids: string[]
  federation_realm_role_ids: string[]
  client_role_ids: string[]
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
  realm_name: string
  requester_username: string
  requester_display_name: string
  reviewer_username?: string
  /** Set for ROLE_ASSIGNMENT: the role approving would grant. */
  target_role_name?: string
}

export interface PasswordPolicy {
  min_length: number
  max_login_attempts: number
  lockout_seconds: number
  idle_timeout_seconds: number
}

export interface Me {
  user: User
  roles: string[]
  csrf_token: string
  permissions: { platform_admin: boolean; realm_admin: boolean; admin: boolean }
  password_policy?: PasswordPolicy
}
