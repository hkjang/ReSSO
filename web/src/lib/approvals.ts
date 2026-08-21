const kindLabels: Record<string, string> = {
  ROLE_ASSIGNMENT: 'Role 할당',
  CLIENT_REGISTRATION: 'Client 등록',
  API_KEY_SCOPE: 'API Key 범위',
}

/** The request kind in the reviewer's language rather than the stored constant. */
export function approvalKindLabel(kind: string): string {
  return kindLabels[kind] ?? kind
}
