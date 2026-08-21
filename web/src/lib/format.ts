export function formatDate(value?: string): string {
  if (!value) return '—'
  return new Intl.DateTimeFormat('ko-KR', { dateStyle: 'medium', timeStyle: 'short' }).format(new Date(value))
}

/**
 * A timestamp precise to the second.
 *
 * The compact format above stops at minutes, which is fine for "created at"
 * columns but hides the ordering of audit events and log lines that land in
 * the same minute — exactly when that ordering matters most.
 */
export function formatTimestamp(value?: string): string {
  if (!value) return '—'
  return new Intl.DateTimeFormat('ko-KR', { dateStyle: 'short', timeStyle: 'medium' }).format(new Date(value))
}

export function shortId(value: string): string {
  return value.length > 15 ? `${value.slice(0, 8)}…${value.slice(-4)}` : value
}
