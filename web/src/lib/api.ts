export class APIError extends Error {
  status: number
  code: string
  traceId?: string
  /** Seconds the caller must wait, taken from the Retry-After response header. */
  retryAfterSeconds?: number

  constructor(status: number, code: string, message: string, traceId?: string, retryAfterSeconds?: number) {
    super(message)
    this.name = 'APIError'
    this.status = status
    this.code = code
    this.traceId = traceId
    this.retryAfterSeconds = retryAfterSeconds
  }
}

function retryAfter(response: Response): number | undefined {
  const header = response.headers.get('Retry-After')
  if (!header) return undefined
  const seconds = Number(header)
  return Number.isFinite(seconds) && seconds > 0 ? Math.ceil(seconds) : undefined
}

function cookie(name: string): string {
  const prefix = `${name}=`
  const value = document.cookie.split(';').map((part) => part.trim()).find((part) => part.startsWith(prefix))
  return value ? decodeURIComponent(value.slice(prefix.length)) : ''
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  headers.set('Accept', 'application/json')
  if (init.body && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json')
  if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    const csrf = cookie('resso_csrf')
    if (csrf) headers.set('X-CSRF-Token', csrf)
  }
  const response = await fetch(path, { ...init, headers, credentials: 'same-origin' })
  if (!response.ok) {
    let body: { error?: string; message?: string; error_description?: string; trace_id?: string } = {}
    try { body = await response.json() } catch { /* non-JSON proxy error */ }
    throw new APIError(response.status, body.error ?? 'request_failed', body.message ?? body.error_description ?? `요청이 실패했습니다 (${response.status})`, body.trace_id, retryAfter(response))
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}

export const jsonBody = (value: unknown): Pick<RequestInit, 'body'> => ({ body: JSON.stringify(value) })
