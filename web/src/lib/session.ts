type Listener = () => void

const listeners = new Set<Listener>()

/**
 * Announce that the server rejected a request for lack of a session.
 *
 * React Query caches `me` and does not refetch on window focus, so once a
 * session ended the console kept rendering the signed-in shell: every panel
 * failed with "로그인이 필요합니다" and nothing sent the user to log in again.
 * The API layer reports the rejection here and the auth provider turns it into
 * a redirect.
 */
export function reportUnauthenticated(): void {
  for (const listener of listeners) listener()
}

export function onUnauthenticated(listener: Listener): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}
