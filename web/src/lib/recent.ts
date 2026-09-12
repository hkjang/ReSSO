// Where this administrator was last, so the palette can offer it before they
// have typed anything.
//
// An operator's day is a handful of screens visited over and over — the
// research on enterprise consoles is blunt about it: the same task a hundred
// times, and seconds saved compound into hours. A palette that shows the whole
// menu in a fixed order makes them read past the same nine entries every time
// to reach the two they actually use.
//
// This is a per-browser convenience and nothing more. It holds paths the
// console itself defines, never a name, an identifier or anything read from a
// record, so a shared machine leaks no tenant data through it.

const storageKey = 'resso.recent-destinations'
const maximumRemembered = 5

// Every accessor is guarded. Private windows, cleared site data and browsers
// configured to refuse storage all throw here rather than returning empty, and
// a palette that cannot open is a worse failure than one with no history.
function read(): string[] {
  try {
    const raw = window.localStorage.getItem(storageKey)
    if (!raw) return []
    const parsed: unknown = JSON.parse(raw)
    if (!Array.isArray(parsed)) return []
    return parsed.filter((entry): entry is string => typeof entry === 'string')
  } catch {
    return []
  }
}

/**
 * The paths visited most recently, newest first.
 *
 * `allowed` is the set of destinations this administrator may currently reach.
 * A path that was remembered before a permission was withdrawn — or before the
 * menu entry it names was removed — is dropped rather than offered, so the
 * palette never leads anywhere the menu itself would not.
 */
export function recentDestinations(allowed: Iterable<string>): string[] {
  const reachable = new Set(allowed)
  return read().filter((path) => reachable.has(path)).slice(0, maximumRemembered)
}

/** Record a visit, moving the path to the front without duplicating it. */
export function rememberDestination(path: string): void {
  const next = [path, ...read().filter((entry) => entry !== path)].slice(0, maximumRemembered)
  try {
    window.localStorage.setItem(storageKey, JSON.stringify(next))
  } catch {
    // Remembering is a convenience; failing to is not worth an error.
  }
}
