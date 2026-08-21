/**
 * Copy text to the clipboard, falling back for non-secure contexts.
 *
 * ReSSO is normally reached over plain HTTP inside an offline network, where
 * `navigator.clipboard` is undefined because the page is not a secure context.
 * Calling it directly threw a TypeError that nothing caught, so the copy
 * buttons for one-time secrets appeared to do nothing at all. The fallback
 * below is deprecated but is the only option available on those origins.
 *
 * Returns whether the text reached the clipboard so callers can tell the user.
 */
export async function copyText(value: string): Promise<boolean> {
  if (!value) return false
  if (navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(value)
      return true
    } catch {
      // Permission denied or a non-secure context: try the fallback below.
    }
  }
  return legacyCopy(value)
}

function legacyCopy(value: string): boolean {
  const area = document.createElement('textarea')
  area.value = value
  // Keep it off-screen and unfocusable-looking without using display:none,
  // which would make the selection impossible.
  area.setAttribute('readonly', '')
  area.style.position = 'fixed'
  area.style.top = '-1000px'
  area.style.opacity = '0'
  document.body.appendChild(area)
  try {
    area.select()
    area.setSelectionRange(0, value.length)
    return document.execCommand('copy')
  } catch {
    return false
  } finally {
    document.body.removeChild(area)
  }
}
