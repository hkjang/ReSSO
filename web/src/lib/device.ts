/**
 * Turn a User-Agent string into something a person can recognise.
 *
 * The session lists showed the raw header, so a user deciding which session to
 * end read "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 …"
 * instead of "Chrome · Windows". Detection is deliberately coarse: the goal is
 * for someone to recognise their own device, not to fingerprint it.
 */
export function describeDevice(userAgent?: string): string {
  const agent = (userAgent ?? '').trim()
  if (!agent) return '알 수 없는 클라이언트'
  const browser = detectBrowser(agent)
  const platform = detectPlatform(agent)
  if (!browser && !platform) return agent.length > 48 ? `${agent.slice(0, 48)}…` : agent
  if (!platform) return browser
  if (!browser) return platform
  return `${browser} · ${platform}`
}

function detectBrowser(agent: string): string {
  // Order matters: Edge and Chrome both advertise Safari, and Chromium-based
  // Edge also advertises Chrome.
  const candidates: Array<[RegExp, string]> = [
    [/Edg[A-Z]?\//, 'Edge'],
    [/OPR\/|Opera/, 'Opera'],
    [/Whale\//, 'Whale'],
    [/SamsungBrowser\//, 'Samsung Internet'],
    [/Firefox\//, 'Firefox'],
    [/Chrome\//, 'Chrome'],
    [/Safari\//, 'Safari'],
    [/curl\//i, 'curl'],
    [/PostmanRuntime/i, 'Postman'],
    [/python-requests/i, 'Python requests'],
    [/Go-http-client/i, 'Go client'],
  ]
  for (const [pattern, name] of candidates) {
    if (pattern.test(agent)) return name
  }
  return ''
}

function detectPlatform(agent: string): string {
  const candidates: Array<[RegExp, string]> = [
    [/Windows NT 10|Windows NT 11/, 'Windows'],
    [/Windows/, 'Windows'],
    [/iPhone/, 'iPhone'],
    [/iPad/, 'iPad'],
    [/Android/, 'Android'],
    [/Mac OS X|Macintosh/, 'macOS'],
    [/CrOS/, 'ChromeOS'],
    [/Linux/, 'Linux'],
  ]
  for (const [pattern, name] of candidates) {
    if (pattern.test(agent)) return name
  }
  return ''
}
