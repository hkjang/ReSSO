#!/usr/bin/env node
// Fills a throwaway ReSSO with demo data and photographs the console for
// docs/USER_GUIDE.md and docs/ADMIN_GUIDE.md.
//
// This script writes. It creates a Realm, users, Clients, Roles, sessions and
// an API key, so pointing it at a deployment somebody uses would leave all of
// that behind in their audit trail. Two things keep that from happening by
// accident:
//
//   - the target comes from RESSO_GUIDE_URL, a variable no other script here
//     reads, and there is no default;
//   - the target must be a loopback address. A capture runs against an
//     instance started for the capture and thrown away afterwards, so refusing
//     everything else costs nothing and removes the whole class of mistake.
//
// It only ever creates new objects. Nothing global is overwritten — the only
// existing record it touches is the Realm it just created, to turn on the
// approval workflow — so there is no prior state to restore.
//
//   POSTGRES_DSN=... BOOTSTRAP_ADMIN=admin BOOTSTRAP_ADMIN_PASSWORD=... ./build/resso &
//   RESSO_GUIDE_URL=http://127.0.0.1:18080 \
//   RESSO_GUIDE_ADMIN=admin RESSO_GUIDE_ADMIN_PASSWORD=... \
//     node scripts/guide-screenshots.mjs
//
// Screenshots land in docs/assets/guide/ at 1440x900, the desktop size the
// guide standard fixes.
import { execFileSync, spawn } from 'node:child_process'
import { mkdirSync, readFileSync, writeFileSync, existsSync, rmSync } from 'node:fs'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const outputDir = path.join(repoRoot, 'docs', 'assets', 'guide')

const VIEWPORT = { width: 1440, height: 900 }
const DEMO_PASSWORD = 'demo-user-pass-1234'

function fail(message) {
  console.error(message)
  process.exit(1)
}

const rawTarget = (process.env.RESSO_GUIDE_URL ?? '').trim()
if (!rawTarget) {
  fail('RESSO_GUIDE_URL is not set. Start a throwaway ReSSO and point this at it, for example\n' +
    '  RESSO_GUIDE_URL=http://127.0.0.1:18080 node scripts/guide-screenshots.mjs')
}
let target
try {
  target = new URL(rawTarget)
} catch {
  fail(`RESSO_GUIDE_URL is not a URL: ${rawTarget}`)
}
if (!['127.0.0.1', 'localhost', '[::1]', '::1'].includes(target.hostname)) {
  fail(`RESSO_GUIDE_URL must be a loopback address; this script seeds demo data and must not reach a real deployment (${target.hostname})`)
}
const base = target.origin

const adminUser = (process.env.RESSO_GUIDE_ADMIN ?? '').trim()
const adminPassword = process.env.RESSO_GUIDE_ADMIN_PASSWORD ?? ''
if (!adminUser || !adminPassword) {
  fail('RESSO_GUIDE_ADMIN and RESSO_GUIDE_ADMIN_PASSWORD are required (the bootstrap administrator of the throwaway instance).')
}

// --- the REST API, as a browser session -------------------------------------

// The session screens name the browser a session was opened from, read out of
// the User-Agent. Node sends "node", which is a truthful but distracting answer
// in a screenshot of what a person's own devices look like, so each seeded
// login says which desktop browser it stands in for.
const AGENTS = {
  chromeWindows: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36',
  edgeWindows: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0',
  safariMac: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15',
}

class Session {
  constructor(userAgent = AGENTS.chromeWindows) {
    this.cookies = new Map()
    this.csrf = ''
    this.userAgent = userAgent
  }

  header() {
    return [...this.cookies].map(([name, value]) => `${name}=${value}`).join('; ')
  }

  absorb(response) {
    for (const raw of response.headers.getSetCookie()) {
      const [pair] = raw.split(';')
      const index = pair.indexOf('=')
      const name = pair.slice(0, index).trim()
      const value = pair.slice(index + 1).trim()
      if (value) this.cookies.set(name, value)
      else this.cookies.delete(name)
    }
  }

  async request(method, urlPath, body) {
    const headers = { Cookie: this.header(), 'User-Agent': this.userAgent }
    if (this.csrf) headers['X-CSRF-Token'] = this.csrf
    if (body !== undefined) headers['Content-Type'] = 'application/json'
    const response = await fetch(base + urlPath, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      redirect: 'manual',
    })
    this.absorb(response)
    const text = await response.text()
    let parsed
    try {
      parsed = text ? JSON.parse(text) : undefined
    } catch {
      parsed = undefined
    }
    return { status: response.status, body: parsed, text }
  }

  async login(realm, username, password) {
    const result = await this.request('POST', '/api/v1/auth/login', { realm, username, password })
    if (result.status !== 200) throw new Error(`login as ${username} failed: ${result.status} ${result.text}`)
    this.csrf = result.body.csrf_token
    return result.body
  }
}

// Creating the same object twice is not an error worth stopping for: a rerun
// against an instance that already has the demo data should still take the
// pictures. Conflicts are reported and skipped, everything else stops.
async function create(session, urlPath, body, what) {
  const result = await session.request('POST', urlPath, body)
  if (result.status === 201 || result.status === 200) return result.body
  if (result.status === 409) {
    console.log(`  ${what} is already there`)
    return null
  }
  throw new Error(`${what} failed: ${result.status} ${result.text}`)
}

async function seed(admin) {
  console.log('seeding demo data')
  const realms = await admin.request('GET', '/api/admin/v1/realms')
  let realm = realms.body.items.find((item) => item.name === 'demo')
  if (!realm) {
    const created = await create(admin, '/api/admin/v1/realms', {
      name: 'demo',
      display_name: '데모 회사',
      issuer_url: 'https://sso.example.com/realms/demo',
    }, 'the demo realm')
    // The creation response carries the Realm as it was built in memory, and
    // the password and lockout policy is defaulted by the database rather than
    // there — so those fields come back as zero. Reading it back is what makes
    // the update below a change of one field rather than a policy of zeroes.
    realm = (await admin.request('GET', `/api/admin/v1/realms/${created.id}`)).body
  }
  const realmPath = `/api/admin/v1/realms/${realm.id}`
  // The approval workflow is off by default and the console hides the two
  // screens that show it, so the guide could not photograph either.
  const enabling = await admin.request('PUT', realmPath, {
    display_name: realm.display_name,
    issuer_url: realm.issuer_url,
    enabled: true,
    approval_enabled: true,
    access_token_ttl_seconds: realm.access_token_ttl_seconds,
    refresh_token_ttl_seconds: realm.refresh_token_ttl_seconds,
    session_ttl_seconds: realm.session_ttl_seconds,
    idle_timeout_seconds: realm.idle_timeout_seconds,
    password_min_length: realm.password_min_length,
    max_login_attempts: realm.max_login_attempts,
    lockout_seconds: realm.lockout_seconds,
  })
  if (enabling.status !== 200) {
    throw new Error(`turning on the approval workflow failed: ${enabling.status} ${enabling.text}`)
  }

  const existingUsers = (await admin.request('GET', `${realmPath}/users?limit=100`)).body.items ?? []
  const byName = new Map(existingUsers.map((user) => [user.username, user]))
  const ensureUser = async (input) => {
    if (byName.has(input.username)) return byName.get(input.username)
    const user = await create(admin, `${realmPath}/users`, input, `user ${input.username}`)
    byName.set(input.username, user)
    return user
  }

  const manager = await ensureUser({
    username: 'park.jihun', email: 'park.jihun@example.com', email_verified: true,
    display_name: '박지훈 (팀장)', password: DEMO_PASSWORD, enabled: true,
  })
  await ensureUser({
    username: 'hong.gildong', email: 'hong.gildong@example.com', email_verified: true,
    display_name: '홍길동', password: DEMO_PASSWORD, enabled: true, manager_id: manager.id,
  })
  await ensureUser({
    username: 'kim.seoyeon', email: 'kim.seoyeon@example.com', email_verified: true,
    display_name: '김서연', password: DEMO_PASSWORD, enabled: true, manager_id: manager.id,
  })
  await ensureUser({
    username: 'lee.junho', email: 'lee.junho@example.com', email_verified: true,
    display_name: '이준호', password: DEMO_PASSWORD, enabled: true, manager_id: manager.id,
  })

  const roleNames = new Set(((await admin.request('GET', `${realmPath}/roles`)).body.items ?? []).map((role) => role.name))
  for (const role of [
    { name: 'employee', description: '임직원 공통 권한' },
    { name: 'billing-manager', description: '정산 화면 관리' },
    { name: 'auditor', description: '감사 이벤트 열람' },
  ]) {
    if (!roleNames.has(role.name)) await create(admin, `${realmPath}/roles`, role, `role ${role.name}`)
  }
  const roles = (await admin.request('GET', `${realmPath}/roles`)).body.items ?? []

  const clientIDs = new Set(((await admin.request('GET', `${realmPath}/clients`)).body.items ?? []).map((client) => client.client_id))
  for (const client of [
    {
      client_id: 'portal-web', name: '사내 포털', type: 'confidential',
      redirect_uris: ['https://portal.example.com/oidc/callback'],
      post_logout_redirect_uris: ['https://portal.example.com/'],
      web_origins: ['https://portal.example.com'],
      grant_types: ['authorization_code', 'refresh_token'],
      default_scopes: ['openid', 'profile', 'email', 'roles'],
      require_pkce: true,
      backchannel_logout_uri: 'https://portal.example.com/oidc/backchannel-logout',
    },
    {
      client_id: 'mobile-app', name: '모바일 근태 앱', type: 'public',
      redirect_uris: ['https://app.example.com/callback', 'http://127.0.0.1:9876/callback'],
      post_logout_redirect_uris: ['https://app.example.com/'],
      web_origins: [],
      grant_types: ['authorization_code', 'refresh_token'],
      default_scopes: ['openid', 'profile'],
      require_pkce: true,
    },
    {
      client_id: 'billing-batch', name: '정산 배치', type: 'confidential',
      redirect_uris: [], post_logout_redirect_uris: [], web_origins: [],
      grant_types: ['client_credentials'], default_scopes: ['openid'], require_pkce: false,
    },
  ]) {
    if (!clientIDs.has(client.client_id)) await create(admin, `${realmPath}/clients`, client, `client ${client.client_id}`)
  }

  // A directory connection, so the federation screen is not an empty state.
  // It names a host that does not exist, which is what the screen looks like
  // between registering a provider and running the connection test.
  const federations = (await admin.request('GET', `${realmPath}/user-federations`)).body.items ?? []
  if (!federations.some((provider) => provider.name === '본사 Active Directory')) {
    await create(admin, `${realmPath}/user-federations`, {
      name: '본사 Active Directory', vendor: 'AD', priority: 0, enabled: true,
      connection_url: 'ldaps://ad.example.com:636', start_tls: false,
      bind_dn: 'CN=resso-bind,OU=Service,DC=example,DC=com',
      bind_credential: 'replace-with-the-bind-password',
      users_dn: 'OU=People,DC=example,DC=com',
      username_ldap_attribute: 'sAMAccountName', rdn_ldap_attribute: 'cn', uuid_ldap_attribute: 'objectGUID',
      user_object_classes: ['person', 'organizationalPerson', 'user'],
      search_scope: 'SUBTREE', email_ldap_attribute: 'mail',
      first_name_ldap_attribute: 'givenName', last_name_ldap_attribute: 'sn',
      display_name_ldap_attribute: 'displayName', member_of_ldap_attribute: 'memberOf',
      group_role_mappings: { 'CN=Billing,OU=Groups,DC=example,DC=com': 'billing-manager' },
      import_enabled: true, sync_registrations: false, missing_user_action: 'DISABLE',
      edit_mode: 'READ_ONLY', batch_size: 500, sync_period_seconds: 3600,
    }, 'the directory connection')
  }

  // Role mappings, so the user list and the role screen are not all zeroes.
  const employee = roles.find((role) => role.name === 'employee')
  const auditor = roles.find((role) => role.name === 'auditor')
  for (const [username, assigned] of [
    ['hong.gildong', [employee]],
    ['kim.seoyeon', [employee, auditor]],
    ['park.jihun', [employee]],
  ]) {
    const user = byName.get(username)
    await admin.request('PUT', `${realmPath}/users/${user.id}/role-mappings`, {
      realm_role_ids: assigned.filter(Boolean).map((role) => role.id),
      client_role_ids: [],
    })
  }

  // Signed-in people, so the session screens have rows. Each browser login
  // also writes the audit events the trail screen shows.
  const people = new Session(AGENTS.safariMac)
  await people.login('demo', 'kim.seoyeon', DEMO_PASSWORD)
  await people.request('POST', '/api/v1/auth/logout')
  const hong = new Session(AGENTS.edgeWindows)
  await hong.login('demo', 'hong.gildong', DEMO_PASSWORD)

  const keys = (await hong.request('GET', '/api/v1/me/api-keys')).body.items ?? []
  if (!keys.some((key) => key.name === '근태 조회 스크립트')) {
    await create(hong, '/api/v1/me/api-keys', { name: '근태 조회 스크립트', scopes: ['api:read'], expires_days: 90 }, 'a personal API key')
  }
  if (!keys.some((key) => key.name === 'MCP 클라이언트')) {
    await create(hong, '/api/v1/me/api-keys', { name: 'MCP 클라이언트', scopes: ['mcp:read'], expires_days: 180 }, 'an MCP API key')
  }

  const requests = (await hong.request('GET', '/api/v1/me/requests')).body.items ?? []
  const billing = roles.find((role) => role.name === 'billing-manager')
  if (billing && !requests.some((request) => request.role_id === billing.id)) {
    await create(hong, '/api/v1/me/requests', {
      role_id: billing.id, reason: '4분기 정산 화면 확인이 필요합니다.',
    }, 'a role request')
  }

  return { realm, hong }
}

// --- Chrome, over the DevTools protocol --------------------------------------

const chromeBinary = ['google-chrome', 'chromium', 'chromium-browser', 'google-chrome-stable'].find((candidate) => {
  try {
    execFileSync('command', ['-v', candidate], { shell: true, stdio: 'ignore' })
    return true
  } catch {
    return false
  }
})
if (!chromeBinary) fail('Chrome/Chromium was not found.')

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}

async function launchChrome() {
  const profile = mkdtempSync(path.join(tmpdir(), 'resso-guide-chrome-'))
  const child = spawn(chromeBinary, [
    '--headless=new', '--no-sandbox', '--disable-gpu', '--hide-scrollbars',
    '--disable-dev-shm-usage', '--force-color-profile=srgb', '--font-render-hinting=none',
    `--window-size=${VIEWPORT.width},${VIEWPORT.height}`,
    `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank',
  ], { stdio: 'ignore' })
  const portFile = path.join(profile, 'DevToolsActivePort')
  for (let attempt = 0; attempt < 100; attempt += 1) {
    if (existsSync(portFile)) {
      const [port] = readFileSync(portFile, 'utf8').split('\n')
      if (port) {
        const version = await fetch(`http://127.0.0.1:${port}/json/version`).then((r) => r.json())
        return { child, profile, webSocketDebuggerUrl: version.webSocketDebuggerUrl }
      }
    }
    await sleep(100)
  }
  child.kill()
  throw new Error('Chrome never reported a DevTools port')
}

class CDP {
  constructor(socket) {
    this.socket = socket
    this.nextID = 1
    this.pending = new Map()
    this.listeners = []
    socket.addEventListener('message', (event) => {
      const message = JSON.parse(event.data)
      if (message.id && this.pending.has(message.id)) {
        const { resolve, reject } = this.pending.get(message.id)
        this.pending.delete(message.id)
        if (message.error) reject(new Error(`${message.error.message} (${JSON.stringify(message.error)})`))
        else resolve(message.result)
        return
      }
      for (const listener of this.listeners) listener(message)
    })
  }

  static async connect(url) {
    const socket = new WebSocket(url)
    await new Promise((resolve, reject) => {
      socket.addEventListener('open', resolve, { once: true })
      socket.addEventListener('error', reject, { once: true })
    })
    return new CDP(socket)
  }

  send(method, params = {}, sessionId) {
    const id = this.nextID++
    const message = { id, method, params }
    if (sessionId) message.sessionId = sessionId
    this.socket.send(JSON.stringify(message))
    return new Promise((resolve, reject) => this.pending.set(id, { resolve, reject }))
  }

  once(method, sessionId, timeoutMs = 30000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.listeners = this.listeners.filter((entry) => entry !== listener)
        reject(new Error(`timed out waiting for ${method}`))
      }, timeoutMs)
      const listener = (message) => {
        if (message.method !== method) return
        if (sessionId && message.sessionId !== sessionId) return
        clearTimeout(timer)
        this.listeners = this.listeners.filter((entry) => entry !== listener)
        resolve(message.params)
      }
      this.listeners.push(listener)
    })
  }
}

class Page {
  constructor(cdp, sessionId) {
    this.cdp = cdp
    this.sessionId = sessionId
  }

  static async open(cdp) {
    const { targetId } = await cdp.send('Target.createTarget', { url: 'about:blank' })
    const { sessionId } = await cdp.send('Target.attachToTarget', { targetId, flatten: true })
    const page = new Page(cdp, sessionId)
    await page.send('Page.enable')
    await page.send('Network.enable')
    await page.send('Runtime.enable')
    await page.send('Emulation.setDeviceMetricsOverride', {
      width: VIEWPORT.width, height: VIEWPORT.height, deviceScaleFactor: 1, mobile: false,
    })
    return page
  }

  send(method, params) {
    return this.cdp.send(method, params, this.sessionId)
  }

  async setCookies(cookies) {
    for (const [name, value] of cookies) {
      await this.send('Network.setCookie', { name, value, url: base, path: '/' })
    }
  }

  async evaluate(expression) {
    const result = await this.send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true })
    if (result.exceptionDetails) throw new Error(`evaluate failed: ${result.exceptionDetails.text}`)
    return result.result.value
  }

  async goto(urlPath) {
    const loaded = this.cdp.once('Page.loadEventFired', this.sessionId)
    await this.send('Page.navigate', { url: base + urlPath })
    await loaded
    await this.settle()
  }

  // A spinner frozen into a screenshot is a retake, so the wait is for the
  // console to have stopped showing one rather than for a fixed delay.
  async settle() {
    for (let attempt = 0; attempt < 100; attempt += 1) {
      const busy = await this.evaluate(
        "document.querySelectorAll('.MuiCircularProgress-root, .MuiSkeleton-root').length",
      )
      if (busy === 0) break
      await sleep(100)
    }
    await sleep(700)
  }

  async shoot(name) {
    const { data } = await this.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
    const file = path.join(outputDir, `${name}.png`)
    writeFileSync(file, Buffer.from(data, 'base64'))
    console.log(`  ${path.relative(repoRoot, file)}`)
  }
}

// React keeps the input's value in its own state, so assigning to .value is
// undone on the next render. The native setter plus an input event is what the
// component actually listens for.
const typeInto = (selector, value) => `
  (() => {
    const field = document.querySelector(${JSON.stringify(selector)})
    const setter = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value').set
    setter.call(field, ${JSON.stringify(value)})
    field.dispatchEvent(new Event('input', { bubbles: true }))
    return true
  })()
`

async function main() {
  const admin = new Session()
  await admin.login('master', adminUser, adminPassword)
  const { realm } = await seed(admin)

  mkdirSync(outputDir, { recursive: true })
  const chrome = await launchChrome()
  const cdp = await CDP.connect(chrome.webSocketDebuggerUrl)
  try {
    console.log('capturing the console')
    const anonymous = await Page.open(cdp)
    await anonymous.goto('/login')
    await anonymous.evaluate(typeInto('input[name="realm"]', 'demo'))
    await anonymous.evaluate(typeInto('input[name="username"]', 'hong.gildong'))
    await anonymous.evaluate(typeInto('input[name="password"]', DEMO_PASSWORD))
    await sleep(300)
    await anonymous.shoot('login')

    const person = await Page.open(cdp)
    const hong = new Session()
    await hong.login('demo', 'hong.gildong', DEMO_PASSWORD)
    await person.setCookies(hong.cookies)
    for (const [urlPath, name] of [
      ['/personal', 'personal-profile'],
      ['/personal/security', 'personal-security'],
      ['/personal/api-keys', 'personal-api-keys'],
      ['/personal/sessions', 'personal-sessions'],
      ['/personal/requests', 'personal-requests'],
    ]) {
      await person.goto(urlPath)
      await person.shoot(name)
    }

    const administration = await Page.open(cdp)
    await administration.setCookies(admin.cookies)
    // Every administrative screen but the dashboard is scoped to a Realm, and
    // that selection travels in the query string.
    const scoped = `?realm=${encodeURIComponent(realm.name)}`
    for (const [urlPath, name] of [
      ['/admin', 'admin-dashboard'],
      ['/admin/realms', 'admin-realms'],
      ['/admin/users', 'admin-users'],
      ['/admin/clients', 'admin-clients'],
      ['/admin/roles', 'admin-roles'],
      ['/admin/sessions', 'admin-sessions'],
      ['/admin/keys', 'admin-keys'],
      ['/admin/api-keys', 'admin-api-keys'],
      ['/admin/approvals', 'admin-approvals'],
      ['/admin/audit', 'admin-audit'],
      ['/admin/logs', 'admin-logs'],
      ['/admin/user-federation', 'admin-user-federation'],
      ['/admin/integrations', 'admin-integrations'],
    ]) {
      await administration.goto(urlPath + scoped)
      await administration.shoot(name)
    }
  } finally {
    // Chrome is still writing its profile when kill() returns, so removing the
    // directory straight away raced it and ended the run on ENOTEMPTY after
    // every screenshot had already been written.
    const exited = new Promise((resolve) => chrome.child.once('exit', resolve))
    chrome.child.kill()
    await Promise.race([exited, sleep(5000)])
    for (let attempt = 0; attempt < 5; attempt += 1) {
      try {
        rmSync(chrome.profile, { recursive: true, force: true })
        break
      } catch (error) {
        if (attempt === 4) console.log(`  left ${chrome.profile} behind: ${error.message}`)
        else await sleep(500)
      }
    }
  }
  console.log('done')
}

await main()
