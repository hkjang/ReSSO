import { afterEach, expect, test, vi } from 'vitest'
import { recentDestinations, rememberDestination } from './recent'

const menu = ['/admin', '/admin/users', '/admin/clients', '/admin/sessions', '/admin/keys', '/admin/roles']

afterEach(() => {
  window.localStorage.clear()
  vi.restoreAllMocks()
})

test('가장 최근에 방문한 곳이 앞에 온다', () => {
  rememberDestination('/admin/users')
  rememberDestination('/admin/clients')
  expect(recentDestinations(menu)).toEqual(['/admin/clients', '/admin/users'])
})

test('같은 곳을 다시 방문해도 한 번만 남고 맨 앞으로 온다', () => {
  rememberDestination('/admin/users')
  rememberDestination('/admin/clients')
  rememberDestination('/admin/users')
  expect(recentDestinations(menu)).toEqual(['/admin/users', '/admin/clients'])
})

test('다섯 개를 넘기지 않는다', () => {
  for (const path of menu) rememberDestination(path)
  expect(recentDestinations(menu)).toHaveLength(5)
})

// 권한이 줄거나 메뉴가 바뀌면 기억해 둔 경로가 더는 갈 수 없는 곳이 된다. 그것을
// 그대로 내놓으면 팔레트가 메뉴에는 없는 화면으로 보낸다.
test('지금 갈 수 없는 곳은 내놓지 않는다', () => {
  rememberDestination('/admin/logs')
  rememberDestination('/admin/users')
  expect(recentDestinations(menu)).toEqual(['/admin/users'])
})

// 사생활 보호 창이나 저장을 막은 브라우저에서는 접근 자체가 예외를 던진다.
// 기록하지 못하는 것은 편의의 문제지만, 여기서 터지면 팔레트가 열리지 않는다.
test('저장소가 막혀 있어도 터지지 않는다', () => {
  vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('denied') })
  vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('denied') })
  expect(() => rememberDestination('/admin/users')).not.toThrow()
  expect(recentDestinations(menu)).toEqual([])
})

// 손으로 고쳤거나 다른 버전이 남긴 값이 들어 있을 수 있다.
test('저장된 값이 배열이 아니면 무시한다', () => {
  window.localStorage.setItem('resso.recent-destinations', '{"not":"an array"}')
  expect(recentDestinations(menu)).toEqual([])
  window.localStorage.setItem('resso.recent-destinations', 'not json at all')
  expect(recentDestinations(menu)).toEqual([])
})
