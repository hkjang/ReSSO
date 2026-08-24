import { describe, expect, test } from 'vitest'
import { theme } from './theme'

// WCAG 2.1 relative luminance (SC 1.4.3). 콘솔의 상태 문구 — 대시보드 준비 상태,
// 서명 키 회전 권고, 비밀번호 조건 체크리스트 — 는 팔레트 색을 그대로 글자색으로 쓴다.
// 배경으로만 쓰인다면 3:1이면 되지만 글자로 쓰이는 이상 4.5:1을 넘어야 하고,
// 팔레트를 손볼 때 그 사실을 잊기 쉬워서 여기서 계산해 막는다.
function channel(value: number): number {
  const c = value / 255
  return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4
}

function luminance(hex: string): number {
  const raw = hex.replace('#', '')
  // #fff 같은 축약형도 팔레트에 섞여 있다. 형식을 못 읽으면 NaN이 되어
  // 비교가 조용히 통과해버리므로, 여기서 분명히 실패시킨다.
  const h = raw.length === 3 ? raw.replace(/./g, (c) => c + c) : raw
  if (!/^[0-9a-fA-F]{6}$/.test(h)) throw new Error(`대비를 계산할 수 없는 색 형식: ${hex}`)
  const [r, g, b] = [0, 2, 4].map((i) => parseInt(h.slice(i, i + 2), 16))
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b)
}

export function contrast(foreground: string, background: string): number {
  const [a, b] = [luminance(foreground), luminance(background)]
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)
}

const surfaces = [
  ['카드 배경', theme.palette.background.paper],
  ['페이지 배경', theme.palette.background.default],
] as const

const foregrounds = [
  ['본문', theme.palette.text.primary],
  ['보조 설명', theme.palette.text.secondary],
  ['강조/링크', theme.palette.primary.main],
  ['오류', theme.palette.error.main],
  ['경고', theme.palette.warning.main],
  ['성공', theme.palette.success.main],
] as const

describe('팔레트는 본문 글자 대비 기준(AA, 4.5:1)을 지킨다', () => {
  for (const [surfaceName, surface] of surfaces) {
    for (const [name, color] of foregrounds) {
      test(`${surfaceName} 위의 ${name} 글자`, () => {
        expect(contrast(color, surface)).toBeGreaterThanOrEqual(4.5)
      })
    }
  }
})

test('흰 글자를 얹는 채움 버튼과 칩도 같은 기준을 지킨다', () => {
  for (const [name, color] of foregrounds.slice(2)) {
    expect(contrast(theme.palette.common.white, color), name).toBeGreaterThanOrEqual(4.5)
  }
})
