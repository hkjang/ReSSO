import { render } from '@testing-library/react'
import { expect, test } from 'vitest'
import { PageHeader } from '../components/Page'

// A single-page application changes route without reloading, so the title is
// the only thing that tells a screen reader the page changed. Every screen was
// called "ReSSO", which also left an administrator with three tabs open unable
// to tell them apart. Taking the name from the heading the page already shows
// means the tab cannot come to say something the page does not.
test('the tab is named after the page being shown', () => {
  const before = document.title
  const view = render(<PageHeader title="SSO 세션" />)
  expect(document.title).toBe('SSO 세션 · ReSSO')

  view.rerender(<PageHeader title="감사 이벤트" />)
  expect(document.title).toBe('감사 이벤트 · ReSSO')

  // Leaving the page puts back what was there, so a screen without a heading
  // does not inherit the last one's name.
  view.unmount()
  expect(document.title).toBe(before)
})
