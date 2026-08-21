import type { KeyboardEvent, MouseEvent } from 'react'

// Anything the user can operate in its own right. A click or key press that
// lands on one of these belongs to it, not to the row around it.
const interactiveSelector = 'button, a, input, select, textarea, [role="button"], [role="checkbox"]'

function fromInteractiveDescendant(target: EventTarget | null): boolean {
  return target instanceof Element && target.closest(interactiveSelector) !== null
}

/**
 * Make a clickable table row reachable from the keyboard.
 *
 * Several lists opened their detail panel only on a mouse click, so the
 * primary action of those screens — opening a client, an audit event, a log
 * line, a role — could not be reached without a pointer.
 *
 * Activation coming from a control inside the row is left to that control, so
 * copying an identifier does not also open the row behind it.
 */
export function rowActivation(onActivate: () => void) {
  return {
    tabIndex: 0,
    onClick: (event: MouseEvent<HTMLElement>) => {
      if (fromInteractiveDescendant(event.target)) return
      onActivate()
    },
    onKeyDown: (event: KeyboardEvent<HTMLElement>) => {
      if (event.target !== event.currentTarget) return
      if (event.key !== 'Enter' && event.key !== ' ') return
      // Space would otherwise scroll the page.
      event.preventDefault()
      onActivate()
    },
  }
}
