import { useEffect } from 'react'

export const APP_NAME = 'ReSSO'

/**
 * Names the browser tab after the page being shown.
 *
 * A single-page application changes route without reloading, so the title is
 * the one thing that tells a screen reader the page changed at all — nothing
 * else about the navigation is announced. It also settles two ordinary
 * annoyances: an administrator with users, sessions and the audit log open in
 * three tabs saw "ReSSO" on all of them, and every entry in browser history
 * carried the same name.
 *
 * The value comes from the same string the page already displays as its
 * heading, so the tab cannot come to say something the page does not.
 */
export function useDocumentTitle(title: string) {
  useEffect(() => {
    const previous = document.title
    document.title = title ? `${title} · ${APP_NAME}` : APP_NAME
    return () => { document.title = previous }
  }, [title])
}
