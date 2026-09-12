// The console's side of a protected action.
//
// The server refuses an action that hands out access — a password reset, a
// role grant, a rotated secret or key, a new API key — unless the password was
// confirmed in the last few minutes. Handling that refusal in each of the nine
// places would put the same dialog in nine files and leave the tenth out when
// the list grows, so it is handled once: the API layer sees the refusal, asks
// for the password, and repeats the request the caller already made. Nothing
// above it has to know a protected action is protected.

export const reauthenticationRequired = 'reauthentication_required'

type Prompt = () => Promise<boolean>

let prompt: Prompt | null = null
let pending: Promise<boolean> | null = null

/** Install the dialog that asks. Called once, by the provider at the app root. */
export function setReauthenticationPrompt(next: Prompt | null): void {
  prompt = next
}

/**
 * Ask for the password, and report whether it was confirmed.
 *
 * Concurrent callers share one prompt. A bulk action that revokes fourteen
 * things fails fourteen times at once, and fourteen stacked password dialogs
 * is not a security measure — it is a reason to stop using the console.
 */
export function confirmIdentity(): Promise<boolean> {
  if (!prompt) return Promise.resolve(false)
  if (!pending) {
    pending = prompt().finally(() => { pending = null })
  }
  return pending
}
