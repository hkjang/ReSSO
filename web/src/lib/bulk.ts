// Doing one thing to many rows, and saying truthfully what happened.
//
// Every destructive action in the console was one row at a time, which is fine
// until the row count is the emergency: an account is compromised and its
// fourteen sessions each need their own dialog. The part that needs care is
// not the loop — it is the report. A sweep that ends eleven of fourteen
// sessions and says "완료" leaves three signed in and an operator who believes
// otherwise, which is the worst of the three possible outcomes.

const concurrency = 4

export interface BulkOutcome {
  succeeded: number
  failed: number
  /** The first failure, to show the operator what went wrong rather than only that something did. */
  error?: unknown
}

/**
 * Apply `action` to every item, a few at a time, and report both halves.
 *
 * Nothing is aborted on the first failure: the remaining rows are exactly the
 * ones the operator still needs acted on, and stopping would leave the result
 * depending on which row happened to be ordered first.
 */
export async function runBulk<T>(items: readonly T[], action: (item: T) => Promise<unknown>): Promise<BulkOutcome> {
  const outcome: BulkOutcome = { succeeded: 0, failed: 0 }
  let next = 0
  // A handful at a time. All at once opens a connection per row and a slow
  // server turns a sweep of two hundred into two hundred simultaneous
  // timeouts; one at a time makes the operator wait for the round trips to
  // add up.
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    for (;;) {
      const index = next++
      if (index >= items.length) return
      try {
        await action(items[index])
        outcome.succeeded += 1
      } catch (error) {
        outcome.failed += 1
        if (outcome.error === undefined) outcome.error = error
      }
    }
  })
  await Promise.all(workers)
  return outcome
}

/** What to tell the operator, and how loudly. */
export function describeBulkOutcome(outcome: BulkOutcome, noun: string): { message: string; severity: 'success' | 'warning' | 'error' } {
  const total = outcome.succeeded + outcome.failed
  if (!outcome.failed) return { message: `${noun} ${outcome.succeeded}건을 처리했습니다.`, severity: 'success' }
  if (!outcome.succeeded) return { message: `${noun} ${total}건을 모두 처리하지 못했습니다.`, severity: 'error' }
  // The number that matters here is what is left undone, so it comes first.
  return { message: `${noun} ${total}건 중 ${outcome.failed}건이 실패했습니다. ${outcome.succeeded}건은 처리했습니다.`, severity: 'warning' }
}
