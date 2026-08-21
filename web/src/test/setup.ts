import '@testing-library/jest-dom/vitest'
import { cleanup } from '@testing-library/react'
import { afterEach } from 'vitest'

// Testing Library only registers its automatic cleanup when Vitest runs with
// `globals: true`, which this project does not. Without it the DOM accumulates
// across cases in the same file and queries start reporting "found multiple
// elements", so the teardown is registered explicitly here.
afterEach(() => {
  cleanup()
})
