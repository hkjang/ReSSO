import { createContext, useContext } from 'react'

export type ToastSeverity = 'success' | 'info' | 'warning' | 'error'

export interface ToastContextValue {
  notify: (text: string, severity?: ToastSeverity) => void
}

// Kept apart from the provider component so that the module exporting the
// provider exports nothing else, which is what Fast Refresh requires.
export const ToastContext = createContext<ToastContextValue | null>(null)

export function useToast(): ToastContextValue {
  const context = useContext(ToastContext)
  // Falling back to a no-op keeps components usable in tests that render them
  // without the provider.
  return context ?? { notify: () => undefined }
}
