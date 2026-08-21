export const EMAIL_MAX_LENGTH = 320

export function normalizeEmail(value?: string): string {
  return (value ?? '').trim().toLowerCase()
}
