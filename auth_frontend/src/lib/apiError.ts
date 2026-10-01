import { AxiosError } from 'axios'
import type { ApiErrorResponse } from '../types/auth'

export function getApiErrorMessage(
  error: AxiosError<ApiErrorResponse>,
  fallback = 'Something went wrong.',
): string {
  const data = error.response?.data
  if (data?.validationErrors) {
    const first = Object.values(data.validationErrors).find(Boolean)
    if (first) return first
  }
  return data?.message || fallback
}
