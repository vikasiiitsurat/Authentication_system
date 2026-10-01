import axios, { AxiosError, type InternalAxiosRequestConfig } from 'axios'
import { AUTH_SESSION_KEY, type StoredAuthSession } from '../constants/storage'
import { getDeviceId } from '../lib/deviceId'
import type { LoginResponse } from '../types/auth'

export const apiClient = axios.create({
  baseURL: '/',
  headers: {
    'Content-Type': 'application/json',
  },
})

const plainClient = axios.create({
  baseURL: '/',
  headers: {
    'Content-Type': 'application/json',
  },
})

let accessToken: string | null = null
let refreshToken: string | null = null

const NO_BEARER_PREFIXES = [
  '/api/auth/login',
  '/api/auth/register',
  '/api/auth/refresh',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
  '/api/auth/verify-email',
  '/api/auth/resend-verification-otp',
  '/api/auth/request-account-unlock',
  '/api/auth/unlock-account',
]

function pathSkipsBearer(url: string): boolean {
  return NO_BEARER_PREFIXES.some((p) => url.startsWith(p))
}

export function setSessionTokens(access: string | null, refresh: string | null) {
  accessToken = access
  refreshToken = refresh
}

export function persistSession(data: LoginResponse) {
  const session: StoredAuthSession = {
    accessToken: data.accessToken,
    refreshToken: data.refreshToken,
    expiresInSeconds: data.expiresInSeconds,
  }
  localStorage.setItem(AUTH_SESSION_KEY, JSON.stringify(session))
  setSessionTokens(data.accessToken, data.refreshToken)
}

export function clearPersistedSession() {
  localStorage.removeItem(AUTH_SESSION_KEY)
  setSessionTokens(null, null)
}

export function loadSessionFromStorage(): void {
  const raw = localStorage.getItem(AUTH_SESSION_KEY)
  if (!raw) return
  try {
    const s: StoredAuthSession = JSON.parse(raw)
    setSessionTokens(s.accessToken, s.refreshToken)
  } catch {
    localStorage.removeItem(AUTH_SESSION_KEY)
  }
}

export function getRefreshToken(): string | null {
  return refreshToken
}

apiClient.interceptors.request.use((config) => {
  const url = config.url || ''
  if (accessToken && !pathSkipsBearer(url)) {
    config.headers.Authorization = `Bearer ${accessToken}`
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  async (error: AxiosError) => {
    const original = error.config as InternalAxiosRequestConfig & {
      _retry?: boolean
    }
    const url = original?.url || ''

    if (
      error.response?.status !== 401 ||
      original?._retry ||
      !refreshToken ||
      pathSkipsBearer(url) ||
      url.startsWith('/api/auth/refresh')
    ) {
      return Promise.reject(error)
    }

    original._retry = true

    try {
      const { data } = await plainClient.post<LoginResponse>('/api/auth/refresh', {
        refreshToken,
        deviceId: getDeviceId(),
      })
      persistSession(data)
      original.headers.Authorization = `Bearer ${data.accessToken}`
      return apiClient(original)
    } catch {
      clearPersistedSession()
      return Promise.reject(error)
    }
  },
)
