import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
} from 'react'
import {
  clearPersistedSession,
  getRefreshToken,
  loadSessionFromStorage,
  persistSession,
} from '../api/client'
import * as authApi from '../api/authApi'
import { AUTH_SESSION_KEY } from '../constants/storage'
import type { LoginResponse, UserProfileResponse } from '../types/auth'

type AuthContextValue = {
  user: UserProfileResponse | null
  loading: boolean
  login: (email: string, password: string) => Promise<void>
  logout: () => Promise<void>
  /** Clears tokens and user without calling the API (e.g. after password change invalidates the session). */
  clearSession: () => void
  refreshUser: () => Promise<void>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<UserProfileResponse | null>(null)
  const [loading, setLoading] = useState(true)

  const refreshUser = useCallback(async () => {
    const data = await authApi.fetchCurrentUser()
    setUser(data)
  }, [])

  useEffect(() => {
    loadSessionFromStorage()
    const raw = localStorage.getItem(AUTH_SESSION_KEY)
    if (!raw) {
      setLoading(false)
      return
    }
    refreshUser()
      .catch(() => setUser(null))
      .finally(() => setLoading(false))
  }, [refreshUser])

  const login = useCallback(async (email: string, password: string) => {
    const tokens: LoginResponse = await authApi.login({ email, password })
    persistSession(tokens)
    await refreshUser()
  }, [refreshUser])

  const logout = useCallback(async () => {
    try {
      await authApi.logout({
        refreshToken: getRefreshToken() ?? undefined,
      })
    } catch {
      // still clear local session
    }
    clearPersistedSession()
    setUser(null)
  }, [])

  const clearSession = useCallback(() => {
    clearPersistedSession()
    setUser(null)
  }, [])

  const value = useMemo(
    () => ({
      user,
      loading,
      login,
      logout,
      clearSession,
      refreshUser,
    }),
    [user, loading, login, logout, clearSession, refreshUser],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
