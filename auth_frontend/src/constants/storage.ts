export const OTP_EMAIL_KEY = 'otp-email'
export const OTP_META_KEY = 'otp-meta'
export const AUTH_SESSION_KEY = 'auth_session'

export interface OtpMeta {
  otpExpiresInSeconds: number
  resendAvailableInSeconds: number
}

export interface StoredAuthSession {
  accessToken: string
  refreshToken: string
  expiresInSeconds: number
}
