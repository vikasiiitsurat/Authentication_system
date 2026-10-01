export interface RegisterRequest {
  fullName: string
  email: string
  password: string
}

export interface RegisterResponse {
  userId: string
  fullName: string
  email: string
  message: string
  createdAt?: string
  emailVerificationRequired: boolean
  otpExpiresInSeconds: number
  resendAvailableInSeconds: number
}

export interface LoginRequest {
  email: string
  password: string
  deviceId?: string
}

export interface LoginResponse {
  accessToken: string
  refreshToken: string
  tokenType: string
  expiresInSeconds: number
}

export interface RefreshTokenRequest {
  refreshToken: string
  deviceId?: string
}

export interface VerifyEmailOtpRequest {
  email: string
  otp: string
  deviceId?: string
}

export interface EmailVerificationStatusResponse {
  email: string
  message: string
  verified: boolean
  verifiedAt?: string
  expiresInSeconds?: number
  resendAvailableInSeconds?: number
}

export interface ResendVerificationOtpRequest {
  email: string
}

export interface ForgotPasswordRequest {
  email: string
}

export interface PasswordResetRequestResponse {
  email: string
  message: string
  expiresInSeconds: number
  resendAvailableInSeconds: number
}

export interface ResetPasswordRequest {
  email: string
  otp: string
  newPassword: string
  deviceId?: string
}

export interface PasswordChangeRequest {
  currentPassword: string
  newPassword: string
  deviceId?: string
}

export interface DeleteAccountRequest {
  currentPassword: string
  confirmEmail: string
  deviceId?: string
}

export interface LogoutRequest {
  refreshToken?: string
}

export interface UserProfileResponse {
  id: string
  fullName: string
  email: string
  role: 'USER' | 'ADMIN'
  createdAt: string
  updatedAt: string
}

export interface SessionResponse {
  sessionId: string
  deviceId: string
  sessionStartedAt: string
  lastUsedAt: string
  expiresAt: string
  lastSeenIp: string
  current: boolean
}

export interface ApiErrorResponse {
  status?: number
  error?: string
  message?: string
  timestamp?: string
  validationErrors?: Record<string, string>
}
