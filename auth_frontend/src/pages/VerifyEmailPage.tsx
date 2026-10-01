import { AxiosError } from 'axios'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link as RouterLink } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Link,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { resendVerificationOtp, verifyEmailOtp } from '../api/authApi'
import AuthLayout from '../components/AuthLayout'
import { OTP_EMAIL_KEY, OTP_META_KEY, type OtpMeta } from '../constants/storage'
import { getApiErrorMessage } from '../lib/apiError'
import type { ApiErrorResponse } from '../types/auth'

function readOtpMeta(): OtpMeta | null {
  try {
    const raw = sessionStorage.getItem(OTP_META_KEY)
    if (!raw) return null
    return JSON.parse(raw) as OtpMeta
  } catch {
    return null
  }
}

export default function VerifyEmailPage() {
  const initialEmail = useMemo(
    () => sessionStorage.getItem(OTP_EMAIL_KEY) || '',
    [],
  )
  const [email, setEmail] = useState(initialEmail)
  const [otp, setOtp] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [resendLoading, setResendLoading] = useState(false)

  const [otpSecondsLeft, setOtpSecondsLeft] = useState<number | null>(() => {
    const m = readOtpMeta()
    return m?.otpExpiresInSeconds ?? null
  })
  const [resendSecondsLeft, setResendSecondsLeft] = useState<number>(() => {
    const m = readOtpMeta()
    return m?.resendAvailableInSeconds ?? 0
  })

  const tickOtp = useCallback(() => {
    setOtpSecondsLeft((s) => {
      if (s === null || s <= 0) return s
      return s - 1
    })
  }, [])

  const tickResend = useCallback(() => {
    setResendSecondsLeft((s) => Math.max(0, s - 1))
  }, [])

  useEffect(() => {
    if (otpSecondsLeft === null || otpSecondsLeft <= 0) return
    const id = window.setInterval(tickOtp, 1000)
    return () => window.clearInterval(id)
  }, [otpSecondsLeft, tickOtp])

  useEffect(() => {
    if (resendSecondsLeft <= 0) return
    const id = window.setInterval(tickResend, 1000)
    return () => window.clearInterval(id)
  }, [resendSecondsLeft, tickResend])

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  const otpOk = /^\d{6}$/.test(otp.trim())
  const canVerify = emailOk && otpOk && !loading

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setSuccess(null)
    if (!emailOk || !otpOk) {
      setError('Enter a valid email and a 6-digit code.')
      return
    }
    setLoading(true)
    try {
      const res = await verifyEmailOtp({
        email: email.trim(),
        otp: otp.trim(),
      })
      sessionStorage.removeItem(OTP_EMAIL_KEY)
      sessionStorage.removeItem(OTP_META_KEY)
      setSuccess(res.message || 'Email verified. You can sign in now.')
    } catch (err) {
      if (err instanceof AxiosError) {
        const ax = err as AxiosError<ApiErrorResponse>
        const status = ax.response?.status
        if (status === 400) {
          setError(getApiErrorMessage(ax, 'Invalid or expired code.'))
        } else if (status === 429) {
          setError(
            getApiErrorMessage(
              ax,
              'Too many attempts. Please wait before trying again.',
            ),
          )
        } else {
          setError(getApiErrorMessage(ax))
        }
      } else {
        setError('Something went wrong.')
      }
    } finally {
      setLoading(false)
    }
  }

  const handleResend = async () => {
    if (!emailOk || resendSecondsLeft > 0 || resendLoading) return
    setError(null)
    setResendLoading(true)
    try {
      const res = await resendVerificationOtp({ email: email.trim() })
      if (typeof res.resendAvailableInSeconds === 'number') {
        setResendSecondsLeft(res.resendAvailableInSeconds)
      }
      if (typeof res.expiresInSeconds === 'number') {
        setOtpSecondsLeft(res.expiresInSeconds)
      }
      sessionStorage.setItem(
        OTP_META_KEY,
        JSON.stringify({
          otpExpiresInSeconds: res.expiresInSeconds ?? 180,
          resendAvailableInSeconds: res.resendAvailableInSeconds ?? 30,
        }),
      )
    } catch (err) {
      if (err instanceof AxiosError) {
        setError(getApiErrorMessage(err))
      } else {
        setError('Could not resend code.')
      }
    } finally {
      setResendLoading(false)
    }
  }

  const otpHint =
    otpSecondsLeft !== null && otpSecondsLeft > 0
      ? `Code expires in ${Math.ceil(otpSecondsLeft / 60)} min ${otpSecondsLeft % 60}s`
      : ' '

  return (
    <AuthLayout
      title="Verify your email"
      subtitle="Enter the 6-digit code we sent you. You can resend after the cooldown."
      footer={
        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          Wrong address?{' '}
          <Link component={RouterLink} to="/register" fontWeight={600}>
            Register again
          </Link>
          {' · '}
          <Link component={RouterLink} to="/login" fontWeight={600}>
            Sign in
          </Link>
        </Typography>
      }
    >
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {success && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {success}
          <Box sx={{ mt: 1.5 }}>
            <Button component={RouterLink} to="/login" variant="contained" size="small">
              Continue to sign in
            </Button>
          </Box>
        </Alert>
      )}

      {!success && (
      <Box component="form" noValidate onSubmit={handleVerify}>
        <Stack spacing={2}>
          <TextField
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            fullWidth
            required
            helperText="Use the same email you registered with."
          />
          <TextField
            label="One-time code"
            value={otp}
            onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
            inputProps={{
              inputMode: 'numeric',
              pattern: '\\d{6}',
              maxLength: 6,
              'aria-label': 'Six-digit verification code',
            }}
            fullWidth
            required
            helperText={otpHint}
          />
          <Button
            type="submit"
            variant="contained"
            size="large"
            disabled={!canVerify}
          >
            {loading ? (
              <CircularProgress size={22} color="inherit" />
            ) : (
              'Verify email'
            )}
          </Button>
          <Button
            type="button"
            variant="outlined"
            onClick={handleResend}
            disabled={!emailOk || resendSecondsLeft > 0 || resendLoading}
          >
            {resendLoading ? (
              <CircularProgress size={22} />
            ) : resendSecondsLeft > 0 ? (
              `Resend code in ${resendSecondsLeft}s`
            ) : (
              'Resend code'
            )}
          </Button>
        </Stack>
      </Box>
      )}
    </AuthLayout>
  )
}
