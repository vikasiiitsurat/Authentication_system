import { AxiosError } from 'axios'
import { useState } from 'react'
import { Link as RouterLink, useLocation, useNavigate } from 'react-router-dom'
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
import { resetPassword } from '../api/authApi'
import AuthLayout from '../components/AuthLayout'
import { getApiErrorMessage } from '../lib/apiError'

export default function ResetPasswordPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const prefilled =
    (location.state as { email?: string } | null)?.email?.trim() || ''

  const [email, setEmail] = useState(prefilled)
  const [otp, setOtp] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  const otpOk = /^\d{6}$/.test(otp.trim())
  const pwdOk = newPassword.length >= 8 && newPassword.length <= 72
  const canSubmit = emailOk && otpOk && pwdOk && !loading

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!canSubmit) {
      setError('Check email, 6-digit code, and new password (8–72 chars).')
      return
    }
    setLoading(true)
    try {
      await resetPassword({
        email: email.trim(),
        otp: otp.trim(),
        newPassword,
      })
      navigate('/login', { replace: true })
    } catch (err) {
      if (err instanceof AxiosError) {
        const status = err.response?.status
        if (status === 401) {
          setError(getApiErrorMessage(err))
        } else if (status === 429) {
          setError(
            getApiErrorMessage(
              err,
              'Too many attempts. Please wait before trying again.',
            ),
          )
        } else {
          setError(getApiErrorMessage(err))
        }
      } else {
        setError('Something went wrong.')
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <AuthLayout
      title="Reset password"
      subtitle="Paste the code from your email and choose a new password."
      footer={
        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          <Link component={RouterLink} to="/forgot-password" fontWeight={600}>
            Request a new code
          </Link>
          {' · '}
          <Link component={RouterLink} to="/login" fontWeight={600}>
            Sign in
          </Link>
        </Typography>
      }
    >
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Box component="form" noValidate onSubmit={handleSubmit}>
        <Stack spacing={2}>
          <TextField
            label="Email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            fullWidth
            required
          />
          <TextField
            label="Reset code"
            value={otp}
            onChange={(e) => setOtp(e.target.value.replace(/\D/g, '').slice(0, 6))}
            inputProps={{ inputMode: 'numeric', maxLength: 6 }}
            fullWidth
            required
          />
          <TextField
            label="New password"
            type="password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            fullWidth
            required
            helperText="8–72 characters."
          />
          <Button
            type="submit"
            variant="contained"
            size="large"
            disabled={!canSubmit}
          >
            {loading ? (
              <CircularProgress size={22} color="inherit" />
            ) : (
              'Update password'
            )}
          </Button>
        </Stack>
      </Box>
    </AuthLayout>
  )
}
