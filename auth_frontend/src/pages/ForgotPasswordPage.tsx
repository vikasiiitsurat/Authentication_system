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
import { forgotPassword } from '../api/authApi'
import AuthLayout from '../components/AuthLayout'
import { getApiErrorMessage } from '../lib/apiError'

export default function ForgotPasswordPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const prefilled =
    (location.state as { email?: string } | null)?.email?.trim() ?? ''
  const [email, setEmail] = useState(prefilled)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [message, setMessage] = useState<string | null>(null)

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setMessage(null)
    if (!emailOk) {
      setError('Enter a valid email address.')
      return
    }
    setLoading(true)
    try {
      const res = await forgotPassword({ email: email.trim() })
      setMessage(
        res.message ||
          'If an account exists, a reset code will be sent to your email.',
      )
    } catch (err) {
      if (err instanceof AxiosError) {
        const status = err.response?.status
        if (status === 429) {
          setError(
            getApiErrorMessage(
              err,
              'Too many requests. Please wait before trying again.',
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
      title="Forgot password"
      subtitle="We’ll email a reset code if your account is eligible. Responses stay generic to protect your privacy."
      footer={
        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          Remembered it?{' '}
          <Link component={RouterLink} to="/login" fontWeight={600}>
            Sign in
          </Link>
          {' · '}
          <Link
            component={RouterLink}
            to="/reset-password"
            fontWeight={600}
            state={{ email: email.trim() }}
          >
            I have a code
          </Link>
        </Typography>
      }
    >
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {message && <Alert severity="success" sx={{ mb: 2 }}>{message}</Alert>}

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
          <Button
            type="submit"
            variant="contained"
            size="large"
            disabled={!emailOk || loading}
          >
            {loading ? (
              <CircularProgress size={22} color="inherit" />
            ) : (
              'Send reset instructions'
            )}
          </Button>
          <Button
            type="button"
            variant="text"
            onClick={() =>
              navigate('/reset-password', { state: { email: email.trim() } })
            }
          >
            Enter code & new password
          </Button>
        </Stack>
      </Box>
    </AuthLayout>
  )
}
