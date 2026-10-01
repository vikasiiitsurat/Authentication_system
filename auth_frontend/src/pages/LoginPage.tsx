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
import AuthLayout from '../components/AuthLayout'
import { useAuth } from '../context/AuthContext'
import { getApiErrorMessage } from '../lib/apiError'

export default function LoginPage() {
  const navigate = useNavigate()
  const location = useLocation()
  const { login } = useAuth()
  const from =
    (location.state as { from?: { pathname: string } })?.from?.pathname ||
    '/dashboard'
  const flashMessage = (location.state as { flash?: string })?.flash

  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  const pwdOk = password.length >= 8 && password.length <= 72
  const canSubmit = emailOk && pwdOk && !loading

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!emailOk || !pwdOk) {
      setError('Enter a valid email and password (8–72 characters).')
      return
    }
    setLoading(true)
    try {
      await login(email.trim(), password)
      navigate(from, { replace: true })
    } catch (err) {
      if (err instanceof AxiosError) {
        const status = err.response?.status
        if (status === 401) {
          setError(
            getApiErrorMessage(err, 'Invalid email or password.'),
          )
        } else if (status === 429) {
          setError(
            getApiErrorMessage(
              err,
              'Too many sign-in attempts. Please wait and try again.',
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
      title="Welcome back"
      subtitle="Sign in with the email and password you used to register."
      footer={
        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          New here?{' '}
          <Link component={RouterLink} to="/register" fontWeight={600}>
            Create an account
          </Link>
        </Typography>
      }
    >
      {flashMessage && (
        <Alert severity="success" sx={{ mb: 2 }}>
          {flashMessage}
        </Alert>
      )}
      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}

      <Box component="form" noValidate onSubmit={handleSubmit}>
        <Stack spacing={2}>
          <TextField
            label="Email"
            type="email"
            autoComplete="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            fullWidth
            required
          />
          <TextField
            label="Password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            fullWidth
            required
          />
          <Box sx={{ textAlign: 'right' }}>
            <Link component={RouterLink} to="/forgot-password" variant="body2">
              Forgot password?
            </Link>
          </Box>
          <Button
            type="submit"
            variant="contained"
            size="large"
            disabled={!canSubmit}
          >
            {loading ? (
              <CircularProgress size={22} color="inherit" />
            ) : (
              'Sign in'
            )}
          </Button>
        </Stack>
      </Box>
    </AuthLayout>
  )
}
