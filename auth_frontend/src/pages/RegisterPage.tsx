import { AxiosError } from 'axios'
import { useState } from 'react'
import { Link as RouterLink, useNavigate } from 'react-router-dom'
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
import { registerUser } from '../api/authApi'
import AuthLayout from '../components/AuthLayout'
import { OTP_EMAIL_KEY, OTP_META_KEY } from '../constants/storage'
import { getApiErrorMessage } from '../lib/apiError'
import type { ApiErrorResponse } from '../types/auth'

export default function RegisterPage() {
  const navigate = useNavigate()
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [successMessage, setSuccessMessage] = useState<string | null>(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [fullNameTouched, setFullNameTouched] = useState(false)
  const [emailTouched, setEmailTouched] = useState(false)
  const [passwordTouched, setPasswordTouched] = useState(false)

  const trimmedFullName = fullName.trim()
  const isFullNameValid =
    trimmedFullName.length > 0 && trimmedFullName.length <= 255
  const isEmailValid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  const isPasswordValid = password.length >= 8 && password.length <= 72
  const canSubmit =
    isFullNameValid && isEmailValid && isPasswordValid && !isSubmitting

  const handleSubmit = async (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setFullNameTouched(true)
    setEmailTouched(true)
    setPasswordTouched(true)
    setErrorMessage(null)
    setSuccessMessage(null)

    if (!isFullNameValid || !isEmailValid || !isPasswordValid) {
      setErrorMessage(
        'Please enter your full name (1–255 chars), a valid email, and password (8–72 chars).',
      )
      return
    }

    setIsSubmitting(true)

    try {
      const response = await registerUser({
        fullName: trimmedFullName,
        email: email.trim(),
        password,
      })

      sessionStorage.setItem(OTP_EMAIL_KEY, response.email)
      sessionStorage.setItem(
        OTP_META_KEY,
        JSON.stringify({
          otpExpiresInSeconds: response.otpExpiresInSeconds,
          resendAvailableInSeconds: response.resendAvailableInSeconds,
        }),
      )
      setSuccessMessage(response.message || 'Registration successful.')

      setTimeout(() => {
        navigate('/verify-email')
      }, 900)
    } catch (error) {
      if (error instanceof AxiosError) {
        const status = error.response?.status
        const err = error as AxiosError<ApiErrorResponse>
        if (status === 400) {
          setErrorMessage(
            getApiErrorMessage(err, 'Please check your input values.'),
          )
        } else if (status === 409) {
          setErrorMessage(
            getApiErrorMessage(
              err,
              'This email is already registered and verified.',
            ),
          )
        } else if (status === 429) {
          setErrorMessage(
            getApiErrorMessage(
              err,
              'Too many attempts. Please wait and try again.',
            ),
          )
        } else {
          setErrorMessage(getApiErrorMessage(err, 'Registration failed.'))
        }
      } else {
        setErrorMessage('Something went wrong. Please try again.')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <AuthLayout
      title="Create your account"
      subtitle="We’ll send a 6-digit code to verify your email before you can sign in."
      footer={
        <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
          Already registered?{' '}
          <Link component={RouterLink} to="/login" fontWeight={600}>
            Sign in
          </Link>
        </Typography>
      }
    >
      {errorMessage && <Alert severity="error" sx={{ mb: 2 }}>{errorMessage}</Alert>}
      {successMessage && (
        <Alert severity="success" sx={{ mb: 2 }}>{successMessage}</Alert>
      )}

      <Box component="form" noValidate onSubmit={handleSubmit}>
        <Stack spacing={2}>
          <TextField
            label="Full name"
            type="text"
            required
            value={fullName}
            onChange={(event) => setFullName(event.target.value)}
            onBlur={() => setFullNameTouched(true)}
            error={fullNameTouched && !isFullNameValid}
            helperText={
              fullNameTouched && !isFullNameValid
                ? 'Enter your name (1–255 characters).'
                : ' '
            }
            inputProps={{ maxLength: 255 }}
            fullWidth
          />

          <TextField
            label="Email"
            type="email"
            required
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            onBlur={() => setEmailTouched(true)}
            error={emailTouched && !isEmailValid}
            helperText={
              emailTouched && !isEmailValid
                ? 'Enter a valid email address.'
                : ' '
            }
            fullWidth
          />

          <TextField
            label="Password"
            type="password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            onBlur={() => setPasswordTouched(true)}
            error={passwordTouched && !isPasswordValid}
            helperText={
              passwordTouched && !isPasswordValid
                ? 'Password must be between 8 and 72 characters.'
                : ' '
            }
            fullWidth
          />

          <Button
            type="submit"
            variant="contained"
            size="large"
            disabled={!canSubmit}
          >
            {isSubmitting ? (
              <CircularProgress size={22} color="inherit" />
            ) : (
              'Register'
            )}
          </Button>
        </Stack>
      </Box>
    </AuthLayout>
  )
}
