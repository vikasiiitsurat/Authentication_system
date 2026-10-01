import { AxiosError } from 'axios'
import { useState } from 'react'
import { Link as RouterLink, useNavigate } from 'react-router-dom'
import {
  Alert,
  Box,
  Button,
  CircularProgress,
  Paper,
  Stack,
  TextField,
  Typography,
} from '@mui/material'
import { changePassword } from '../api/authApi'
import { useAuth } from '../context/AuthContext'
import { getApiErrorMessage } from '../lib/apiError'

export default function ChangePasswordPage() {
  const navigate = useNavigate()
  const { clearSession } = useAuth()
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const pwdOk = (p: string) => p.length >= 8 && p.length <= 72
  const canSubmit =
    pwdOk(currentPassword) &&
    pwdOk(newPassword) &&
    newPassword === confirmPassword &&
    newPassword !== currentPassword &&
    !loading

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!canSubmit) {
      setError(
        'Use 8–72 character passwords. New password must match confirmation and differ from the current one.',
      )
      return
    }
    setLoading(true)
    try {
      await changePassword({ currentPassword, newPassword })
      clearSession()
      navigate('/login', {
        replace: true,
        state: {
          flash:
            'Password updated. Your previous session was signed out—sign in with your new password.',
        },
      })
    } catch (err) {
      if (err instanceof AxiosError) {
        const status = err.response?.status
        if (status === 401) {
          setError(
            getApiErrorMessage(err, 'Current password is incorrect or session expired.'),
          )
        } else if (status === 400) {
          setError(getApiErrorMessage(err, 'Check your passwords and try again.'))
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
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default', py: 4 }}>
      <Box sx={{ maxWidth: 480, mx: 'auto', px: 2 }}>
        <Paper sx={{ p: 3 }}>
          <Typography variant="h5" fontWeight={700} gutterBottom>
            Change password
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            Updates your password and signs out other devices. You will need to
            sign in again on this device.
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          <Box component="form" noValidate onSubmit={handleSubmit}>
            <Stack spacing={2}>
              <TextField
                label="Current password"
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                fullWidth
                required
              />
              <TextField
                label="New password"
                type="password"
                autoComplete="new-password"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                fullWidth
                required
                helperText="8–72 characters."
              />
              <TextField
                label="Confirm new password"
                type="password"
                autoComplete="new-password"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                fullWidth
                required
                error={confirmPassword.length > 0 && newPassword !== confirmPassword}
                helperText={
                  confirmPassword.length > 0 && newPassword !== confirmPassword
                    ? 'Passwords do not match'
                    : ' '
                }
              />
              <Stack direction="row" spacing={2} justifyContent="flex-end">
                <Button component={RouterLink} to="/dashboard" color="inherit">
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="contained"
                  disabled={!canSubmit}
                >
                  {loading ? (
                    <CircularProgress size={22} color="inherit" />
                  ) : (
                    'Update password'
                  )}
                </Button>
              </Stack>
            </Stack>
          </Box>
        </Paper>

        <Typography variant="body2" color="text.secondary" sx={{ mt: 2 }}>
          <RouterLink to="/forgot-password" style={{ color: 'inherit', fontWeight: 600 }}>
            Forgot password? Use email reset instead
          </RouterLink>
        </Typography>
      </Box>
    </Box>
  )
}
