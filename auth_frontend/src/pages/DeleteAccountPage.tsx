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
import { deleteMyAccount } from '../api/authApi'
import { useAuth } from '../context/AuthContext'
import { getApiErrorMessage } from '../lib/apiError'

export default function DeleteAccountPage() {
  const navigate = useNavigate()
  const { user, clearSession } = useAuth()
  const [currentPassword, setCurrentPassword] = useState('')
  const [confirmEmail, setConfirmEmail] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const emailMatches =
    user?.email &&
    confirmEmail.trim().toLowerCase() === user.email.toLowerCase()
  const pwdOk = currentPassword.length >= 8 && currentPassword.length <= 256
  const canSubmit = Boolean(emailMatches && pwdOk && !loading)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    if (!user?.email) {
      setError('Could not load your account email.')
      return
    }
    if (!canSubmit) {
      setError(
        'Type your account email exactly and enter your current password (8+ characters).',
      )
      return
    }
    setLoading(true)
    try {
      await deleteMyAccount({
        currentPassword,
        confirmEmail: confirmEmail.trim(),
      })
      clearSession()
      navigate('/', {
        replace: true,
        state: {
          flash: 'Your account has been deleted.',
        },
      })
    } catch (err) {
      if (err instanceof AxiosError) {
        const status = err.response?.status
        if (status === 401) {
          setError(
            getApiErrorMessage(err, 'Password incorrect or session expired.'),
          )
        } else if (status === 400) {
          setError(
            getApiErrorMessage(
              err,
              'Confirmation email must match your account email.',
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
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default', py: 4 }}>
      <Box sx={{ maxWidth: 480, mx: 'auto', px: 2 }}>
        <Paper
          sx={{
            p: 3,
            border: '1px solid',
            borderColor: 'error.light',
            bgcolor: 'rgba(220, 38, 38, 0.04)',
          }}
        >
          <Typography variant="h5" fontWeight={700} gutterBottom color="error.dark">
            Delete account
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            This soft-deletes your account, revokes sessions, and signs you out.
            This cannot be undone from this screen.
          </Typography>

          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}

          <Box component="form" noValidate onSubmit={handleSubmit}>
            <Stack spacing={2}>
              <Typography variant="body2">
                Account email:{' '}
                <strong>{user?.email ?? '—'}</strong>
              </Typography>
              <TextField
                label="Type your email to confirm"
                type="email"
                autoComplete="off"
                value={confirmEmail}
                onChange={(e) => setConfirmEmail(e.target.value)}
                fullWidth
                required
                error={confirmEmail.length > 0 && !emailMatches}
                helperText={
                  confirmEmail.length > 0 && !emailMatches
                    ? 'Must match your account email exactly'
                    : ' '
                }
              />
              <TextField
                label="Current password"
                type="password"
                autoComplete="current-password"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                fullWidth
                required
              />
              <Stack direction="row" spacing={2} justifyContent="flex-end">
                <Button component={RouterLink} to="/dashboard" color="inherit">
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="contained"
                  color="error"
                  disabled={!canSubmit}
                >
                  {loading ? (
                    <CircularProgress size={22} color="inherit" />
                  ) : (
                    'Delete my account'
                  )}
                </Button>
              </Stack>
            </Stack>
          </Box>
        </Paper>
      </Box>
    </Box>
  )
}
