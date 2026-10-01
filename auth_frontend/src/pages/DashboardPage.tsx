import { useEffect, useState, type ReactNode } from 'react'
import { Link as RouterLink } from 'react-router-dom'
import {
  AppBar,
  Box,
  Button,
  Chip,
  Container,
  Divider,
  Link,
  Paper,
  Stack,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Toolbar,
  Typography,
} from '@mui/material'
import { listSessions } from '../api/authApi'
import { useAuth } from '../context/AuthContext'
import type { SessionResponse } from '../types/auth'

export default function DashboardPage() {
  const { user, logout } = useAuth()
  const [sessions, setSessions] = useState<SessionResponse[] | null>(null)
  const [sessionsError, setSessionsError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    listSessions()
      .then((data) => {
        if (!cancelled) setSessions(data)
      })
      .catch(() => {
        if (!cancelled) setSessionsError('Could not load sessions.')
      })
    return () => {
      cancelled = true
    }
  }, [])

  return (
    <Box sx={{ minHeight: '100vh', bgcolor: 'background.default' }}>
      <AppBar
        position="sticky"
        elevation={0}
        sx={{
          bgcolor: 'rgba(255,255,255,0.85)',
          backdropFilter: 'blur(8px)',
          borderBottom: '1px solid',
          borderColor: 'rgba(15, 23, 42, 0.08)',
        }}
      >
        <Toolbar sx={{ gap: 2 }}>
          <Typography variant="h6" fontWeight={700} sx={{ flexGrow: 1 }}>
            Dashboard
          </Typography>
          <Chip
            label={user?.role ?? '—'}
            size="small"
            color="primary"
            variant="outlined"
          />
          <Button component={RouterLink} to="/" color="inherit">
            Home
          </Button>
          <Button variant="outlined" color="secondary" onClick={() => logout()}>
            Sign out
          </Button>
        </Toolbar>
      </AppBar>

      <Container maxWidth="md" sx={{ py: 4 }}>
        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h5" gutterBottom>
            Profile
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            From <code>/api/users/me</code>
          </Typography>
          <Stack spacing={1}>
            <Typography>
              <strong>Name:</strong> {user?.fullName}
            </Typography>
            <Typography>
              <strong>Email:</strong> {user?.email}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Created: {user?.createdAt}
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Updated: {user?.updatedAt}
            </Typography>
          </Stack>
        </Paper>

        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom>
            Password &amp; security
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            Change your password while signed in, or reset it with an email code
            if you forgot it.
          </Typography>
          <Stack spacing={1.5} sx={{ maxWidth: 420 }}>
            <Button
              component={RouterLink}
              to="/change-password"
              variant="contained"
              color="primary"
              startIcon={<KeySvg />}
              sx={{ justifyContent: 'flex-start' }}
            >
              Change password
            </Button>
            <Button
              component={RouterLink}
              to="/forgot-password"
              state={{ email: user?.email ?? '' }}
              variant="outlined"
              color="secondary"
              startIcon={<LockResetSvg />}
              sx={{ justifyContent: 'flex-start' }}
            >
              Reset password via email
            </Button>
            <Button
              component={RouterLink}
              to="/reset-password"
              state={{ email: user?.email ?? '' }}
              variant="outlined"
              color="secondary"
              startIcon={<LockResetSvg />}
              sx={{ justifyContent: 'flex-start' }}
            >
              I have a reset code
            </Button>
          </Stack>
        </Paper>

        <Paper sx={{ p: 3, mb: 3 }}>
          <Typography variant="h6" gutterBottom color="error">
            Danger zone
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            Permanently delete your account after confirming your email and
            password.
          </Typography>
          <Button
            component={RouterLink}
            to="/delete-account"
            variant="outlined"
            color="error"
            startIcon={<PersonOffSvg />}
          >
            Delete account
          </Button>
        </Paper>

        <Paper sx={{ p: 3 }}>
          <Typography variant="h6" gutterBottom>
            Active sessions
          </Typography>
          <Typography variant="body2" color="text.secondary" paragraph>
            From <code>/api/sessions</code>
          </Typography>
          {sessionsError && (
            <Typography color="error" variant="body2">
              {sessionsError}
            </Typography>
          )}
          {!sessionsError && sessions === null && (
            <Typography variant="body2" color="text.secondary">
              Loading…
            </Typography>
          )}
          {sessions && sessions.length === 0 && (
            <Typography variant="body2" color="text.secondary">
              No sessions returned.
            </Typography>
          )}
          {sessions && sessions.length > 0 && (
            <TableContainer>
              <Table size="small">
                <TableHead>
                  <TableRow>
                    <TableCell>Device</TableCell>
                    <TableCell>Current</TableCell>
                    <TableCell>Last used</TableCell>
                    <TableCell>Expires</TableCell>
                  </TableRow>
                </TableHead>
                <TableBody>
                  {sessions.map((s) => (
                    <TableRow key={s.sessionId}>
                      <TableCell>{s.deviceId}</TableCell>
                      <TableCell>{s.current ? 'Yes' : 'No'}</TableCell>
                      <TableCell>{s.lastUsedAt}</TableCell>
                      <TableCell>{s.expiresAt}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </TableContainer>
          )}
        </Paper>

        <Divider sx={{ my: 3 }} />

        <Typography variant="body2" color="text.secondary">
          <Link component={RouterLink} to="/verify-email">
            Verify email
          </Link>
        </Typography>
      </Container>
    </Box>
  )
}

function IconWrap({ children }: { children: ReactNode }) {
  return (
    <Box
      component="span"
      sx={{
        display: 'inline-flex',
        alignItems: 'center',
        '& svg': { width: 20, height: 20 },
      }}
    >
      {children}
    </Box>
  )
}

function KeySvg() {
  return (
    <IconWrap>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
        <path d="M7 11V8a5 5 0 0110 0v3M5 11h14v10H5V11zM12 15v2" />
      </svg>
    </IconWrap>
  )
}

function LockResetSvg() {
  return (
    <IconWrap>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
        <path d="M4 11V8a8 8 0 1116 0v3M5 11h14v10H5V11zM12 15v2" />
        <path d="M9 3l2 2 4-4" strokeLinecap="round" />
      </svg>
    </IconWrap>
  )
}

function PersonOffSvg() {
  return (
    <IconWrap>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
        <path d="M4 20h16M8 11a4 4 0 108 0M3 4l18 18" strokeLinecap="round" />
      </svg>
    </IconWrap>
  )
}
