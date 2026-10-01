import type { ReactNode } from 'react'
import { Alert, Box, Button, Container, Stack, Typography } from '@mui/material'
import { Link as RouterLink, useLocation } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

function FeatureIcon({ children }: { children: ReactNode }) {
  return (
    <Box
      sx={{
        width: 48,
        height: 48,
        borderRadius: 2,
        display: 'grid',
        placeItems: 'center',
        bgcolor: 'rgba(13, 148, 136, 0.1)',
        color: 'primary.main',
        '& svg': { width: 26, height: 26 },
      }}
    >
      {children}
    </Box>
  )
}

const features = [
  {
    icon: (
      <FeatureIcon>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
          <path d="M12 3l7 4v5c0 5-3.5 9-7 10-3.5-1-7-5-7-10V7l7-4z" />
        </svg>
      </FeatureIcon>
    ),
    title: 'Layered protection',
    body: 'Abuse-aware login and OTP flows designed to reduce risk without punishing real users.',
  },
  {
    icon: (
      <FeatureIcon>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
          <rect x="5" y="11" width="14" height="10" rx="2" />
          <path d="M8 11V7a4 4 0 118 0v4" />
        </svg>
      </FeatureIcon>
    ),
    title: 'Session control',
    body: 'JWT access tokens with refresh rotation and tools to review active devices.',
  },
  {
    icon: (
      <FeatureIcon>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.75">
          <rect x="3" y="4" width="18" height="14" rx="2" />
          <path d="M8 21h8M12 18v3" />
        </svg>
      </FeatureIcon>
    ),
    title: 'Built for production',
    body: 'Email verification, password reset, and account recovery aligned with your API.',
  },
]

export default function LandingPage() {
  const { user, loading } = useAuth()
  const location = useLocation()
  const flash = (location.state as { flash?: string })?.flash

  return (
    <Box
      sx={{
        minHeight: '100vh',
        position: 'relative',
        overflow: 'hidden',
        background:
          'linear-gradient(165deg, #ecfdf5 0%, #f0f9ff 40%, #f8fafc 100%)',
        '&::before': {
          content: '""',
          position: 'absolute',
          width: '120%',
          height: '60%',
          top: '-20%',
          left: '-10%',
          background:
            'radial-gradient(ellipse at 50% 0%, rgba(13, 148, 136, 0.15), transparent 55%)',
          pointerEvents: 'none',
        },
      }}
    >
      <Container maxWidth="lg" sx={{ position: 'relative', zIndex: 1, py: 6 }}>
        {flash && (
          <Alert severity="info" sx={{ mb: 3 }}>
            {flash}
          </Alert>
        )}
        <Stack
          direction={{ xs: 'column', sm: 'row' }}
          justifyContent="space-between"
          alignItems={{ xs: 'flex-start', sm: 'center' }}
          spacing={2}
          sx={{ mb: 8 }}
        >
          <Stack direction="row" alignItems="center" spacing={1.5}>
            <Box
              sx={{
                width: 44,
                height: 44,
                borderRadius: 2,
                background: 'linear-gradient(135deg, #0d9488, #14b8a6)',
                display: 'grid',
                placeItems: 'center',
                color: 'white',
                fontWeight: 800,
                fontSize: '1.15rem',
                boxShadow: '0 4px 16px rgba(13, 148, 136, 0.4)',
              }}
            >
              N
            </Box>
            <Typography variant="h6" fontWeight={700} letterSpacing="-0.03em">
              Narnix Auth
            </Typography>
          </Stack>
          <Stack direction="row" spacing={1}>
            {!loading && user ? (
              <Button
                component={RouterLink}
                to="/dashboard"
                variant="contained"
                disableElevation
              >
                Open dashboard
              </Button>
            ) : (
              <>
                <Button component={RouterLink} to="/login" color="inherit">
                  Sign in
                </Button>
                <Button
                  component={RouterLink}
                  to="/register"
                  variant="contained"
                  disableElevation
                >
                  Create account
                </Button>
              </>
            )}
          </Stack>
        </Stack>

        <Stack
          direction={{ xs: 'column', md: 'row' }}
          spacing={6}
          alignItems="center"
        >
          <Box sx={{ flex: 1, minWidth: 0 }}>
            <Typography
              variant="h2"
              sx={{
                fontSize: { xs: '2rem', md: '2.75rem' },
                lineHeight: 1.15,
                mb: 2,
              }}
            >
              Authentication that feels calm, clear, and{' '}
              <Box
                component="span"
                sx={{
                  background: 'linear-gradient(90deg, #0d9488, #0891b2)',
                  backgroundClip: 'text',
                  WebkitTextFillColor: 'transparent',
                }}
              >
                under control
              </Box>
              .
            </Typography>
            <Typography
              variant="body1"
              color="text.secondary"
              sx={{ mb: 4, maxWidth: 520 }}
            >
              Register, verify your email with a one-time code, sign in, and
              manage your profile—all wired to your Spring Boot API with smooth
              loading states and helpful errors.
            </Typography>
            <Stack direction={{ xs: 'column', sm: 'row' }} spacing={2}>
              <Button
                component={RouterLink}
                to="/register"
                variant="contained"
                size="large"
                disableElevation
              >
                Get started
              </Button>
              <Button
                component={RouterLink}
                to="/login"
                variant="outlined"
                size="large"
                color="secondary"
              >
                I already have an account
              </Button>
            </Stack>
          </Box>
          <Box sx={{ width: '100%', maxWidth: 420 }}>
            <Box
              sx={{
                borderRadius: 3,
                p: 3,
                bgcolor: 'rgba(255,255,255,0.85)',
                border: '1px solid',
                borderColor: 'rgba(15, 23, 42, 0.08)',
                boxShadow:
                  '0 4px 6px -1px rgba(15, 23, 42, 0.06), 0 20px 40px -12px rgba(15, 23, 42, 0.12)',
                backdropFilter: 'blur(8px)',
              }}
            >
              <Typography variant="subtitle2" color="primary" gutterBottom>
                Today’s flow
              </Typography>
              <Typography variant="body2" color="text.secondary" paragraph>
                1. Register with your name and email
                <br />
                2. Enter the 6-digit code we send you
                <br />
                3. Sign in and open your dashboard
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Errors from the API (validation, conflicts, rate limits) surface
                inline—no silent failures.
              </Typography>
            </Box>
          </Box>
        </Stack>

        <Stack
          direction={{ xs: 'column', md: 'row' }}
          spacing={3}
          sx={{ mt: { xs: 4, md: 8 } }}
        >
          {features.map((f) => (
            <Box
              key={f.title}
              sx={{
                flex: 1,
                p: 3,
                borderRadius: 2,
                bgcolor: 'background.paper',
                border: '1px solid',
                borderColor: 'rgba(15, 23, 42, 0.06)',
                transition: 'transform 0.2s, box-shadow 0.2s',
                '&:hover': {
                  transform: 'translateY(-2px)',
                  boxShadow: '0 12px 24px -8px rgba(15, 23, 42, 0.12)',
                },
              }}
            >
              <Box sx={{ mb: 1.5 }}>{f.icon}</Box>
              <Typography variant="h6" gutterBottom>
                {f.title}
              </Typography>
              <Typography variant="body2" color="text.secondary">
                {f.body}
              </Typography>
            </Box>
          ))}
        </Stack>
      </Container>
    </Box>
  )
}
