import { Box, Container, Link, Stack, Typography } from '@mui/material'
import { Link as RouterLink } from 'react-router-dom'

type AuthLayoutProps = {
  title: string
  subtitle?: string
  children: React.ReactNode
  footer?: React.ReactNode
}

export default function AuthLayout({
  title,
  subtitle,
  children,
  footer,
}: AuthLayoutProps) {
  return (
    <Box
      sx={{
        minHeight: '100vh',
        position: 'relative',
        overflow: 'hidden',
        background:
          'linear-gradient(145deg, #ecfdf5 0%, #f0f9ff 38%, #f8fafc 100%)',
        '&::before': {
          content: '""',
          position: 'absolute',
          inset: 0,
          background:
            'radial-gradient(ellipse 80% 50% at 100% 0%, rgba(13, 148, 136, 0.12), transparent 50%), radial-gradient(ellipse 60% 40% at 0% 100%, rgba(14, 165, 233, 0.1), transparent 45%)',
          pointerEvents: 'none',
        },
      }}
    >
      <Container
        maxWidth="sm"
        sx={{ position: 'relative', zIndex: 1, py: { xs: 4, sm: 6 } }}
      >
        <Stack spacing={3} alignItems="center" sx={{ mb: 3 }}>
          <Link
            component={RouterLink}
            to="/"
            underline="none"
            sx={{
              display: 'flex',
              alignItems: 'center',
              gap: 1,
              color: 'text.primary',
            }}
          >
            <Box
              sx={{
                width: 40,
                height: 40,
                borderRadius: 2,
                background: 'linear-gradient(135deg, #0d9488, #14b8a6)',
                display: 'grid',
                placeItems: 'center',
                color: 'white',
                fontWeight: 800,
                fontSize: '1.1rem',
                boxShadow: '0 4px 14px rgba(13, 148, 136, 0.35)',
              }}
            >
              N
            </Box>
            <Typography variant="h6" fontWeight={700} letterSpacing="-0.03em">
              Narnix Auth
            </Typography>
          </Link>
        </Stack>

        <Box
          sx={{
            borderRadius: 3,
            bgcolor: 'background.paper',
            boxShadow:
              '0 4px 6px -1px rgba(15, 23, 42, 0.06), 0 24px 48px -12px rgba(15, 23, 42, 0.12)',
            border: '1px solid',
            borderColor: 'rgba(15, 23, 42, 0.06)',
            p: { xs: 3, sm: 4 },
          }}
        >
          <Stack spacing={2} sx={{ mb: 3 }}>
            <Typography variant="h4" component="h1" fontWeight={700}>
              {title}
            </Typography>
            {subtitle && (
              <Typography variant="body1" color="text.secondary">
                {subtitle}
              </Typography>
            )}
          </Stack>
          {children}
          {footer}
        </Box>
      </Container>
    </Box>
  )
}
