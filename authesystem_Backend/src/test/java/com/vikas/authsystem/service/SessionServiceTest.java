package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.SessionBulkRevocationResponse;
import com.vikas.authsystem.dto.SessionResponse;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.security.SessionBlacklistService;
import com.vikas.authsystem.security.TokenBlacklistService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class SessionServiceTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-03-19T09:00:00Z");

    private final RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);
    private final TokenBlacklistService tokenBlacklistService = mock(TokenBlacklistService.class);
    private final SessionBlacklistService sessionBlacklistService = mock(SessionBlacklistService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthMetricsService authMetricsService = mock(AuthMetricsService.class);

    private SessionService sessionService;

    @BeforeEach
    void setUp() {
        sessionService = new SessionService(
                refreshTokenService,
                tokenBlacklistService,
                sessionBlacklistService,
                auditService,
                authMetricsService,
                Clock.fixed(FIXED_NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void listSessionsPlacesCurrentSessionFirst() {
        UUID userId = UUID.randomUUID();
        UUID currentSessionId = UUID.randomUUID();
        UUID otherSessionId = UUID.randomUUID();
        AuthenticatedUser authenticatedUser = authenticatedUser(userId, currentSessionId);
        when(refreshTokenService.listActiveSessions(userId)).thenReturn(List.of(
                new RefreshTokenService.StoredSession(
                        otherSessionId,
                        "mobile",
                        FIXED_NOW.minusSeconds(3_600),
                        FIXED_NOW.minusSeconds(300),
                        FIXED_NOW.plusSeconds(3_600),
                        "10.0.0.2"
                ),
                new RefreshTokenService.StoredSession(
                        currentSessionId,
                        "laptop",
                        FIXED_NOW.minusSeconds(7_200),
                        FIXED_NOW.minusSeconds(900),
                        FIXED_NOW.plusSeconds(3_600),
                        "10.0.0.1"
                )
        ));

        List<SessionResponse> response = sessionService.listSessions(authenticatedUser);

        assertEquals(2, response.size());
        assertEquals(currentSessionId, response.get(0).sessionId());
        assertEquals(true, response.get(0).current());
        assertEquals(otherSessionId, response.get(1).sessionId());
    }

    @Test
    void revokeCurrentSessionBlacklistsCurrentTokenAndSession() {
        UUID userId = UUID.randomUUID();
        UUID currentSessionId = UUID.randomUUID();
        AuthenticatedUser authenticatedUser = authenticatedUser(userId, currentSessionId);

        sessionService.revokeSession(authenticatedUser, currentSessionId, "127.0.0.1");

        verify(refreshTokenService).revokeSession(userId, currentSessionId);
        verify(tokenBlacklistService).blacklist("token-jti", Duration.ofSeconds(600));
        verify(sessionBlacklistService).blacklist(currentSessionId, Duration.ofSeconds(600));
        verify(authMetricsService).recordOperation("revoke_session", "success", null);
    }

    @Test
    void revokeOtherSessionsReturnsRevokedCount() {
        UUID userId = UUID.randomUUID();
        UUID currentSessionId = UUID.randomUUID();
        AuthenticatedUser authenticatedUser = authenticatedUser(userId, currentSessionId);
        when(refreshTokenService.revokeOtherSessions(userId, currentSessionId)).thenReturn(2);

        SessionBulkRevocationResponse response = sessionService.revokeOtherSessions(authenticatedUser, "127.0.0.1");

        assertEquals(2, response.revokedSessions());
        assertEquals("Other active sessions revoked", response.message());
        verify(authMetricsService).recordOperation("revoke_other_sessions", "success", null);
    }

    private AuthenticatedUser authenticatedUser(UUID userId, UUID sessionId) {
        return new AuthenticatedUser(
                userId,
                UserRole.USER,
                sessionId,
                "token-jti",
                FIXED_NOW.plusSeconds(600)
        );
    }
}
