package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.SessionBulkRevocationResponse;
import com.vikas.authsystem.dto.SessionResponse;
import com.vikas.authsystem.entity.AuditAction;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.security.SessionBlacklistService;
import com.vikas.authsystem.security.TokenBlacklistService;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@Service
public class SessionService {

    private final RefreshTokenService refreshTokenService;
    private final TokenBlacklistService tokenBlacklistService;
    private final SessionBlacklistService sessionBlacklistService;
    private final AuditService auditService;
    private final AuthMetricsService authMetricsService;
    private final Clock clock;

    public SessionService(
            RefreshTokenService refreshTokenService,
            TokenBlacklistService tokenBlacklistService,
            SessionBlacklistService sessionBlacklistService,
            AuditService auditService,
            AuthMetricsService authMetricsService,
            Clock clock
    ) {
        this.refreshTokenService = refreshTokenService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.sessionBlacklistService = sessionBlacklistService;
        this.auditService = auditService;
        this.authMetricsService = authMetricsService;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<SessionResponse> listSessions(AuthenticatedUser authenticatedUser) {
        UUID currentSessionId = authenticatedUser.getSessionId();
        return refreshTokenService.listActiveSessions(authenticatedUser.getUserId()).stream()
                .map(session -> new SessionResponse(
                        session.sessionId(),
                        session.deviceId(),
                        session.sessionStartedAt(),
                        session.lastUsedAt(),
                        session.expiresAt(),
                        session.lastSeenIp(),
                        session.sessionId().equals(currentSessionId)
                ))
                .sorted(Comparator
                        .comparing(SessionResponse::current).reversed()
                        .thenComparing(SessionResponse::lastUsedAt, Comparator.reverseOrder()))
                .toList();
    }

    @Transactional
    public void revokeSession(AuthenticatedUser authenticatedUser, UUID sessionId, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            refreshTokenService.revokeSession(authenticatedUser.getUserId(), sessionId);
            if (sessionId.equals(authenticatedUser.getSessionId())) {
                blacklistCurrentAccessToken(authenticatedUser);
                blacklistCurrentSession(authenticatedUser);
            }
            auditService.recordEvent(AuditAction.SESSION_REVOKED, authenticatedUser.getUserId(), null, clientIp);
            outcome = "success";
        } finally {
            authMetricsService.recordOperation("revoke_session", outcome, sample);
        }
    }

    @Transactional
    public SessionBulkRevocationResponse revokeOtherSessions(AuthenticatedUser authenticatedUser, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            int revokedSessions = refreshTokenService.revokeOtherSessions(
                    authenticatedUser.getUserId(),
                    authenticatedUser.getSessionId()
            );
            auditService.recordEvent(AuditAction.OTHER_SESSIONS_REVOKED, authenticatedUser.getUserId(), null, clientIp);
            outcome = "success";
            return new SessionBulkRevocationResponse("Other active sessions revoked", revokedSessions);
        } finally {
            authMetricsService.recordOperation("revoke_other_sessions", outcome, sample);
        }
    }

    private void blacklistCurrentAccessToken(AuthenticatedUser authenticatedUser) {
        Instant tokenExpiresAt = authenticatedUser.getTokenExpiresAt();
        if (authenticatedUser.getTokenId() == null || tokenExpiresAt == null) {
            return;
        }
        Duration ttl = Duration.ofSeconds(Math.max(0, tokenExpiresAt.getEpochSecond() - Instant.now(clock).getEpochSecond()));
        tokenBlacklistService.blacklist(authenticatedUser.getTokenId(), ttl);
    }

    private void blacklistCurrentSession(AuthenticatedUser authenticatedUser) {
        Instant tokenExpiresAt = authenticatedUser.getTokenExpiresAt();
        if (authenticatedUser.getSessionId() == null || tokenExpiresAt == null) {
            return;
        }
        Duration ttl = Duration.ofSeconds(Math.max(0, tokenExpiresAt.getEpochSecond() - Instant.now(clock).getEpochSecond()));
        sessionBlacklistService.blacklist(authenticatedUser.getSessionId(), ttl);
    }
}
