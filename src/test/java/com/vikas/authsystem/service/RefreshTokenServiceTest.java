package com.vikas.authsystem.service;

import com.vikas.authsystem.config.JwtProperties;
import com.vikas.authsystem.entity.RefreshToken;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.repository.RefreshTokenRepository;
import com.vikas.authsystem.security.JwtUtil;
import com.vikas.authsystem.security.SessionBlacklistService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RefreshTokenServiceTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-03-27T09:00:00Z");

    private final RefreshTokenRepository refreshTokenRepository = mock(RefreshTokenRepository.class);
    private final SessionBlacklistService sessionBlacklistService = mock(SessionBlacklistService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthMetricsService authMetricsService = mock(AuthMetricsService.class);

    private RefreshTokenService refreshTokenService;

    @BeforeEach
    void setUp() {
        refreshTokenService = new RefreshTokenService(
                refreshTokenRepository,
                jwtProperties(),
                new JwtUtil(jwtProperties()),
                sessionBlacklistService,
                auditService,
                authMetricsService,
                Clock.fixed(FIXED_NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void refreshRejectsDeletedAccountAndRevokesExistingSession() {
        User deletedUser = new User();
        deletedUser.setId(UUID.randomUUID());
        deletedUser.setRole(UserRole.USER);
        deletedUser.setDeletedAt(FIXED_NOW.minusSeconds(10));

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(deletedUser);
        refreshToken.setTokenHash(refreshTokenService.hashToken("raw-refresh-token"));
        refreshToken.setSessionId(UUID.randomUUID());
        refreshToken.setDeviceId("device-1");
        refreshToken.setExpiryDate(FIXED_NOW.plusSeconds(3600));

        when(refreshTokenRepository.findByTokenHash(refreshToken.getTokenHash())).thenReturn(Optional.of(refreshToken));
        when(refreshTokenRepository.findAllByUser_IdAndRevokedAtIsNull(deletedUser.getId())).thenReturn(List.of(refreshToken));

        UnauthorizedException exception = assertThrows(
                UnauthorizedException.class,
                () -> refreshTokenService.refreshAccessToken("raw-refresh-token", "device-1", "127.0.0.1")
        );

        assertEquals("Account is no longer active", exception.getMessage());
        verify(refreshTokenRepository).save(any(RefreshToken.class));
        verify(sessionBlacklistService).blacklist(refreshToken.getSessionId(), java.time.Duration.ofSeconds(3600));
        verify(authMetricsService).recordOperation("refresh_token", "account_deleted", null);
    }

    private JwtProperties jwtProperties() {
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setIssuer("test-issuer");
        jwtProperties.setAccessTokenMinutes(5);
        jwtProperties.setRefreshTokenDays(7);
        SecretKey secretKey = new SecretKeySpec("01234567890123456789012345678901".getBytes(), "HmacSHA256");
        jwtProperties.setSecret(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        return jwtProperties;
    }
}
