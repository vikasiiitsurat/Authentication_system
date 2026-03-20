package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.config.JwtProperties;
import com.vikas.authsystem.entity.AuditAction;
import com.vikas.authsystem.entity.RefreshToken;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.exception.ResourceNotFoundException;
import com.vikas.authsystem.repository.RefreshTokenRepository;
import com.vikas.authsystem.security.JwtUtil;
import com.vikas.authsystem.security.SessionBlacklistService;
import io.micrometer.core.instrument.Timer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;
    private final JwtUtil jwtUtil;
    private final SessionBlacklistService sessionBlacklistService;
    private final AuditService auditService;
    private final AuthMetricsService authMetricsService;
    private final Clock clock;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            JwtProperties jwtProperties,
            JwtUtil jwtUtil,
            SessionBlacklistService sessionBlacklistService,
            AuditService auditService,
            AuthMetricsService authMetricsService,
            Clock clock
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtProperties = jwtProperties;
        this.jwtUtil = jwtUtil;
        this.sessionBlacklistService = sessionBlacklistService;
        this.auditService = auditService;
        this.authMetricsService = authMetricsService;
        this.clock = clock;
    }

    public String generateRawRefreshToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public Instant refreshTokenExpiryDate() {
        return Instant.now(clock).plus(jwtProperties.getRefreshTokenDays(), ChronoUnit.DAYS);
    }

    @Transactional
    public StoredSession storeRefreshToken(User user, String rawRefreshToken, String deviceId, String clientIp) {
        String normalizedDeviceId = normalizeDeviceId(deviceId);
        Instant now = Instant.now(clock);
        // Keep a single active refresh token per user/device pair to simplify revocation and replay handling.
        revokeActiveTokensForDevice(user.getId(), normalizedDeviceId, null);
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(hashToken(rawRefreshToken));
        refreshToken.setSessionId(UUID.randomUUID());
        refreshToken.setDeviceId(normalizedDeviceId);
        refreshToken.setExpiryDate(refreshTokenExpiryDate());
        refreshToken.setSessionStartedAt(now);
        refreshToken.setLastUsedAt(now);
        refreshToken.setLastSeenIp(normalizeIpAddress(clientIp));
        refreshTokenRepository.save(refreshToken);
        return toStoredSession(refreshToken);
    }

    @Transactional
    public LoginResponse refreshAccessToken(String rawRefreshToken, String deviceId, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            RefreshToken currentToken = refreshTokenRepository.findByTokenHash(hashToken(rawRefreshToken))
                    .orElse(null);
            if (currentToken == null) {
                outcome = "invalid_token";
                auditService.recordEvent(AuditAction.TOKEN_REFRESH_FAILED, null, deviceId, clientIp);
                throw new UnauthorizedException("Invalid refresh token");
            }

            RefreshTokenValidationFailure validationFailure = validateRefreshTokenForRotation(currentToken, deviceId);
            if (validationFailure != null) {
                outcome = validationFailure.metricOutcome();
                auditService.recordEvent(
                        AuditAction.TOKEN_REFRESH_FAILED,
                        currentToken.getUser().getId(),
                        currentToken.getDeviceId(),
                        clientIp
                );
                throw new UnauthorizedException(validationFailure.message());
            }

            Instant now = Instant.now(clock);
            String nextRefreshToken = generateRawRefreshToken();
            String nextRefreshTokenHash = hashToken(nextRefreshToken);
            // Rotation revokes the presented token and immediately replaces it with a new one.
            currentToken.setRevokedAt(now);
            currentToken.setReplacedByTokenHash(nextRefreshTokenHash);

            RefreshToken rotatedToken = new RefreshToken();
            rotatedToken.setUser(currentToken.getUser());
            rotatedToken.setTokenHash(nextRefreshTokenHash);
            rotatedToken.setSessionId(currentToken.getSessionId());
            rotatedToken.setDeviceId(currentToken.getDeviceId());
            rotatedToken.setExpiryDate(refreshTokenExpiryDate());
            rotatedToken.setSessionStartedAt(currentToken.getSessionStartedAt());
            rotatedToken.setLastUsedAt(now);
            rotatedToken.setLastSeenIp(normalizeIpAddress(clientIp));

            refreshTokenRepository.save(currentToken);
            refreshTokenRepository.save(rotatedToken);

            String accessToken = jwtUtil.generateAccessToken(
                    currentToken.getUser().getId(),
                    currentToken.getUser().getRole().name(),
                    currentToken.getSessionId()
            );
            auditService.recordEvent(
                    AuditAction.TOKEN_REFRESH,
                    currentToken.getUser().getId(),
                    currentToken.getDeviceId(),
                    clientIp
            );
            outcome = "success";
            return new LoginResponse(accessToken, nextRefreshToken, "Bearer", jwtUtil.accessTokenTtlSeconds());
        } finally {
            authMetricsService.recordOperation("refresh_token", outcome, sample);
        }
    }

    @Transactional
    public RefreshToken revokeRefreshToken(String rawRefreshToken, UUID expectedUserId) {
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(hashToken(rawRefreshToken))
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));
        if (expectedUserId != null && !refreshToken.getUser().getId().equals(expectedUserId)) {
            throw new UnauthorizedException("Refresh token does not belong to the authenticated user");
        }
        revokeToken(refreshToken, null);
        blacklistSession(refreshToken);
        return refreshToken;
    }

    @Transactional
    public void revokeAllTokensForUser(UUID userId) {
        revokeAllUserTokens(userId);
    }

    @Transactional(readOnly = true)
    public List<StoredSession> listActiveSessions(UUID userId) {
        return refreshTokenRepository.findAllByUser_IdAndRevokedAtIsNullOrderByLastUsedAtDesc(userId).stream()
                .map(this::toStoredSession)
                .toList();
    }

    @Transactional
    public void revokeSession(UUID userId, UUID sessionId) {
        RefreshToken activeSession = refreshTokenRepository.findByUser_IdAndSessionIdAndRevokedAtIsNull(userId, sessionId)
                .orElseThrow(() -> new ResourceNotFoundException("Session not found"));
        revokeToken(activeSession, null);
        blacklistSession(activeSession);
    }

    @Transactional
    public int revokeOtherSessions(UUID userId, UUID currentSessionId) {
        int revokedSessions = 0;
        List<RefreshToken> activeTokens = refreshTokenRepository.findAllByUser_IdAndRevokedAtIsNull(userId);
        for (RefreshToken token : activeTokens) {
            if (token.getSessionId().equals(currentSessionId)) {
                continue;
            }
            revokeToken(token, null);
            blacklistSession(token);
            revokedSessions++;
        }
        return revokedSessions;
    }

    @Transactional
    public void deleteExpiredRefreshTokens() {
        refreshTokenRepository.deleteAllExpiredSince(Instant.now(clock));
    }

    public String hashToken(String rawToken) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawToken.getBytes(StandardCharsets.UTF_8));
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 hashing algorithm is not available", e);
        }
    }

    private String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private RefreshTokenValidationFailure validateRefreshTokenForRotation(RefreshToken refreshToken, String deviceId) {
        if (refreshToken.getExpiryDate().isBefore(Instant.now(clock))) {
            revokeAllUserTokens(refreshToken.getUser().getId());
            return RefreshTokenValidationFailure.EXPIRED;
        }

        if (refreshToken.getRevokedAt() != null) {
            // A revoked token being presented again is treated as replay and forces user-wide revocation.
            revokeAllUserTokens(refreshToken.getUser().getId());
            log.warn("Refresh token reuse detected for userId={}", refreshToken.getUser().getId());
            return RefreshTokenValidationFailure.REPLAY_DETECTED;
        }

        String normalizedDeviceId = normalizeDeviceId(deviceId);
        if (!refreshToken.getDeviceId().equals(normalizedDeviceId)) {
            revokeAllUserTokens(refreshToken.getUser().getId());
            return RefreshTokenValidationFailure.DEVICE_MISMATCH;
        }
        return null;
    }

    private void revokeActiveTokensForDevice(UUID userId, String deviceId, String replacedByTokenHash) {
        for (RefreshToken token : refreshTokenRepository.findAllByUser_IdAndDeviceIdAndRevokedAtIsNull(userId, deviceId)) {
            revokeToken(token, replacedByTokenHash);
            blacklistSession(token);
        }
    }

    private void revokeAllUserTokens(UUID userId) {
        for (RefreshToken token : refreshTokenRepository.findAllByUser_IdAndRevokedAtIsNull(userId)) {
            revokeToken(token, null);
            blacklistSession(token);
        }
    }

    private void revokeToken(RefreshToken token, String replacedByTokenHash) {
        token.setRevokedAt(Instant.now(clock));
        token.setReplacedByTokenHash(replacedByTokenHash);
        refreshTokenRepository.save(token);
    }

    private String normalizeDeviceId(String deviceId) {
        return (deviceId == null || deviceId.isBlank()) ? "unknown-device" : deviceId.trim();
    }

    private String normalizeIpAddress(String ipAddress) {
        return (ipAddress == null || ipAddress.isBlank()) ? "unknown-ip" : ipAddress.trim();
    }

    private void blacklistSession(RefreshToken refreshToken) {
        long ttlSeconds = Math.max(
                0,
                refreshToken.getExpiryDate().getEpochSecond() - Instant.now(clock).getEpochSecond()
        );
        sessionBlacklistService.blacklist(refreshToken.getSessionId(), Duration.ofSeconds(ttlSeconds));
    }

    private StoredSession toStoredSession(RefreshToken refreshToken) {
        return new StoredSession(
                refreshToken.getSessionId(),
                refreshToken.getDeviceId(),
                refreshToken.getSessionStartedAt(),
                refreshToken.getLastUsedAt(),
                refreshToken.getExpiryDate(),
                refreshToken.getLastSeenIp()
        );
    }

    public record StoredSession(
            UUID sessionId,
            String deviceId,
            Instant sessionStartedAt,
            Instant lastUsedAt,
            Instant expiresAt,
            String lastSeenIp
    ) {
    }

    private enum RefreshTokenValidationFailure {
        EXPIRED("expired_token", "Refresh token has expired"),
        REPLAY_DETECTED("replay_detected", "Refresh token reuse detected"),
        DEVICE_MISMATCH("device_mismatch", "Refresh token does not match device");

        private final String metricOutcome;
        private final String message;

        RefreshTokenValidationFailure(String metricOutcome, String message) {
            this.metricOutcome = metricOutcome;
            this.message = message;
        }

        public String metricOutcome() {
            return metricOutcome;
        }

        public String message() {
            return message;
        }
    }
}
