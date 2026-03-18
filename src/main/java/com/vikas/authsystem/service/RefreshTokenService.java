package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.config.JwtProperties;
import com.vikas.authsystem.entity.AuditAction;
import com.vikas.authsystem.entity.RefreshToken;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.repository.RefreshTokenRepository;
import com.vikas.authsystem.security.JwtUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private static final Logger log = LoggerFactory.getLogger(RefreshTokenService.class);
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtProperties jwtProperties;
    private final JwtUtil jwtUtil;
    private final AuditService auditService;
    private final SecureRandom secureRandom = new SecureRandom();

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            JwtProperties jwtProperties,
            JwtUtil jwtUtil,
            AuditService auditService
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtProperties = jwtProperties;
        this.jwtUtil = jwtUtil;
        this.auditService = auditService;
    }

    public String generateRawRefreshToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    public Instant refreshTokenExpiryDate() {
        return Instant.now().plus(jwtProperties.getRefreshTokenDays(), ChronoUnit.DAYS);
    }

    @Transactional
    public void storeRefreshToken(User user, String rawRefreshToken, String deviceId) {
        String normalizedDeviceId = normalizeDeviceId(deviceId);
        // Keep a single active refresh token per user/device pair to simplify revocation and replay handling.
        revokeActiveTokensForDevice(user.getId(), normalizedDeviceId, null);
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenHash(hashToken(rawRefreshToken));
        refreshToken.setDeviceId(normalizedDeviceId);
        refreshToken.setExpiryDate(refreshTokenExpiryDate());
        refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public LoginResponse refreshAccessToken(String rawRefreshToken, String deviceId, String clientIp) {
        RefreshToken currentToken = refreshTokenRepository.findByTokenHash(hashToken(rawRefreshToken))
                .orElse(null);
        if (currentToken == null) {
            auditService.recordEvent(AuditAction.TOKEN_REFRESH_FAILED, null, deviceId, clientIp);
            throw new UnauthorizedException("Invalid refresh token");
        }

        try {
            validateRefreshTokenForRotation(currentToken, deviceId);
        } catch (UnauthorizedException ex) {
            auditService.recordEvent(
                    AuditAction.TOKEN_REFRESH_FAILED,
                    currentToken.getUser().getId(),
                    currentToken.getDeviceId(),
                    clientIp
            );
            throw ex;
        }

        String nextRefreshToken = generateRawRefreshToken();
        String nextRefreshTokenHash = hashToken(nextRefreshToken);
        // Rotation revokes the presented token and immediately replaces it with a new one.
        currentToken.setRevokedAt(Instant.now());
        currentToken.setReplacedByTokenHash(nextRefreshTokenHash);

        RefreshToken rotatedToken = new RefreshToken();
        rotatedToken.setUser(currentToken.getUser());
        rotatedToken.setTokenHash(nextRefreshTokenHash);
        rotatedToken.setDeviceId(currentToken.getDeviceId());
        rotatedToken.setExpiryDate(refreshTokenExpiryDate());

        refreshTokenRepository.save(currentToken);
        refreshTokenRepository.save(rotatedToken);

        String accessToken = jwtUtil.generateAccessToken(currentToken.getUser().getId(), currentToken.getUser().getRole().name());
        auditService.recordEvent(
                AuditAction.TOKEN_REFRESH,
                currentToken.getUser().getId(),
                currentToken.getDeviceId(),
                clientIp
        );
        return new LoginResponse(accessToken, nextRefreshToken, "Bearer", jwtUtil.accessTokenTtlSeconds());
    }

    @Transactional
    public RefreshToken revokeRefreshToken(String rawRefreshToken, UUID expectedUserId) {
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(hashToken(rawRefreshToken))
                .orElseThrow(() -> new UnauthorizedException("Invalid refresh token"));
        if (expectedUserId != null && !refreshToken.getUser().getId().equals(expectedUserId)) {
            throw new UnauthorizedException("Refresh token does not belong to the authenticated user");
        }
        revokeToken(refreshToken, null);
        return refreshToken;
    }

    @Transactional
    public void revokeAllTokensForUser(UUID userId) {
        revokeAllUserTokens(userId);
    }

    @Transactional
    public void deleteExpiredRefreshTokens() {
        refreshTokenRepository.deleteAllExpiredSince(Instant.now());
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

    private void validateRefreshTokenForRotation(RefreshToken refreshToken, String deviceId) {
        if (refreshToken.getExpiryDate().isBefore(Instant.now())) {
            revokeAllUserTokens(refreshToken.getUser().getId());
            throw new UnauthorizedException("Refresh token has expired");
        }

        if (refreshToken.getRevokedAt() != null) {
            // A revoked token being presented again is treated as replay and forces user-wide revocation.
            revokeAllUserTokens(refreshToken.getUser().getId());
            log.warn("Refresh token reuse detected for userId={}", refreshToken.getUser().getId());
            throw new UnauthorizedException("Refresh token reuse detected");
        }

        String normalizedDeviceId = normalizeDeviceId(deviceId);
        if (!refreshToken.getDeviceId().equals(normalizedDeviceId)) {
            revokeAllUserTokens(refreshToken.getUser().getId());
            throw new UnauthorizedException("Refresh token does not match device");
        }
    }

    private void revokeActiveTokensForDevice(UUID userId, String deviceId, String replacedByTokenHash) {
        for (RefreshToken token : refreshTokenRepository.findAllByUser_IdAndDeviceIdAndRevokedAtIsNull(userId, deviceId)) {
            revokeToken(token, replacedByTokenHash);
        }
    }

    private void revokeAllUserTokens(UUID userId) {
        for (RefreshToken token : refreshTokenRepository.findAllByUser_IdAndRevokedAtIsNull(userId)) {
            revokeToken(token, null);
        }
    }

    private void revokeToken(RefreshToken token, String replacedByTokenHash) {
        token.setRevokedAt(Instant.now());
        token.setReplacedByTokenHash(replacedByTokenHash);
        refreshTokenRepository.save(token);
    }

    private String normalizeDeviceId(String deviceId) {
        return (deviceId == null || deviceId.isBlank()) ? "unknown-device" : deviceId.trim();
    }
}
