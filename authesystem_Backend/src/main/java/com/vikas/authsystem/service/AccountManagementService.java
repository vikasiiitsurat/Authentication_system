package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.DeleteAccountRequest;
import com.vikas.authsystem.entity.AuditAction;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.exception.BadRequestException;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.repository.UserRepository;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.security.SessionBlacklistService;
import com.vikas.authsystem.security.TokenBlacklistService;
import io.micrometer.core.instrument.Timer;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

@Service
public class AccountManagementService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final LoginProtectionService loginProtectionService;
    private final TokenBlacklistService tokenBlacklistService;
    private final SessionBlacklistService sessionBlacklistService;
    private final AuditService auditService;
    private final AuthMetricsService authMetricsService;
    private final Clock clock;

    public AccountManagementService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            RefreshTokenService refreshTokenService,
            LoginProtectionService loginProtectionService,
            TokenBlacklistService tokenBlacklistService,
            SessionBlacklistService sessionBlacklistService,
            AuditService auditService,
            AuthMetricsService authMetricsService,
            Clock clock
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
        this.loginProtectionService = loginProtectionService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.sessionBlacklistService = sessionBlacklistService;
        this.auditService = auditService;
        this.authMetricsService = authMetricsService;
        this.clock = clock;
    }

    @Transactional
    public void deleteAuthenticatedAccount(AuthenticatedUser authenticatedUser, DeleteAccountRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            if (authenticatedUser == null) {
                throw new UnauthorizedException("Authentication is required");
            }

            User user = userRepository.findByIdForUpdate(authenticatedUser.getUserId())
                    .orElseThrow(() -> new UnauthorizedException("Authenticated user not found"));

            if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
                outcome = "invalid_current_password";
                auditService.recordEvent(AuditAction.ACCOUNT_DELETE_FAILED, user.getId(), request.deviceId(), clientIp);
                throw new UnauthorizedException("Current password is invalid");
            }

            String normalizedConfirmedEmail = normalizeEmail(request.confirmEmail());
            if (!user.getEmail().equals(normalizedConfirmedEmail)) {
                outcome = "invalid_confirmation";
                auditService.recordEvent(AuditAction.ACCOUNT_DELETE_FAILED, user.getId(), request.deviceId(), clientIp);
                throw new BadRequestException("Account deletion confirmation email does not match the authenticated account");
            }

            String activeEmail = user.getEmail();
            softDeleteUser(user);
            schedulePostCommitCleanup(user.getId(), authenticatedUser, activeEmail, clientIp, request.deviceId());
            outcome = "success";
        } finally {
            authMetricsService.recordOperation("delete_account", outcome, sample);
        }
    }

    private void revokeAuthenticatedAccess(AuthenticatedUser authenticatedUser) {
        Instant tokenExpiresAt = authenticatedUser.getTokenExpiresAt();
        if (authenticatedUser.getTokenId() != null && tokenExpiresAt != null) {
            long ttlSeconds = Math.max(0, tokenExpiresAt.getEpochSecond() - Instant.now(clock).getEpochSecond());
            tokenBlacklistService.blacklist(authenticatedUser.getTokenId(), Duration.ofSeconds(ttlSeconds));
        }
        if (authenticatedUser.getSessionId() != null && tokenExpiresAt != null) {
            long ttlSeconds = Math.max(0, tokenExpiresAt.getEpochSecond() - Instant.now(clock).getEpochSecond());
            sessionBlacklistService.blacklist(authenticatedUser.getSessionId(), Duration.ofSeconds(ttlSeconds));
        }
    }

    private String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase();
    }

    private void softDeleteUser(User user) {
        Instant now = Instant.now(clock);
        String normalizedEmail = normalizeEmail(user.getEmail());
        user.setDeletedAt(now);
        user.setDeletedEmailHash(hashValue(normalizedEmail));
        user.setEmail(buildDeletedEmailAlias(user.getId()));
        user.setPasswordHash(passwordEncoder.encode(buildDeletedPasswordSecret(user.getId(), now)));
        user.setEmailVerified(false);
        user.setEmailVerifiedAt(null);
        user.setPasswordChangedAt(now);
        user.setSessionInvalidatedAt(now);
        userRepository.save(user);
    }

    private void schedulePostCommitCleanup(
            java.util.UUID userId,
            AuthenticatedUser authenticatedUser,
            String activeEmail,
            String clientIp,
            String deviceId
    ) {
        if (!TransactionSynchronizationManager.isSynchronizationActive()) {
            refreshTokenService.revokeAllTokensForUser(userId);
            revokeAuthenticatedAccess(authenticatedUser);
            loginProtectionService.clearSuccess(activeEmail, clientIp);
            auditService.recordEvent(AuditAction.ACCOUNT_DELETE, userId, deviceId, clientIp);
            return;
        }
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                refreshTokenService.revokeAllTokensForUser(userId);
                revokeAuthenticatedAccess(authenticatedUser);
                loginProtectionService.clearSuccess(activeEmail, clientIp);
                auditService.recordEvent(AuditAction.ACCOUNT_DELETE, userId, deviceId, clientIp);
            }
        });
    }

    private String buildDeletedEmailAlias(java.util.UUID userId) {
        return "deleted+" + userId + "@deleted.auth.local";
    }

    private String buildDeletedPasswordSecret(java.util.UUID userId, Instant deletedAt) {
        return "deleted:" + hashValue(userId + ":" + deletedAt).substring(0, 32);
    }

    private String hashValue(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(value.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte current : hash) {
                builder.append(String.format("%02x", current));
            }
            return builder.toString();
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 hashing algorithm is not available", ex);
        }
    }
}
