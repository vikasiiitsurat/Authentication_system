package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.LoginRequest;
import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.dto.LogoutRequest;
import com.vikas.authsystem.dto.PasswordChangeRequest;
import com.vikas.authsystem.dto.RefreshTokenRequest;
import com.vikas.authsystem.dto.ResendVerificationOtpRequest;
import com.vikas.authsystem.dto.RegisterRequest;
import com.vikas.authsystem.dto.RegisterResponse;
import com.vikas.authsystem.dto.VerifyEmailOtpRequest;
import com.vikas.authsystem.dto.EmailVerificationStatusResponse;
import com.vikas.authsystem.entity.AuditAction;
import com.vikas.authsystem.entity.RefreshToken;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.exception.AccountLockedException;
import com.vikas.authsystem.exception.BadRequestException;
import com.vikas.authsystem.exception.ForbiddenException;
import com.vikas.authsystem.exception.ResourceConflictException;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.repository.UserRepository;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.security.JwtUtil;
import com.vikas.authsystem.security.TokenBlacklistService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private static final int MAX_FAILED_ATTEMPTS = 5;
    private static final Duration INITIAL_LOCK_DURATION = Duration.ofMinutes(5);
    private static final Duration SECOND_LOCK_DURATION = Duration.ofMinutes(10);
    private static final Duration THIRD_LOCK_DURATION = Duration.ofMinutes(40);
    private static final Duration MAX_LOCK_DURATION = Duration.ofHours(24);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final TemporaryCacheService temporaryCacheService;
    private final TokenBlacklistService tokenBlacklistService;
    private final EmailVerificationOtpService emailVerificationOtpService;
    private final OtpDeliveryService otpDeliveryService;
    private final AuditService auditService;
    private final Clock clock;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            RefreshTokenService refreshTokenService,
            TemporaryCacheService temporaryCacheService,
            TokenBlacklistService tokenBlacklistService,
            EmailVerificationOtpService emailVerificationOtpService,
            OtpDeliveryService otpDeliveryService,
            AuditService auditService,
            Clock clock
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
        this.temporaryCacheService = temporaryCacheService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.emailVerificationOtpService = emailVerificationOtpService;
        this.otpDeliveryService = otpDeliveryService;
        this.auditService = auditService;
        this.clock = clock;
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request, String clientIp) {
        String normalizedEmail = normalizeEmail(request.email());
        User existingUser = userRepository.findByEmail(normalizedEmail).orElse(null);
        if (existingUser != null && existingUser.isEmailVerified()) {
            auditService.recordEvent(AuditAction.REGISTER_FAILED, null, null, clientIp);
            throw new ResourceConflictException("Email is already registered");
        }
        if (existingUser != null) {
            existingUser.setPasswordHash(passwordEncoder.encode(request.password()));
            clearFailedLoginState(existingUser);
            userRepository.save(existingUser);
            EmailVerificationOtpService.OtpIssueResult otpIssueResult = emailVerificationOtpService.reissueOtp(existingUser.getId());
            otpDeliveryService.sendVerificationOtp(existingUser.getEmail(), otpIssueResult.otp(), otpIssueResult.expiresInSeconds());
            auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_OTP_RESENT, existingUser.getId(), null, clientIp);
            return new RegisterResponse(
                    existingUser.getId(),
                    existingUser.getEmail(),
                    "Registration is pending email verification. A fresh OTP has been sent.",
                    existingUser.getCreatedAt(),
                    true,
                    otpIssueResult.expiresInSeconds(),
                    otpIssueResult.resendAvailableInSeconds()
            );
        }

        User user = new User();
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(UserRole.USER);
        user.setEmailVerified(false);
        user.setEmailVerifiedAt(null);
        clearFailedLoginState(user);
        User savedUser = userRepository.save(user);
        EmailVerificationOtpService.OtpIssueResult otpIssueResult = emailVerificationOtpService.issueOtp(savedUser.getId());
        otpDeliveryService.sendVerificationOtp(savedUser.getEmail(), otpIssueResult.otp(), otpIssueResult.expiresInSeconds());
        auditService.recordEvent(AuditAction.REGISTER_SUCCESS, savedUser.getId(), null, clientIp);
        auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_OTP_SENT, savedUser.getId(), null, clientIp);

        log.info("User registered successfully with userId={}", savedUser.getId());
        return new RegisterResponse(
                savedUser.getId(),
                savedUser.getEmail(),
                "Registration successful. Verify the OTP within 3 minutes to activate the account.",
                savedUser.getCreatedAt(),
                true,
                otpIssueResult.expiresInSeconds(),
                otpIssueResult.resendAvailableInSeconds()
        );
    }

    @Transactional
    public LoginResponse login(LoginRequest request, String clientIp) {
        String normalizedEmail = normalizeEmail(request.email());
        User user = userRepository.findByEmailForUpdate(normalizedEmail)
                .orElse(null);

        if (user == null) {
            auditService.recordEvent(AuditAction.LOGIN_FAILED, null, request.deviceId(), clientIp);
            throw new UnauthorizedException("Invalid credentials");
        }

        Instant now = Instant.now(clock);
        if (isLockActive(user, now)) {
            auditService.recordEvent(AuditAction.ACCOUNT_LOCKED, user.getId(), request.deviceId(), clientIp);
            throw new AccountLockedException(buildLockMessage(user.getLockUntil()));
        }

        if (hasExpiredLock(user, now)) {
            clearExpiredLock(user);
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            boolean accountLocked = handleFailedLogin(user, now);
            auditService.recordEvent(AuditAction.LOGIN_FAILED, user.getId(), request.deviceId(), clientIp);
            if (accountLocked) {
                auditService.recordEvent(AuditAction.ACCOUNT_LOCKED, user.getId(), request.deviceId(), clientIp);
            }
            throw new UnauthorizedException("Invalid credentials");
        }

        if (!user.isEmailVerified()) {
            auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_REQUIRED, user.getId(), request.deviceId(), clientIp);
            throw new ForbiddenException("Email verification is required before logging in");
        }

        resetFailedLoginState(user);
        // Access tokens stay stateless while refresh-token lifecycle is delegated to RefreshTokenService.
        String accessToken = jwtUtil.generateAccessToken(user.getId(), user.getRole().name());
        String refreshToken = refreshTokenService.generateRawRefreshToken();
        refreshTokenService.storeRefreshToken(user, refreshToken, request.deviceId());
        temporaryCacheService.cacheLastLoginMetadata(user.getId(), clientIp);
        refreshTokenService.deleteExpiredRefreshTokens();
        auditService.recordEvent(AuditAction.LOGIN_SUCCESS, user.getId(), request.deviceId(), clientIp);

        log.info("User login succeeded for userId={} from ip={}", user.getId(), clientIp);
        return new LoginResponse(accessToken, refreshToken, "Bearer", jwtUtil.accessTokenTtlSeconds());
    }

    @Transactional
    public LoginResponse refresh(RefreshTokenRequest request, String clientIp) {
        return refreshTokenService.refreshAccessToken(request.refreshToken(), request.deviceId(), clientIp);
    }

    @Transactional
    public EmailVerificationStatusResponse verifyEmailOtp(VerifyEmailOtpRequest request, String clientIp) {
        User user = userRepository.findByEmailForUpdate(normalizeEmail(request.email()))
                .orElseThrow(() -> new BadRequestException("Invalid verification request"));
        if (user.isEmailVerified()) {
            return new EmailVerificationStatusResponse(
                    user.getEmail(),
                    "Email is already verified",
                    true,
                    user.getEmailVerifiedAt(),
                    0,
                    0
            );
        }

        try {
            emailVerificationOtpService.verifyOtp(user.getId(), request.otp());
        } catch (BadRequestException ex) {
            auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_FAILED, user.getId(), request.deviceId(), clientIp);
            throw ex;
        }

        Instant verifiedAt = Instant.now(clock);
        user.setEmailVerified(true);
        user.setEmailVerifiedAt(verifiedAt);
        userRepository.save(user);
        auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_SUCCESS, user.getId(), request.deviceId(), clientIp);
        return new EmailVerificationStatusResponse(
                user.getEmail(),
                "Email verified successfully",
                true,
                verifiedAt,
                0,
                0
        );
    }

    @Transactional
    public EmailVerificationStatusResponse resendVerificationOtp(ResendVerificationOtpRequest request, String clientIp) {
        User user = userRepository.findByEmailForUpdate(normalizeEmail(request.email()))
                .orElseThrow(() -> new BadRequestException("Invalid resend request"));
        if (user.isEmailVerified()) {
            return new EmailVerificationStatusResponse(
                    user.getEmail(),
                    "Email is already verified",
                    true,
                    user.getEmailVerifiedAt(),
                    0,
                    0
            );
        }

        EmailVerificationOtpService.OtpIssueResult otpIssueResult = emailVerificationOtpService.reissueOtp(user.getId());
        otpDeliveryService.sendVerificationOtp(user.getEmail(), otpIssueResult.otp(), otpIssueResult.expiresInSeconds());
        auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_OTP_RESENT, user.getId(), null, clientIp);
        return new EmailVerificationStatusResponse(
                user.getEmail(),
                "A new OTP has been sent. It expires in 3 minutes.",
                false,
                null,
                otpIssueResult.expiresInSeconds(),
                otpIssueResult.resendAvailableInSeconds()
        );
    }

    @Transactional
    public void logout(LogoutRequest request, AuthenticatedUser authenticatedUser, String clientIp) {
        java.util.UUID authenticatedUserId = authenticatedUser == null ? null : authenticatedUser.getUserId();
        if (authenticatedUser != null && authenticatedUser.getTokenId() != null && authenticatedUser.getTokenExpiresAt() != null) {
            // The access token is blacklisted independently from refresh-token revocation to cover both token types.
            long ttlSeconds = Math.max(0, authenticatedUser.getTokenExpiresAt().getEpochSecond() - Instant.now(clock).getEpochSecond());
            tokenBlacklistService.blacklist(authenticatedUser.getTokenId(), java.time.Duration.ofSeconds(ttlSeconds));
        }
        RefreshToken refreshToken;
        try {
            refreshToken = refreshTokenService.revokeRefreshToken(request.refreshToken(), authenticatedUserId);
        } catch (UnauthorizedException ex) {
            auditService.recordEvent(AuditAction.LOGOUT_FAILED, authenticatedUserId, null, clientIp);
            throw ex;
        }
        auditService.recordEvent(
                AuditAction.LOGOUT,
                refreshToken.getUser().getId(),
                refreshToken.getDeviceId(),
                clientIp
        );
    }

    @Transactional
    public void changePassword(java.util.UUID authenticatedUserId, PasswordChangeRequest request, String clientIp) {
        User user = userRepository.findByIdForUpdate(authenticatedUserId)
                .orElseThrow(() -> new UnauthorizedException("Authenticated user not found"));

        if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
            auditService.recordEvent(AuditAction.PASSWORD_CHANGE_FAILED, user.getId(), request.deviceId(), clientIp);
            throw new UnauthorizedException("Current password is invalid");
        }

        if (request.currentPassword().equals(request.newPassword())) {
            auditService.recordEvent(AuditAction.PASSWORD_CHANGE_FAILED, user.getId(), request.deviceId(), clientIp);
            throw new BadRequestException("New password must be different from the current password");
        }

        user.setPasswordHash(passwordEncoder.encode(request.newPassword()));
        resetFailedLoginState(user);
        userRepository.save(user);
        // Rotating the password invalidates every active refresh token for the user.
        refreshTokenService.revokeAllTokensForUser(user.getId());
        auditService.recordEvent(AuditAction.PASSWORD_CHANGE, user.getId(), request.deviceId(), clientIp);
    }

    private boolean handleFailedLogin(User user, Instant currentTime) {
        int updatedAttempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(updatedAttempts);
        user.setLastFailedAttempt(currentTime);

        if (updatedAttempts < MAX_FAILED_ATTEMPTS) {
            log.warn("Failed login attempt {} for userId={}", updatedAttempts, user.getId());
            userRepository.save(user);
            return false;
        }

        Duration lockDuration = calculateLockDuration(updatedAttempts);
        Instant lockUntil = currentTime.plus(lockDuration);
        user.setLockUntil(lockUntil);
        userRepository.save(user);
        log.warn(
                "User account locked after {} failed attempts for userId={} until={}",
                updatedAttempts,
                user.getId(),
                lockUntil
        );
        return true;
    }

    private void resetFailedLoginState(User user) {
        clearFailedLoginState(user);
        userRepository.save(user);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }

    private void clearFailedLoginState(User user) {
        user.setFailedAttempts(0);
        user.setLockUntil(null);
        user.setLastFailedAttempt(null);
    }

    private void clearExpiredLock(User user) {
        // Keep failedAttempts intact so the next failure can escalate the backoff window.
        user.setLockUntil(null);
        userRepository.save(user);
    }

    private boolean isLockActive(User user, Instant currentTime) {
        Instant lockUntil = user.getLockUntil();
        return lockUntil != null && currentTime.isBefore(lockUntil);
    }

    private boolean hasExpiredLock(User user, Instant currentTime) {
        Instant lockUntil = user.getLockUntil();
        return lockUntil != null && !currentTime.isBefore(lockUntil);
    }

    private Duration calculateLockDuration(int failedAttempts) {
        return switch (failedAttempts) {
            case 5 -> INITIAL_LOCK_DURATION;
            case 6 -> SECOND_LOCK_DURATION;
            case 7 -> THIRD_LOCK_DURATION;
            default -> MAX_LOCK_DURATION;
        };
    }

    private String buildLockMessage(Instant lockUntil) {
        return "Account is locked until " + lockUntil;
    }
}
