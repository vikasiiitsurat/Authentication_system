package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.LoginRequest;
import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.dto.LogoutRequest;
import com.vikas.authsystem.dto.ForgotPasswordRequest;
import com.vikas.authsystem.dto.PasswordChangeRequest;
import com.vikas.authsystem.dto.PasswordResetRequestResponse;
import com.vikas.authsystem.dto.RefreshTokenRequest;
import com.vikas.authsystem.dto.ResendVerificationOtpRequest;
import com.vikas.authsystem.dto.RegisterRequest;
import com.vikas.authsystem.dto.RegisterResponse;
import com.vikas.authsystem.dto.ResetPasswordRequest;
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
import com.vikas.authsystem.security.SessionBlacklistService;
import com.vikas.authsystem.security.TokenBlacklistService;
import io.micrometer.core.instrument.Timer;
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
    private final SessionBlacklistService sessionBlacklistService;
    private final EmailVerificationOtpService emailVerificationOtpService;
    private final PasswordResetOtpService passwordResetOtpService;
    private final OtpDeliveryService otpDeliveryService;
    private final AuditService auditService;
    private final AuthMetricsService authMetricsService;
    private final Clock clock;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            RefreshTokenService refreshTokenService,
            TemporaryCacheService temporaryCacheService,
            TokenBlacklistService tokenBlacklistService,
            SessionBlacklistService sessionBlacklistService,
            EmailVerificationOtpService emailVerificationOtpService,
            PasswordResetOtpService passwordResetOtpService,
            OtpDeliveryService otpDeliveryService,
            AuditService auditService,
            AuthMetricsService authMetricsService,
            Clock clock
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
        this.temporaryCacheService = temporaryCacheService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.sessionBlacklistService = sessionBlacklistService;
        this.emailVerificationOtpService = emailVerificationOtpService;
        this.passwordResetOtpService = passwordResetOtpService;
        this.otpDeliveryService = otpDeliveryService;
        this.auditService = auditService;
        this.authMetricsService = authMetricsService;
        this.clock = clock;
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            String normalizedEmail = normalizeEmail(request.email());
            User existingUser = userRepository.findByEmail(normalizedEmail).orElse(null);
            if (existingUser != null && existingUser.isEmailVerified()) {
                outcome = "already_registered";
                auditService.recordEvent(AuditAction.REGISTER_FAILED, null, null, clientIp);
                throw new ResourceConflictException("Email is already registered");
            }
            if (existingUser != null) {
                existingUser.setPasswordHash(passwordEncoder.encode(request.password()));
                existingUser.setPasswordChangedAt(Instant.now(clock));
                clearFailedLoginState(existingUser);
                userRepository.save(existingUser);
                EmailVerificationOtpService.OtpIssueResult otpIssueResult = emailVerificationOtpService.reissueOtp(existingUser.getId());
                otpDeliveryService.sendVerificationOtp(existingUser.getEmail(), otpIssueResult.otp(), otpIssueResult.expiresInSeconds());
                auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_OTP_RESENT, existingUser.getId(), null, clientIp);
                outcome = "pending_verification";
                return new RegisterResponse(
                        existingUser.getId(),
                        existingUser.getEmail(),
                        "Registration is pending email verification. An OTP has been sent.",
                        existingUser.getCreatedAt(),
                        true,
                        otpIssueResult.expiresInSeconds(),
                        otpIssueResult.resendAvailableInSeconds()
                );
            }

            User user = new User();
            user.setEmail(normalizedEmail);
            user.setPasswordHash(passwordEncoder.encode(request.password()));
            user.setPasswordChangedAt(Instant.now(clock));
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
            outcome = "success";
            return new RegisterResponse(
                    savedUser.getId(),
                    savedUser.getEmail(),
                    "Registration successful. Verify the OTP within 3 minutes to activate the account.",
                    savedUser.getCreatedAt(),
                    true,
                    otpIssueResult.expiresInSeconds(),
                    otpIssueResult.resendAvailableInSeconds()
            );
        } finally {
            authMetricsService.recordOperation("register", outcome, sample);
        }
    }

    @Transactional
    public LoginResponse login(LoginRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            String normalizedEmail = normalizeEmail(request.email());
            User user = userRepository.findByEmailForUpdate(normalizedEmail)
                    .orElse(null);

            if (user == null) {
                outcome = "invalid_credentials";
                auditService.recordEvent(AuditAction.LOGIN_FAILED, null, request.deviceId(), clientIp);
                throw new UnauthorizedException("Invalid credentials");
            }

            Instant now = Instant.now(clock);
            if (isLockActive(user, now)) {
                outcome = "account_locked";
                auditService.recordEvent(AuditAction.ACCOUNT_LOCKED, user.getId(), request.deviceId(), clientIp);
                throw new AccountLockedException(
                        buildLockMessage(user.getLockUntil(), now),
                        secondsUntil(user.getLockUntil(), now)
                );
            }

            if (hasExpiredLock(user, now)) {
                clearExpiredLock(user);
            }

            if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
                boolean accountLocked = handleFailedLogin(user, now);
                outcome = accountLocked ? "account_locked" : "invalid_credentials";
                auditService.recordEvent(AuditAction.LOGIN_FAILED, user.getId(), request.deviceId(), clientIp);
                if (accountLocked) {
                    auditService.recordEvent(AuditAction.ACCOUNT_LOCKED, user.getId(), request.deviceId(), clientIp);
                    throw new AccountLockedException(
                            buildLockMessage(user.getLockUntil(), now),
                            secondsUntil(user.getLockUntil(), now)
                    );
                }
                throw new UnauthorizedException("Invalid credentials");
            }

            if (!user.isEmailVerified()) {
                outcome = "email_verification_required";
                auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_REQUIRED, user.getId(), request.deviceId(), clientIp);
                throw new ForbiddenException("Email verification is required before logging in");
            }

            resetFailedLoginState(user);
            // Access tokens stay stateless while refresh-token lifecycle is delegated to RefreshTokenService.
            String refreshToken = refreshTokenService.generateRawRefreshToken();
            RefreshTokenService.StoredSession storedSession = refreshTokenService.storeRefreshToken(
                    user,
                    refreshToken,
                    request.deviceId(),
                    clientIp
            );
            String accessToken = jwtUtil.generateAccessToken(user.getId(), user.getRole().name(), storedSession.sessionId());
            temporaryCacheService.cacheLastLoginMetadata(user.getId(), clientIp);
            refreshTokenService.deleteExpiredRefreshTokens();
            auditService.recordEvent(AuditAction.LOGIN_SUCCESS, user.getId(), request.deviceId(), clientIp);

            log.info("User login succeeded for userId={} from ip={}", user.getId(), clientIp);
            outcome = "success";
            return new LoginResponse(accessToken, refreshToken, "Bearer", jwtUtil.accessTokenTtlSeconds());
        } finally {
            authMetricsService.recordOperation("login", outcome, sample);
        }
    }

    @Transactional
    public LoginResponse refresh(RefreshTokenRequest request, String clientIp) {
        return refreshTokenService.refreshAccessToken(request.refreshToken(), request.deviceId(), clientIp);
    }

    @Transactional
    public EmailVerificationStatusResponse verifyEmailOtp(VerifyEmailOtpRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            User user = userRepository.findByEmailForUpdate(normalizeEmail(request.email()))
                    .orElseThrow(() -> new BadRequestException("Invalid verification request"));
            if (user.isEmailVerified()) {
                outcome = "already_verified";
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
                outcome = "invalid_otp";
                auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_FAILED, user.getId(), request.deviceId(), clientIp);
                throw ex;
            }

            Instant verifiedAt = Instant.now(clock);
            user.setEmailVerified(true);
            user.setEmailVerifiedAt(verifiedAt);
            userRepository.save(user);
            auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_SUCCESS, user.getId(), request.deviceId(), clientIp);
            outcome = "success";
            return new EmailVerificationStatusResponse(
                    user.getEmail(),
                    "Email verified successfully",
                    true,
                    verifiedAt,
                    0,
                    0
            );
        } finally {
            authMetricsService.recordOperation("verify_email_otp", outcome, sample);
        }
    }

    @Transactional
    public EmailVerificationStatusResponse resendVerificationOtp(ResendVerificationOtpRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            String normalizedEmail = normalizeEmail(request.email());
            User user = userRepository.findByEmailForUpdate(normalizedEmail).orElse(null);
            if (user == null || user.isEmailVerified()) {
                outcome = "accepted";
                return genericResendResponse(normalizedEmail);
            }

            EmailVerificationOtpService.OtpIssueResult otpIssueResult = emailVerificationOtpService.reissueOtp(user.getId());
            otpDeliveryService.sendVerificationOtp(user.getEmail(), otpIssueResult.otp(), otpIssueResult.expiresInSeconds());
            auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_OTP_RESENT, user.getId(), null, clientIp);
            outcome = "success";
            return new EmailVerificationStatusResponse(
                    user.getEmail(),
                    "A verification OTP has been sent. It expires in " + formatRetryAfter(otpIssueResult.expiresInSeconds()) + ".",
                    false,
                    null,
                    otpIssueResult.expiresInSeconds(),
                    otpIssueResult.resendAvailableInSeconds()
            );
        } finally {
            authMetricsService.recordOperation("resend_verification_otp", outcome, sample);
        }
    }

    @Transactional
    public void logout(LogoutRequest request, AuthenticatedUser authenticatedUser, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
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
                outcome = "invalid_refresh_token";
                auditService.recordEvent(AuditAction.LOGOUT_FAILED, authenticatedUserId, null, clientIp);
                throw ex;
            }
            auditService.recordEvent(
                    AuditAction.LOGOUT,
                    refreshToken.getUser().getId(),
                    refreshToken.getDeviceId(),
                    clientIp
            );
            outcome = "success";
        } finally {
            authMetricsService.recordOperation("logout", outcome, sample);
        }
    }

    @Transactional
    public void changePassword(AuthenticatedUser authenticatedUser, PasswordChangeRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            User user = userRepository.findByIdForUpdate(authenticatedUser.getUserId())
                    .orElseThrow(() -> new UnauthorizedException("Authenticated user not found"));

            if (!passwordEncoder.matches(request.currentPassword(), user.getPasswordHash())) {
                outcome = "invalid_current_password";
                auditService.recordEvent(AuditAction.PASSWORD_CHANGE_FAILED, user.getId(), request.deviceId(), clientIp);
                throw new UnauthorizedException("Current password is invalid");
            }

            if (request.currentPassword().equals(request.newPassword())) {
                outcome = "password_reuse";
                auditService.recordEvent(AuditAction.PASSWORD_CHANGE_FAILED, user.getId(), request.deviceId(), clientIp);
                throw new BadRequestException("New password must be different from the current password");
            }

            rotatePassword(user, request.newPassword());
            revokeAuthenticatedAccess(authenticatedUser);
            auditService.recordEvent(AuditAction.PASSWORD_CHANGE, user.getId(), request.deviceId(), clientIp);
            outcome = "success";
        } finally {
            authMetricsService.recordOperation("change_password", outcome, sample);
        }
    }

    @Transactional
    public PasswordResetRequestResponse requestPasswordReset(ForgotPasswordRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "accepted";
        String normalizedEmail = normalizeEmail(request.email());
        try {
            User user = userRepository.findByEmailForUpdate(normalizedEmail).orElse(null);
            if (user == null || !user.isEmailVerified()) {
                log.info(
                        "password_reset_request_accepted_without_dispatch email={} reason={}",
                        normalizedEmail,
                        user == null ? "user_not_found" : "email_not_verified"
                );
                return genericPasswordResetResponse(normalizedEmail);
            }

            auditService.recordEvent(AuditAction.PASSWORD_RESET_REQUESTED, user.getId(), null, clientIp);
            PasswordResetOtpService.OtpDispatchResult otpDispatchResult = passwordResetOtpService.requestOtp(user.getId());
            if (otpDispatchResult.dispatched()) {
                otpDeliveryService.sendPasswordResetOtp(user.getEmail(), otpDispatchResult.otp(), otpDispatchResult.expiresInSeconds());
                auditService.recordEvent(AuditAction.PASSWORD_RESET_OTP_SENT, user.getId(), null, clientIp);
                log.info("password_reset_otp_dispatch_succeeded userId={} email={}", user.getId(), user.getEmail());
                outcome = "dispatched";
            } else {
                log.info(
                        "password_reset_request_accepted_without_dispatch email={} reason=cooldown_or_budget_suppressed",
                        normalizedEmail
                );
            }
            return genericPasswordResetResponse(normalizedEmail);
        } finally {
            authMetricsService.recordOperation("request_password_reset", outcome, sample);
        }
    }

    @Transactional
    public void resetPassword(ResetPasswordRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            User user = userRepository.findByEmailForUpdate(normalizeEmail(request.email())).orElse(null);
            if (user == null) {
                outcome = "invalid_request";
                throw new BadRequestException("Invalid password reset request");
            }
            if (!user.isEmailVerified()) {
                outcome = "invalid_request";
                throw new BadRequestException("Invalid password reset request");
            }

            try {
                passwordResetOtpService.verifyOtp(user.getId(), request.otp());
            } catch (BadRequestException ex) {
                outcome = "invalid_otp";
                auditService.recordEvent(AuditAction.PASSWORD_RESET_FAILED, user.getId(), request.deviceId(), clientIp);
                throw ex;
            }

            if (passwordEncoder.matches(request.newPassword(), user.getPasswordHash())) {
                outcome = "password_reuse";
                auditService.recordEvent(AuditAction.PASSWORD_RESET_FAILED, user.getId(), request.deviceId(), clientIp);
                throw new BadRequestException("New password must be different from the current password");
            }

            rotatePassword(user, request.newPassword());
            auditService.recordEvent(AuditAction.PASSWORD_RESET_SUCCESS, user.getId(), request.deviceId(), clientIp);
            outcome = "success";
        } finally {
            authMetricsService.recordOperation("reset_password", outcome, sample);
        }
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

    private EmailVerificationStatusResponse genericResendResponse(String email) {
        return new EmailVerificationStatusResponse(
                email,
                "If the account exists and is pending verification, an OTP will be sent if resend rules allow it.",
                false,
                null,
                0,
                0
        );
    }

    private PasswordResetRequestResponse genericPasswordResetResponse(String email) {
        return new PasswordResetRequestResponse(
                email,
                "If the account exists and is eligible, a password reset code will be sent. The code expires in 10 minutes.",
                passwordResetOtpService.expiresInSeconds(),
                passwordResetOtpService.resendCooldownSeconds()
        );
    }

    private void clearFailedLoginState(User user) {
        user.setFailedAttempts(0);
        user.setLockUntil(null);
        user.setLastFailedAttempt(null);
    }

    private void rotatePassword(User user, String rawPassword) {
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setPasswordChangedAt(Instant.now(clock));
        resetFailedLoginState(user);
        refreshTokenService.revokeAllTokensForUser(user.getId());
    }

    private void revokeAuthenticatedAccess(AuthenticatedUser authenticatedUser) {
        if (authenticatedUser.getTokenId() != null && authenticatedUser.getTokenExpiresAt() != null) {
            long ttlSeconds = Math.max(
                    0,
                    authenticatedUser.getTokenExpiresAt().getEpochSecond() - Instant.now(clock).getEpochSecond()
            );
            tokenBlacklistService.blacklist(authenticatedUser.getTokenId(), Duration.ofSeconds(ttlSeconds));
        }
        if (authenticatedUser.getSessionId() != null && authenticatedUser.getTokenExpiresAt() != null) {
            long ttlSeconds = Math.max(
                    0,
                    authenticatedUser.getTokenExpiresAt().getEpochSecond() - Instant.now(clock).getEpochSecond()
            );
            sessionBlacklistService.blacklist(authenticatedUser.getSessionId(), Duration.ofSeconds(ttlSeconds));
        }
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

    private long secondsUntil(Instant lockUntil, Instant currentTime) {
        if (lockUntil == null) {
            return 0;
        }
        return Math.max(0, Duration.between(currentTime, lockUntil).getSeconds());
    }

    private String buildLockMessage(Instant lockUntil, Instant currentTime) {
        long remainingSeconds = secondsUntil(lockUntil, currentTime);
        return "Account is locked. Try again in " + formatRetryAfter(remainingSeconds) + ".";
    }

    private String formatRetryAfter(long remainingSeconds) {
        if (remainingSeconds <= 0) {
            return "a few seconds";
        }

        long hours = remainingSeconds / 3600;
        long minutes = (remainingSeconds % 3600) / 60;
        long seconds = remainingSeconds % 60;

        if (hours > 0) {
            return minutes > 0
                    ? hours + " hour" + pluralize(hours) + " and " + minutes + " minute" + pluralize(minutes)
                    : hours + " hour" + pluralize(hours);
        }
        if (minutes > 0) {
            return seconds > 0
                    ? minutes + " minute" + pluralize(minutes) + " and " + seconds + " second" + pluralize(seconds)
                    : minutes + " minute" + pluralize(minutes);
        }
        return seconds + " second" + pluralize(seconds);
    }

    private String pluralize(long value) {
        return value == 1 ? "" : "s";
    }
}
