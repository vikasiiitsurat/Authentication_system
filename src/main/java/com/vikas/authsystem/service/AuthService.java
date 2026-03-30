package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.LoginRequest;
import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.dto.ForgotPasswordRequest;
import com.vikas.authsystem.dto.GlobalLogoutResponse;
import com.vikas.authsystem.dto.PasswordChangeRequest;
import com.vikas.authsystem.dto.PasswordResetRequestResponse;
import com.vikas.authsystem.dto.RefreshTokenRequest;
import com.vikas.authsystem.dto.ResendVerificationOtpRequest;
import com.vikas.authsystem.dto.RegisterRequest;
import com.vikas.authsystem.dto.RegisterResponse;
import com.vikas.authsystem.dto.ResetPasswordRequest;
import com.vikas.authsystem.dto.VerifyEmailOtpRequest;
import com.vikas.authsystem.dto.EmailVerificationStatusResponse;
import com.vikas.authsystem.dto.AccountUnlockRequest;
import com.vikas.authsystem.dto.AccountUnlockRequestResponse;
import com.vikas.authsystem.entity.AuditAction;
import com.vikas.authsystem.entity.RefreshToken;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.dto.VerifyAccountUnlockRequest;
import com.vikas.authsystem.exception.BadRequestException;
import com.vikas.authsystem.exception.ResourceConflictException;
import com.vikas.authsystem.exception.TooManyRequestsException;
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
    private static final String GENERIC_LOGIN_FAILURE_MESSAGE = "Invalid email or password";

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final LoginProtectionService loginProtectionService;
    private final RefreshTokenService refreshTokenService;
    private final TemporaryCacheService temporaryCacheService;
    private final TokenBlacklistService tokenBlacklistService;
    private final SessionBlacklistService sessionBlacklistService;
    private final EmailVerificationOtpService emailVerificationOtpService;
    private final PasswordResetOtpService passwordResetOtpService;
    private final AccountUnlockOtpService accountUnlockOtpService;
    private final OtpDeliveryService otpDeliveryService;
    private final AuditService auditService;
    private final AuthMetricsService authMetricsService;
    private final Clock clock;
    private final String dummyPasswordHash;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            LoginProtectionService loginProtectionService,
            RefreshTokenService refreshTokenService,
            TemporaryCacheService temporaryCacheService,
            TokenBlacklistService tokenBlacklistService,
            SessionBlacklistService sessionBlacklistService,
            EmailVerificationOtpService emailVerificationOtpService,
            PasswordResetOtpService passwordResetOtpService,
            AccountUnlockOtpService accountUnlockOtpService,
            OtpDeliveryService otpDeliveryService,
            AuditService auditService,
            AuthMetricsService authMetricsService,
            Clock clock
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.loginProtectionService = loginProtectionService;
        this.refreshTokenService = refreshTokenService;
        this.temporaryCacheService = temporaryCacheService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.sessionBlacklistService = sessionBlacklistService;
        this.emailVerificationOtpService = emailVerificationOtpService;
        this.passwordResetOtpService = passwordResetOtpService;
        this.accountUnlockOtpService = accountUnlockOtpService;
        this.otpDeliveryService = otpDeliveryService;
        this.auditService = auditService;
        this.authMetricsService = authMetricsService;
        this.clock = clock;
        this.dummyPasswordHash = passwordEncoder.encode("auth-system-dummy-password");
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            String normalizedEmail = normalizeEmail(request.email());
            String normalizedFullName = normalizeFullName(request.fullName());
            User existingUser = userRepository.findByEmail(normalizedEmail).orElse(null);
            if (existingUser != null && existingUser.isEmailVerified()) {
                outcome = "already_registered";
                auditService.recordEvent(AuditAction.REGISTER_FAILED, null, null, clientIp);
                throw new ResourceConflictException("Email is already registered");
            }
            if (existingUser != null) {
                existingUser.setFullName(normalizedFullName);
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
                        existingUser.getFullName(),
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
            user.setFullName(normalizedFullName);
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
                    savedUser.getFullName(),
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
            LoginProtectionService.PreAuthenticationDecision preAuthenticationDecision =
                    loginProtectionService.evaluateAttempt(normalizedEmail, clientIp);
            if (preAuthenticationDecision.throttled()) {
                outcome = "rate_limited_" + preAuthenticationDecision.reason();
                authMetricsService.recordLoginAttempt("rate_limited");
                auditService.recordEvent(resolveThrottleAuditAction(preAuthenticationDecision.reason()), null, request.deviceId(), clientIp);
                consumePasswordWorkFactor(request.password());
                throw new TooManyRequestsException(
                        "Too many login attempts. Please try again later.",
                        preAuthenticationDecision.retryAfterSeconds()
                );
            }

            User user = userRepository.findByEmail(normalizedEmail).orElse(null);
            String passwordHashToCheck = user == null ? dummyPasswordHash : user.getPasswordHash();
            boolean passwordMatches = passwordEncoder.matches(request.password(), passwordHashToCheck);
            if (user == null || !passwordMatches) {
                LoginProtectionService.FailureDecision failureDecision =
                        loginProtectionService.recordFailedAttempt(normalizedEmail, clientIp);
                outcome = failureDecision.suspiciousIpThrottled() ? "suspicious_ip" : "invalid_credentials";
                authMetricsService.recordLoginAttempt("failure");
                authMetricsService.recordLoginFailure(failureDecision.suspiciousIpThrottled() ? "suspicious_ip" : "invalid_credentials");
                auditService.recordEvent(AuditAction.LOGIN_FAILED, user == null ? null : user.getId(), request.deviceId(), clientIp);
                if (failureDecision.accountProtectionActivated()) {
                    auditService.recordEvent(AuditAction.LOGIN_ACCOUNT_PROTECTION_ACTIVATED, user == null ? null : user.getId(), request.deviceId(), clientIp);
                }
                if (failureDecision.accountIpThrottled()) {
                    auditService.recordEvent(AuditAction.LOGIN_ACCOUNT_IP_THROTTLED, user == null ? null : user.getId(), request.deviceId(), clientIp);
                    throw new TooManyRequestsException(
                            "Too many login attempts. Please try again later.",
                            failureDecision.retryAfterSeconds()
                    );
                }
                if (failureDecision.suspiciousIpThrottled()) {
                    auditService.recordEvent(AuditAction.LOGIN_SUSPICIOUS_IP_BLOCKED, user == null ? null : user.getId(), request.deviceId(), clientIp);
                    throw new TooManyRequestsException("Too many login attempts. Please try again later.", failureDecision.retryAfterSeconds());
                }
                throw new UnauthorizedException(GENERIC_LOGIN_FAILURE_MESSAGE);
            }

            if (!user.isEmailVerified()) {
                outcome = "login_denied";
                authMetricsService.recordLoginAttempt("failure");
                authMetricsService.recordLoginFailure("email_verification_required");
                auditService.recordEvent(AuditAction.EMAIL_VERIFICATION_REQUIRED, user.getId(), request.deviceId(), clientIp);
                throw new UnauthorizedException(GENERIC_LOGIN_FAILURE_MESSAGE);
            }

            loginProtectionService.clearSuccess(normalizedEmail, clientIp);
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
            authMetricsService.recordLoginAttempt("success");
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
    public void logout(AuthenticatedUser authenticatedUser, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            if (authenticatedUser == null) {
                outcome = "unauthorized";
                auditService.recordEvent(AuditAction.LOGOUT_FAILED, null, null, clientIp);
                throw new UnauthorizedException("Authentication is required");
            }
            // Logout is session-centric: the access token identifies the session to revoke, making the endpoint
            // idempotent and eliminating dependency on a potentially stale client-held refresh token.
            RefreshTokenService.SessionRevocationResult revocationResult = refreshTokenService.revokeSessionIfPresent(
                    authenticatedUser.getUserId(),
                    authenticatedUser.getSessionId()
            );
            revokeAuthenticatedAccess(authenticatedUser);
            auditService.recordEvent(
                    AuditAction.LOGOUT,
                    authenticatedUser.getUserId(),
                    revocationResult.deviceId(),
                    clientIp
            );
            outcome = "success";
        } finally {
            authMetricsService.recordOperation("logout", outcome, sample);
        }
    }

    @Transactional
    public GlobalLogoutResponse logoutAll(AuthenticatedUser authenticatedUser, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            if (authenticatedUser == null) {
                throw new UnauthorizedException("Authentication is required");
            }
            User user = userRepository.findByIdForUpdate(authenticatedUser.getUserId())
                    .orElseThrow(() -> new UnauthorizedException("Authenticated user not found"));
            Instant now = Instant.now(clock);
            user.setSessionInvalidatedAt(now);
            userRepository.save(user);
            int revokedSessions = refreshTokenService.revokeAllTokensForUser(user.getId());
            revokeAuthenticatedAccess(authenticatedUser);
            auditService.recordEvent(AuditAction.GLOBAL_LOGOUT, user.getId(), null, clientIp);
            outcome = "success";
            return new GlobalLogoutResponse(
                    "All active sessions were revoked",
                    revokedSessions,
                    now
            );
        } catch (UnauthorizedException ex) {
            outcome = "unauthorized";
            auditService.recordEvent(
                    AuditAction.GLOBAL_LOGOUT_FAILED,
                    authenticatedUser == null ? null : authenticatedUser.getUserId(),
                    null,
                    clientIp
            );
            throw ex;
        } finally {
            authMetricsService.recordOperation("logout_all", outcome, sample);
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

    @Transactional
    public AccountUnlockRequestResponse requestAccountUnlock(AccountUnlockRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "accepted";
        String normalizedEmail = normalizeEmail(request.email());
        try {
            User user = userRepository.findByEmail(normalizedEmail).orElse(null);
            if (user == null || !user.isEmailVerified()) {
                log.info(
                        "account_unlock_request_accepted_without_dispatch email={} reason={}",
                        normalizedEmail,
                        user == null ? "user_not_found" : "email_not_verified"
                );
                return genericAccountUnlockResponse(normalizedEmail);
            }

            if (!loginProtectionService.isRecoveryEligible(normalizedEmail, clientIp)) {
                log.info(
                        "account_unlock_request_accepted_without_dispatch email={} reason=no_active_account_recovery_state",
                        normalizedEmail
                );
                return genericAccountUnlockResponse(normalizedEmail);
            }

            auditService.recordEvent(AuditAction.ACCOUNT_UNLOCK_REQUESTED, user.getId(), null, clientIp);
            AccountUnlockOtpService.OtpDispatchResult otpDispatchResult = accountUnlockOtpService.requestOtp(
                    user.getId(),
                    loginProtectionService.hashIpAddress(clientIp)
            );
            if (otpDispatchResult.dispatched()) {
                otpDeliveryService.sendAccountUnlockOtp(user.getEmail(), otpDispatchResult.otp(), otpDispatchResult.expiresInSeconds());
                auditService.recordEvent(AuditAction.ACCOUNT_UNLOCK_OTP_SENT, user.getId(), null, clientIp);
                log.info("account_unlock_otp_dispatch_succeeded userId={} email={}", user.getId(), user.getEmail());
                outcome = "dispatched";
            } else {
                log.info(
                        "account_unlock_request_accepted_without_dispatch email={} reason=cooldown_or_budget_suppressed",
                        normalizedEmail
                );
            }
            return genericAccountUnlockResponse(normalizedEmail);
        } finally {
            authMetricsService.recordOperation("request_account_unlock", outcome, sample);
        }
    }

    @Transactional
    public void unlockAccount(VerifyAccountUnlockRequest request, String clientIp) {
        Timer.Sample sample = authMetricsService.startTimer();
        String outcome = "error";
        try {
            User user = userRepository.findByEmail(normalizeEmail(request.email())).orElse(null);
            if (user == null || !user.isEmailVerified()) {
                outcome = "invalid_request";
                throw new BadRequestException("Invalid account unlock request");
            }

            AccountUnlockOtpService.OtpVerificationResult verificationResult;
            try {
                verificationResult = accountUnlockOtpService.verifyOtp(user.getId(), request.otp());
            } catch (BadRequestException ex) {
                outcome = "invalid_otp";
                auditService.recordEvent(AuditAction.ACCOUNT_UNLOCK_FAILED, user.getId(), null, clientIp);
                throw ex;
            }

            loginProtectionService.clearRecoveryStateByIpHash(user.getEmail(), verificationResult.originatingIpHash());
            if (!verificationResult.originatingIpHash().equals(loginProtectionService.hashIpAddress(clientIp))) {
                loginProtectionService.clearRecoveryState(user.getEmail(), clientIp);
            }
            auditService.recordEvent(AuditAction.ACCOUNT_UNLOCK_SUCCESS, user.getId(), null, clientIp);
            outcome = "success";
        } finally {
            authMetricsService.recordOperation("unlock_account", outcome, sample);
        }
    }

    private void resetFailedLoginState(User user) {
        clearFailedLoginState(user);
        userRepository.save(user);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }

    private String normalizeFullName(String fullName) {
        return fullName.trim().replaceAll("\\s+", " ");
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

    private AccountUnlockRequestResponse genericAccountUnlockResponse(String email) {
        return new AccountUnlockRequestResponse(
                email,
                "If the account exists and unlock recovery is available, an account unlock code will be sent. The code expires in 10 minutes.",
                accountUnlockOtpService.expiresInSeconds(),
                accountUnlockOtpService.resendCooldownSeconds()
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
        if (authenticatedUser == null) {
            return;
        }
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

    private void consumePasswordWorkFactor(String rawPassword) {
        passwordEncoder.matches(rawPassword == null ? "" : rawPassword, dummyPasswordHash);
    }

    private AuditAction resolveThrottleAuditAction(String reason) {
        return switch (reason) {
            case "account_ip" -> AuditAction.LOGIN_ACCOUNT_IP_THROTTLED;
            case "suspicious_ip", "ip_burst", "ip_sustained" -> AuditAction.LOGIN_SUSPICIOUS_IP_BLOCKED;
            default -> AuditAction.LOGIN_IP_THROTTLED;
        };
    }
}
