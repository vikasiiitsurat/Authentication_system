package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.AccountUnlockRequest;
import com.vikas.authsystem.dto.AccountUnlockRequestResponse;
import com.vikas.authsystem.dto.EmailVerificationStatusResponse;
import com.vikas.authsystem.dto.ForgotPasswordRequest;
import com.vikas.authsystem.dto.GlobalLogoutResponse;
import com.vikas.authsystem.dto.LoginRequest;
import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.dto.PasswordChangeRequest;
import com.vikas.authsystem.dto.PasswordResetRequestResponse;
import com.vikas.authsystem.dto.RegisterRequest;
import com.vikas.authsystem.dto.RegisterResponse;
import com.vikas.authsystem.dto.ResendVerificationOtpRequest;
import com.vikas.authsystem.dto.ResetPasswordRequest;
import com.vikas.authsystem.dto.VerifyAccountUnlockRequest;
import com.vikas.authsystem.dto.VerifyEmailOtpRequest;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.exception.BadRequestException;
import com.vikas.authsystem.exception.TooManyRequestsException;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.repository.UserRepository;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.security.JwtUtil;
import com.vikas.authsystem.security.SessionBlacklistService;
import com.vikas.authsystem.security.TokenBlacklistService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-03-18T10:15:30Z");

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final JwtUtil jwtUtil = mock(JwtUtil.class);
    private final LoginProtectionService loginProtectionService = mock(LoginProtectionService.class);
    private final RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);
    private final TemporaryCacheService temporaryCacheService = mock(TemporaryCacheService.class);
    private final TokenBlacklistService tokenBlacklistService = mock(TokenBlacklistService.class);
    private final SessionBlacklistService sessionBlacklistService = mock(SessionBlacklistService.class);
    private final EmailVerificationOtpService emailVerificationOtpService = mock(EmailVerificationOtpService.class);
    private final PasswordResetOtpService passwordResetOtpService = mock(PasswordResetOtpService.class);
    private final AccountUnlockOtpService accountUnlockOtpService = mock(AccountUnlockOtpService.class);
    private final OtpDeliveryService otpDeliveryService = mock(OtpDeliveryService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthMetricsService authMetricsService = mock(AuthMetricsService.class);

    private AuthService authService;

    @BeforeEach
    void setUp() {
        Clock clock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        when(passwordEncoder.encode(anyString())).thenReturn("dummy-encoded");
        authService = new AuthService(
                userRepository,
                passwordEncoder,
                jwtUtil,
                loginProtectionService,
                refreshTokenService,
                temporaryCacheService,
                tokenBlacklistService,
                sessionBlacklistService,
                emailVerificationOtpService,
                passwordResetOtpService,
                accountUnlockOtpService,
                otpDeliveryService,
                auditService,
                authMetricsService,
                clock
        );
        when(loginProtectionService.evaluateAttempt(anyString(), anyString()))
                .thenReturn(new LoginProtectionService.PreAuthenticationDecision(false, 0, "allowed"));
        when(loginProtectionService.recordFailedAttempt(anyString(), anyString()))
                .thenReturn(new LoginProtectionService.FailureDecision(false, false, false, 0));
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            if (user.getId() == null) {
                user.setId(UUID.randomUUID());
            }
            return user;
        });
    }

    @Test
    void loginSucceedsAndClearsRedisProtectionState() {
        User user = baseUser();
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("correct-password", user.getPasswordHash())).thenReturn(true);
        UUID sessionId = UUID.randomUUID();
        when(jwtUtil.generateAccessToken(user.getId(), user.getRole().name(), sessionId)).thenReturn("access-token");
        when(jwtUtil.accessTokenTtlSeconds()).thenReturn(900L);
        when(refreshTokenService.generateRawRefreshToken()).thenReturn("refresh-token");
        when(refreshTokenService.storeRefreshToken(user, "refresh-token", "device-1", "127.0.0.1"))
                .thenReturn(new RefreshTokenService.StoredSession(
                        sessionId,
                        "device-1",
                        FIXED_NOW,
                        FIXED_NOW,
                        FIXED_NOW.plusSeconds(3600),
                        "127.0.0.1"
                ));

        LoginResponse response = authService.login(
                new LoginRequest(user.getEmail(), "correct-password", "device-1"),
                "127.0.0.1"
        );

        assertEquals("access-token", response.accessToken());
        assertEquals("refresh-token", response.refreshToken());
        verify(loginProtectionService).clearSuccess(user.getEmail(), "127.0.0.1");
        verify(authMetricsService).recordOperation("login", "success", null);
    }

    @Test
    void loginReturnsGenericUnauthorizedForUnknownUser() {
        when(userRepository.findByEmail("missing@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.matches("bad-password", "dummy-encoded")).thenReturn(false);

        UnauthorizedException exception = assertThrows(
                UnauthorizedException.class,
                () -> authService.login(new LoginRequest("missing@example.com", "bad-password", "device-1"), "127.0.0.1")
        );

        assertEquals("Invalid email or password", exception.getMessage());
        verify(loginProtectionService).recordFailedAttempt("missing@example.com", "127.0.0.1");
        verify(refreshTokenService, never()).generateRawRefreshToken();
    }

    @Test
    void loginReturnsGenericUnauthorizedForUnverifiedAccount() {
        User user = baseUser();
        user.setEmailVerified(false);
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("correct-password", user.getPasswordHash())).thenReturn(true);

        UnauthorizedException exception = assertThrows(
                UnauthorizedException.class,
                () -> authService.login(new LoginRequest(user.getEmail(), "correct-password", "device-1"), "127.0.0.1")
        );

        assertEquals("Invalid email or password", exception.getMessage());
        verify(refreshTokenService, never()).generateRawRefreshToken();
        verify(authMetricsService).recordOperation("login", "login_denied", null);
    }

    @Test
    void loginReturnsTooManyRequestsWhenSourceIsPreThrottled() {
        when(loginProtectionService.evaluateAttempt("user@example.com", "127.0.0.1"))
                .thenReturn(new LoginProtectionService.PreAuthenticationDecision(true, 60, "ip_burst"));

        TooManyRequestsException exception = assertThrows(
                TooManyRequestsException.class,
                () -> authService.login(new LoginRequest("user@example.com", "bad-password", "device-1"), "127.0.0.1")
        );

        assertEquals(60L, exception.getRetryAfterSeconds());
        verify(userRepository, never()).findByEmail(anyString());
    }

    @Test
    void loginReturnsTooManyRequestsWhenAccountIpThrottleTripsAfterFailure() {
        User user = baseUser();
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("bad-password", user.getPasswordHash())).thenReturn(false);
        when(loginProtectionService.recordFailedAttempt(user.getEmail(), "127.0.0.1"))
                .thenReturn(new LoginProtectionService.FailureDecision(true, false, false, 300));

        TooManyRequestsException exception = assertThrows(
                TooManyRequestsException.class,
                () -> authService.login(new LoginRequest(user.getEmail(), "bad-password", "device-1"), "127.0.0.1")
        );

        assertEquals(300L, exception.getRetryAfterSeconds());
        verify(authMetricsService).recordOperation("login", "invalid_credentials", null);
    }

    @Test
    void logoutBlacklistsAccessTokenAndRevokesOwnedRefreshToken() {
        User user = baseUser();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(
                user.getId(),
                user.getRole(),
                UUID.randomUUID(),
                "access-jti",
                FIXED_NOW.plusSeconds(300)
        );
        when(refreshTokenService.revokeSessionIfPresent(user.getId(), authenticatedUser.getSessionId()))
                .thenReturn(new RefreshTokenService.SessionRevocationResult(
                        authenticatedUser.getSessionId(),
                        "device-1",
                        1
                ));

        authService.logout(authenticatedUser, "127.0.0.1");

        verify(tokenBlacklistService).blacklist("access-jti", Duration.ofSeconds(300));
        verify(sessionBlacklistService).blacklist(authenticatedUser.getSessionId(), Duration.ofSeconds(300));
        verify(refreshTokenService).revokeSessionIfPresent(user.getId(), authenticatedUser.getSessionId());
        verify(authMetricsService).recordOperation("logout", "success", null);
    }

    @Test
    void logoutRemainsSuccessfulWhenRefreshTokenPayloadIsMissing() {
        User user = baseUser();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(
                user.getId(),
                user.getRole(),
                UUID.randomUUID(),
                "access-jti",
                FIXED_NOW.plusSeconds(300)
        );
        when(refreshTokenService.revokeSessionIfPresent(user.getId(), authenticatedUser.getSessionId()))
                .thenReturn(new RefreshTokenService.SessionRevocationResult(
                        authenticatedUser.getSessionId(),
                        null,
                        0
                ));

        authService.logout(authenticatedUser, "127.0.0.1");

        verify(refreshTokenService).revokeSessionIfPresent(user.getId(), authenticatedUser.getSessionId());
        verify(tokenBlacklistService).blacklist("access-jti", Duration.ofSeconds(300));
        verify(sessionBlacklistService).blacklist(authenticatedUser.getSessionId(), Duration.ofSeconds(300));
        verify(authMetricsService).recordOperation("logout", "success", null);
    }

    @Test
    void logoutAllRevokesEverySessionAndInvalidatesAllAccessTokens() {
        User user = baseUser();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(
                user.getId(),
                user.getRole(),
                UUID.randomUUID(),
                "access-jti",
                FIXED_NOW.plusSeconds(300)
        );
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));
        when(refreshTokenService.revokeAllTokensForUser(user.getId())).thenReturn(3);

        GlobalLogoutResponse response = authService.logoutAll(authenticatedUser, "127.0.0.1");

        assertEquals("All active sessions were revoked", response.message());
        assertEquals(3, response.revokedSessions());
        assertEquals(FIXED_NOW, response.accessTokensInvalidatedAt());
        assertEquals(FIXED_NOW, user.getSessionInvalidatedAt());
        verify(userRepository).save(user);
        verify(refreshTokenService).revokeAllTokensForUser(user.getId());
        verify(tokenBlacklistService).blacklist("access-jti", Duration.ofSeconds(300));
        verify(sessionBlacklistService).blacklist(authenticatedUser.getSessionId(), Duration.ofSeconds(300));
        verify(authMetricsService).recordOperation("logout_all", "success", null);
    }

    @Test
    void changePasswordRevokesAllSessionsAndBlacklistsCurrentAccessToken() {
        User user = baseUser();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(
                user.getId(),
                user.getRole(),
                UUID.randomUUID(),
                "access-jti",
                FIXED_NOW.plusSeconds(300)
        );
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("current-password", user.getPasswordHash())).thenReturn(true);
        when(passwordEncoder.encode("new-password-123")).thenReturn("new-password-hash");

        authService.changePassword(
                authenticatedUser,
                new PasswordChangeRequest("current-password", "new-password-123", "device-1"),
                "127.0.0.1"
        );

        assertEquals("new-password-hash", user.getPasswordHash());
        assertEquals(FIXED_NOW, user.getPasswordChangedAt());
        verify(refreshTokenService).revokeAllTokensForUser(user.getId());
        verify(tokenBlacklistService).blacklist("access-jti", Duration.ofSeconds(300));
        verify(sessionBlacklistService).blacklist(authenticatedUser.getSessionId(), Duration.ofSeconds(300));
        verify(authMetricsService).recordOperation("change_password", "success", null);
    }

    @Test
    void requestPasswordResetDispatchesOtpForVerifiedAccounts() {
        User user = baseUser();
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordResetOtpService.requestOtp(user.getId()))
                .thenReturn(new PasswordResetOtpService.OtpDispatchResult(true, "654321", 600, 60));
        when(passwordResetOtpService.expiresInSeconds()).thenReturn(600L);
        when(passwordResetOtpService.resendCooldownSeconds()).thenReturn(60L);

        PasswordResetRequestResponse response = authService.requestPasswordReset(
                new ForgotPasswordRequest(user.getEmail()),
                "127.0.0.1"
        );

        assertEquals(
                "If the account exists and is eligible, a password reset code will be sent. The code expires in 10 minutes.",
                response.message()
        );
        assertEquals(600L, response.expiresInSeconds());
        assertEquals(60L, response.resendAvailableInSeconds());
        verify(otpDeliveryService).sendPasswordResetOtp(user.getEmail(), "654321", 600);
        verify(authMetricsService).recordOperation("request_password_reset", "dispatched", null);
    }

    @Test
    void requestPasswordResetDoesNotExposeUnknownAccounts() {
        when(userRepository.findByEmailForUpdate("missing@example.com")).thenReturn(Optional.empty());
        when(passwordResetOtpService.expiresInSeconds()).thenReturn(600L);
        when(passwordResetOtpService.resendCooldownSeconds()).thenReturn(60L);

        PasswordResetRequestResponse response = authService.requestPasswordReset(
                new ForgotPasswordRequest("missing@example.com"),
                "127.0.0.1"
        );

        assertEquals("missing@example.com", response.email());
        verify(passwordResetOtpService, never()).requestOtp(any(UUID.class));
        verify(otpDeliveryService, never()).sendPasswordResetOtp(anyString(), anyString(), anyLong());
        verify(authMetricsService).recordOperation("request_password_reset", "accepted", null);
    }

    @Test
    void requestAccountUnlockDispatchesOtpForProtectedVerifiedAccounts() {
        User user = baseUser();
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(loginProtectionService.isRecoveryEligible(user.getEmail(), "127.0.0.1")).thenReturn(true);
        when(loginProtectionService.hashIpAddress("127.0.0.1")).thenReturn("origin-ip-hash");
        when(accountUnlockOtpService.requestOtp(user.getId(), "origin-ip-hash"))
                .thenReturn(new AccountUnlockOtpService.OtpDispatchResult(true, "918273", 600, 60));
        when(accountUnlockOtpService.expiresInSeconds()).thenReturn(600L);
        when(accountUnlockOtpService.resendCooldownSeconds()).thenReturn(60L);

        AccountUnlockRequestResponse response = authService.requestAccountUnlock(
                new AccountUnlockRequest(user.getEmail()),
                "127.0.0.1"
        );

        assertEquals(
                "If the account exists and unlock recovery is available, an account unlock code will be sent. The code expires in 10 minutes.",
                response.message()
        );
        verify(otpDeliveryService).sendAccountUnlockOtp(user.getEmail(), "918273", 600);
        verify(authMetricsService).recordOperation("request_account_unlock", "dispatched", null);
    }

    @Test
    void requestAccountUnlockDoesNotExposeMissingRecoveryState() {
        User user = baseUser();
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(loginProtectionService.isRecoveryEligible(user.getEmail(), "127.0.0.1")).thenReturn(false);
        when(accountUnlockOtpService.expiresInSeconds()).thenReturn(600L);
        when(accountUnlockOtpService.resendCooldownSeconds()).thenReturn(60L);

        AccountUnlockRequestResponse response = authService.requestAccountUnlock(
                new AccountUnlockRequest(user.getEmail()),
                "127.0.0.1"
        );

        assertEquals(user.getEmail(), response.email());
        verify(accountUnlockOtpService, never()).requestOtp(any(UUID.class), anyString());
        verify(otpDeliveryService, never()).sendAccountUnlockOtp(anyString(), anyString(), anyLong());
        verify(authMetricsService).recordOperation("request_account_unlock", "accepted", null);
    }

    @Test
    void unlockAccountClearsRecoveryStateAfterOtpVerification() {
        User user = baseUser();
        when(userRepository.findByEmail(user.getEmail())).thenReturn(Optional.of(user));
        when(accountUnlockOtpService.verifyOtp(user.getId(), "123456"))
                .thenReturn(new AccountUnlockOtpService.OtpVerificationResult(true, 540, "origin-ip-hash"));
        when(loginProtectionService.hashIpAddress("127.0.0.1")).thenReturn("origin-ip-hash");

        authService.unlockAccount(
                new VerifyAccountUnlockRequest(user.getEmail(), "123456"),
                "127.0.0.1"
        );

        verify(loginProtectionService).clearRecoveryStateByIpHash(user.getEmail(), "origin-ip-hash");
        verify(authMetricsService).recordOperation("unlock_account", "success", null);
    }

    @Test
    void resetPasswordRotatesPasswordAndRevokesAllSessions() {
        User user = baseUser();
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordResetOtpService.verifyOtp(user.getId(), "123456"))
                .thenReturn(new PasswordResetOtpService.OtpVerificationResult(true, 540));
        when(passwordEncoder.matches("new-password-123", user.getPasswordHash())).thenReturn(false);
        when(passwordEncoder.encode("new-password-123")).thenReturn("new-password-hash");

        authService.resetPassword(
                new ResetPasswordRequest(user.getEmail(), "123456", "new-password-123", "device-1"),
                "127.0.0.1"
        );

        assertEquals("new-password-hash", user.getPasswordHash());
        assertEquals(FIXED_NOW, user.getPasswordChangedAt());
        verify(refreshTokenService).revokeAllTokensForUser(user.getId());
        verify(authMetricsService).recordOperation("reset_password", "success", null);
    }

    @Test
    void resetPasswordRejectsPasswordReuse() {
        User user = baseUser();
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordResetOtpService.verifyOtp(user.getId(), "123456"))
                .thenReturn(new PasswordResetOtpService.OtpVerificationResult(true, 540));
        when(passwordEncoder.matches("encoded-password", user.getPasswordHash())).thenReturn(true);

        BadRequestException exception = assertThrows(
                BadRequestException.class,
                () -> authService.resetPassword(
                        new ResetPasswordRequest(user.getEmail(), "123456", "encoded-password", "device-1"),
                        "127.0.0.1"
                )
        );

        assertEquals("New password must be different from the current password", exception.getMessage());
        verify(refreshTokenService, never()).revokeAllTokensForUser(any(UUID.class));
        verify(authMetricsService).recordOperation("reset_password", "password_reuse", null);
    }

    @Test
    void registerCreatesUnverifiedUserAndDispatchesOtp() {
        RegisterRequest request = new RegisterRequest("new@example.com", "super-secret");
        EmailVerificationOtpService.OtpIssueResult otpIssueResult =
                new EmailVerificationOtpService.OtpIssueResult("482913", 180, 30);
        when(userRepository.findByEmail("new@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("super-secret")).thenReturn("encoded-password");
        when(emailVerificationOtpService.issueOtp(any(UUID.class))).thenReturn(otpIssueResult);

        RegisterResponse response = authService.register(request, "127.0.0.1");

        assertTrue(response.emailVerificationRequired());
        assertEquals(180, response.otpExpiresInSeconds());
        assertEquals(30, response.resendAvailableInSeconds());
        verify(otpDeliveryService).sendVerificationOtp("new@example.com", "482913", 180);
        verify(authMetricsService).recordOperation("register", "success", null);
    }

    @Test
    void registerUpdatesPasswordWhenUnverifiedUserRegistersAgain() {
        User existingUser = baseUser();
        existingUser.setEmailVerified(false);
        existingUser.setPasswordHash("old-hash");
        RegisterRequest request = new RegisterRequest(existingUser.getEmail(), "new-secret-123");
        EmailVerificationOtpService.OtpIssueResult otpIssueResult =
                new EmailVerificationOtpService.OtpIssueResult("222333", 180, 30);
        when(userRepository.findByEmail(existingUser.getEmail())).thenReturn(Optional.of(existingUser));
        when(passwordEncoder.encode("new-secret-123")).thenReturn("new-hash");
        when(emailVerificationOtpService.reissueOtp(existingUser.getId())).thenReturn(otpIssueResult);

        RegisterResponse response = authService.register(request, "127.0.0.1");

        assertEquals(existingUser.getId(), response.userId());
        assertEquals("new-hash", existingUser.getPasswordHash());
        verify(userRepository).save(existingUser);
        verify(otpDeliveryService).sendVerificationOtp(existingUser.getEmail(), "222333", 180);
        verify(authMetricsService).recordOperation("register", "pending_verification", null);
    }

    @Test
    void registerCreatesFreshAccountWhenPreviousAccountWasDeleted() {
        RegisterRequest request = new RegisterRequest("user@example.com", "super-secret");
        EmailVerificationOtpService.OtpIssueResult otpIssueResult =
                new EmailVerificationOtpService.OtpIssueResult("482913", 180, 30);
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.encode("super-secret")).thenReturn("encoded-password");
        when(emailVerificationOtpService.issueOtp(any(UUID.class))).thenReturn(otpIssueResult);

        RegisterResponse response = authService.register(request, "127.0.0.1");

        assertEquals("user@example.com", response.email());
        assertTrue(response.emailVerificationRequired());
        verify(otpDeliveryService).sendVerificationOtp("user@example.com", "482913", 180);
        verify(authMetricsService).recordOperation("register", "success", null);
    }

    @Test
    void loginReturnsGenericUnauthorizedForDeletedAccountEmail() {
        when(userRepository.findByEmail("user@example.com")).thenReturn(Optional.empty());
        when(passwordEncoder.matches("correct-password", "dummy-encoded")).thenReturn(false);

        UnauthorizedException exception = assertThrows(
                UnauthorizedException.class,
                () -> authService.login(new LoginRequest("user@example.com", "correct-password", "device-1"), "127.0.0.1")
        );

        assertEquals("Invalid email or password", exception.getMessage());
        verify(refreshTokenService, never()).generateRawRefreshToken();
        verify(authMetricsService).recordOperation("login", "invalid_credentials", null);
    }

    @Test
    void verifyEmailOtpMarksUserAsVerified() {
        User user = baseUser();
        user.setEmailVerified(false);
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(emailVerificationOtpService.verifyOtp(user.getId(), "123456"))
                .thenReturn(new EmailVerificationOtpService.OtpVerificationResult(true, 120));

        EmailVerificationStatusResponse response = authService.verifyEmailOtp(
                new VerifyEmailOtpRequest(user.getEmail(), "123456", "device-1"),
                "127.0.0.1"
        );

        assertTrue(response.verified());
        assertTrue(user.isEmailVerified());
        verify(userRepository).save(user);
        verify(authMetricsService).recordOperation("verify_email_otp", "success", null);
    }

    @Test
    void resendVerificationOtpDispatchesFreshOtp() {
        User user = baseUser();
        user.setEmailVerified(false);
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(emailVerificationOtpService.reissueOtp(user.getId()))
                .thenReturn(new EmailVerificationOtpService.OtpIssueResult("111222", 180, 30));

        EmailVerificationStatusResponse response = authService.resendVerificationOtp(
                new ResendVerificationOtpRequest(user.getEmail()),
                "127.0.0.1"
        );

        assertEquals("A verification OTP has been sent. It expires in 3 minutes.", response.message());
        assertEquals(180, response.expiresInSeconds());
        assertEquals(30, response.resendAvailableInSeconds());
        verify(otpDeliveryService).sendVerificationOtp(user.getEmail(), "111222", 180);
        verify(authMetricsService).recordOperation("resend_verification_otp", "success", null);
    }

    @Test
    void resendVerificationOtpDoesNotExposeMissingAccounts() {
        when(userRepository.findByEmailForUpdate("missing@example.com")).thenReturn(Optional.empty());

        EmailVerificationStatusResponse response = authService.resendVerificationOtp(
                new ResendVerificationOtpRequest("missing@example.com"),
                "127.0.0.1"
        );

        assertEquals("missing@example.com", response.email());
        assertEquals(
                "If the account exists and is pending verification, an OTP will be sent if resend rules allow it.",
                response.message()
        );
        assertEquals(0, response.expiresInSeconds());
        assertEquals(0, response.resendAvailableInSeconds());
        verify(otpDeliveryService, never()).sendVerificationOtp(anyString(), anyString(), anyLong());
        verify(authMetricsService).recordOperation("resend_verification_otp", "accepted", null);
    }

    @Test
    void resendVerificationOtpDoesNotExposeVerifiedAccounts() {
        User user = baseUser();
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));

        EmailVerificationStatusResponse response = authService.resendVerificationOtp(
                new ResendVerificationOtpRequest(user.getEmail()),
                "127.0.0.1"
        );

        assertEquals(
                "If the account exists and is pending verification, an OTP will be sent if resend rules allow it.",
                response.message()
        );
        assertEquals(0, response.expiresInSeconds());
        assertEquals(0, response.resendAvailableInSeconds());
        verify(emailVerificationOtpService, never()).reissueOtp(any(UUID.class));
        verify(authMetricsService).recordOperation("resend_verification_otp", "accepted", null);
    }

    private User baseUser() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setPasswordHash("encoded-password");
        user.setRole(UserRole.USER);
        user.setEmailVerified(true);
        return user;
    }
}
