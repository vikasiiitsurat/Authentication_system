package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.LoginRequest;
import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.dto.LogoutRequest;
import com.vikas.authsystem.dto.ForgotPasswordRequest;
import com.vikas.authsystem.dto.PasswordChangeRequest;
import com.vikas.authsystem.dto.PasswordResetRequestResponse;
import com.vikas.authsystem.dto.RegisterRequest;
import com.vikas.authsystem.dto.RegisterResponse;
import com.vikas.authsystem.dto.ResendVerificationOtpRequest;
import com.vikas.authsystem.dto.ResetPasswordRequest;
import com.vikas.authsystem.dto.VerifyEmailOtpRequest;
import com.vikas.authsystem.dto.EmailVerificationStatusResponse;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.exception.AccountLockedException;
import com.vikas.authsystem.exception.BadRequestException;
import com.vikas.authsystem.exception.ForbiddenException;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.repository.UserRepository;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.security.JwtUtil;
import com.vikas.authsystem.security.SessionBlacklistService;
import com.vikas.authsystem.security.TokenBlacklistService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthServiceTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-03-18T10:15:30Z");

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final JwtUtil jwtUtil = mock(JwtUtil.class);
    private final RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);
    private final TemporaryCacheService temporaryCacheService = mock(TemporaryCacheService.class);
    private final TokenBlacklistService tokenBlacklistService = mock(TokenBlacklistService.class);
    private final SessionBlacklistService sessionBlacklistService = mock(SessionBlacklistService.class);
    private final EmailVerificationOtpService emailVerificationOtpService = mock(EmailVerificationOtpService.class);
    private final PasswordResetOtpService passwordResetOtpService = mock(PasswordResetOtpService.class);
    private final OtpDeliveryService otpDeliveryService = mock(OtpDeliveryService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthMetricsService authMetricsService = mock(AuthMetricsService.class);

    private AuthService authService;

    @BeforeEach
    void setUp() {
        Clock clock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        authService = new AuthService(
                userRepository,
                passwordEncoder,
                jwtUtil,
                refreshTokenService,
                temporaryCacheService,
                tokenBlacklistService,
                sessionBlacklistService,
                emailVerificationOtpService,
                passwordResetOtpService,
                otpDeliveryService,
                auditService,
                authMetricsService,
                clock
        );
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
            User user = invocation.getArgument(0);
            if (user.getId() == null) {
                user.setId(UUID.randomUUID());
            }
            return user;
        });
    }

    @Test
    void loginRejectsRequestWhileLockIsStillActive() {
        User user = baseUser();
        user.setLockUntil(FIXED_NOW.plusSeconds(120));
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));

        AccountLockedException exception = assertThrows(
                AccountLockedException.class,
                () -> authService.login(new LoginRequest(user.getEmail(), "bad-password", "device-1"), "127.0.0.1")
        );

        assertEquals("Account is locked. Try again in 2 minutes.", exception.getMessage());
        assertEquals(120, exception.getRetryAfterSeconds());
        verify(passwordEncoder, never()).matches(anyString(), anyString());
        verify(userRepository, never()).save(any(User.class));
        verify(authMetricsService).recordOperation("login", "account_locked", null);
    }

    @Test
    void loginClearsExpiredLockAndResetsFailureStateAfterSuccessfulAuthentication() {
        User user = baseUser();
        user.setFailedAttempts(7);
        user.setLastFailedAttempt(FIXED_NOW.minusSeconds(900));
        user.setLockUntil(FIXED_NOW.minusSeconds(1));
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
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
        assertEquals(0, user.getFailedAttempts());
        assertNull(user.getLockUntil());
        assertNull(user.getLastFailedAttempt());
        verify(userRepository, times(2)).save(user);
        verify(refreshTokenService).storeRefreshToken(user, "refresh-token", "device-1", "127.0.0.1");
        verify(authMetricsService).recordOperation("login", "success", null);
    }

    @Test
    void loginRejectsUnverifiedUsersEvenWithCorrectPassword() {
        User user = baseUser();
        user.setEmailVerified(false);
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("correct-password", user.getPasswordHash())).thenReturn(true);

        ForbiddenException exception = assertThrows(
                ForbiddenException.class,
                () -> authService.login(new LoginRequest(user.getEmail(), "correct-password", "device-1"), "127.0.0.1")
        );

        assertEquals("Email verification is required before logging in", exception.getMessage());
        verify(refreshTokenService, never()).generateRawRefreshToken();
        verify(authMetricsService).recordOperation("login", "email_verification_required", null);
    }

    @ParameterizedTest
    @MethodSource("lockEscalationCases")
    void failedLoginAppliesEscalatingLockDurations(
            int existingFailedAttempts,
            long expectedLockSeconds,
            String expectedRetryWindow
    ) {
        User user = baseUser();
        user.setFailedAttempts(existingFailedAttempts);
        when(userRepository.findByEmailForUpdate(user.getEmail())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", user.getPasswordHash())).thenReturn(false);

        AccountLockedException exception = assertThrows(
                AccountLockedException.class,
                () -> authService.login(new LoginRequest(user.getEmail(), "wrong-password", "device-1"), "127.0.0.1")
        );

        assertEquals("Account is locked. Try again in " + expectedRetryWindow + ".", exception.getMessage());
        assertEquals(expectedLockSeconds, exception.getRetryAfterSeconds());
        assertEquals(existingFailedAttempts + 1, user.getFailedAttempts());
        assertEquals(FIXED_NOW, user.getLastFailedAttempt());
        assertEquals(FIXED_NOW.plusSeconds(expectedLockSeconds), user.getLockUntil());

        ArgumentCaptor<User> savedUser = ArgumentCaptor.forClass(User.class);
        verify(userRepository).save(savedUser.capture());
        assertEquals(user.getLockUntil(), savedUser.getValue().getLockUntil());
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
        com.vikas.authsystem.entity.RefreshToken refreshToken = new com.vikas.authsystem.entity.RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setDeviceId("device-1");
        when(refreshTokenService.revokeRefreshToken("refresh-token", user.getId())).thenReturn(refreshToken);

        authService.logout(new LogoutRequest("refresh-token"), authenticatedUser, "127.0.0.1");

        verify(tokenBlacklistService).blacklist("access-jti", Duration.ofSeconds(300));
        verify(refreshTokenService).revokeRefreshToken("refresh-token", user.getId());
        verify(authMetricsService).recordOperation("logout", "success", null);
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

    private static Stream<Arguments> lockEscalationCases() {
        return Stream.of(
                Arguments.of(4, 5 * 60L, "5 minutes"),
                Arguments.of(5, 10 * 60L, "10 minutes"),
                Arguments.of(6, 40 * 60L, "40 minutes"),
                Arguments.of(7, 24 * 60 * 60L, "24 hours"),
                Arguments.of(8, 24 * 60 * 60L, "24 hours")
        );
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
