package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.TwoFactorStatusResponse;
import com.vikas.authsystem.dto.TwoFactorUpdateRequest;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.repository.UserRepository;
import com.vikas.authsystem.security.AuthenticatedUser;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class TwoFactorManagementServiceTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-04-01T11:15:30Z");

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final LoginTwoFactorChallengeService loginTwoFactorChallengeService = mock(LoginTwoFactorChallengeService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthMetricsService authMetricsService = mock(AuthMetricsService.class);

    private TwoFactorManagementService twoFactorManagementService;

    @BeforeEach
    void setUp() {
        twoFactorManagementService = new TwoFactorManagementService(
                userRepository,
                passwordEncoder,
                loginTwoFactorChallengeService,
                auditService,
                authMetricsService,
                Clock.fixed(FIXED_NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void enableTurnsOnTwoFactorForAuthenticatedUser() {
        User user = baseUser();
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("StrongPass@123", user.getPasswordHash())).thenReturn(true);

        TwoFactorStatusResponse response = twoFactorManagementService.enable(
                authenticatedUser(user),
                new TwoFactorUpdateRequest("StrongPass@123", "web-browser"),
                "127.0.0.1"
        );

        assertEquals(true, response.enabled());
        assertEquals(FIXED_NOW, response.enabledAt());
        assertEquals(FIXED_NOW, user.getTwoFactorEnabledAt());
        verify(userRepository).save(user);
        verify(authMetricsService).recordOperation("enable_two_factor", "success", null);
    }

    @Test
    void disableTurnsOffTwoFactorAndClearsChallenge() {
        User user = baseUser();
        user.setTwoFactorEnabled(true);
        user.setTwoFactorEnabledAt(FIXED_NOW.minusSeconds(120));
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("StrongPass@123", user.getPasswordHash())).thenReturn(true);

        TwoFactorStatusResponse response = twoFactorManagementService.disable(
                authenticatedUser(user),
                new TwoFactorUpdateRequest("StrongPass@123", "web-browser"),
                "127.0.0.1"
        );

        assertEquals(false, response.enabled());
        assertNull(response.enabledAt());
        assertEquals(false, user.isTwoFactorEnabled());
        verify(loginTwoFactorChallengeService).invalidateChallenge(user.getId());
        verify(authMetricsService).recordOperation("disable_two_factor", "success", null);
    }

    @Test
    void enableRejectsInvalidCurrentPassword() {
        User user = baseUser();
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", user.getPasswordHash())).thenReturn(false);

        assertThrows(
                UnauthorizedException.class,
                () -> twoFactorManagementService.enable(
                        authenticatedUser(user),
                        new TwoFactorUpdateRequest("wrong-password", "web-browser"),
                        "127.0.0.1"
                )
        );

        verify(userRepository, never()).save(user);
        verify(authMetricsService).recordOperation("enable_two_factor", "invalid_current_password", null);
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

    private AuthenticatedUser authenticatedUser(User user) {
        return new AuthenticatedUser(user.getId(), user.getRole(), UUID.randomUUID(), "access-jti", FIXED_NOW.plusSeconds(300));
    }
}
