package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.DeleteAccountRequest;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.exception.BadRequestException;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.repository.UserRepository;
import com.vikas.authsystem.security.AuthenticatedUser;
import com.vikas.authsystem.security.SessionBlacklistService;
import com.vikas.authsystem.security.TokenBlacklistService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccountManagementServiceTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-03-26T10:15:30Z");

    private final UserRepository userRepository = mock(UserRepository.class);
    private final PasswordEncoder passwordEncoder = mock(PasswordEncoder.class);
    private final RefreshTokenService refreshTokenService = mock(RefreshTokenService.class);
    private final LoginProtectionService loginProtectionService = mock(LoginProtectionService.class);
    private final TokenBlacklistService tokenBlacklistService = mock(TokenBlacklistService.class);
    private final SessionBlacklistService sessionBlacklistService = mock(SessionBlacklistService.class);
    private final AuditService auditService = mock(AuditService.class);
    private final AuthMetricsService authMetricsService = mock(AuthMetricsService.class);
    private final UserSecurityStateService userSecurityStateService = mock(UserSecurityStateService.class);

    private AccountManagementService accountManagementService;

    @BeforeEach
    void setUp() {
        accountManagementService = new AccountManagementService(
                userRepository,
                passwordEncoder,
                refreshTokenService,
                loginProtectionService,
                tokenBlacklistService,
                sessionBlacklistService,
                auditService,
                authMetricsService,
                userSecurityStateService,
                Clock.fixed(FIXED_NOW, ZoneOffset.UTC)
        );
    }

    @Test
    void deleteAuthenticatedAccountSoftDeletesUserAndRevokesSessions() {
        User user = baseUser();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(
                user.getId(),
                user.getRole(),
                UUID.randomUUID(),
                "access-jti",
                FIXED_NOW.plusSeconds(300)
        );
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("StrongPass123", user.getPasswordHash())).thenReturn(true);
        when(passwordEncoder.encode(anyString())).thenReturn("deleted-password-hash");

        accountManagementService.deleteAuthenticatedAccount(
                authenticatedUser,
                new DeleteAccountRequest("StrongPass123", user.getEmail(), "web-browser"),
                "127.0.0.1"
        );

        verify(refreshTokenService).revokeAllTokensForUser(user.getId());
        verify(tokenBlacklistService).blacklist("access-jti", Duration.ofSeconds(300));
        verify(sessionBlacklistService).blacklist(authenticatedUser.getSessionId(), Duration.ofSeconds(300));
        verify(loginProtectionService).clearSuccess("user@example.com", "127.0.0.1");
        verify(userRepository).save(user);
        assertEquals(FIXED_NOW, user.getDeletedAt());
        assertEquals(FIXED_NOW, user.getPasswordChangedAt());
        assertEquals(FIXED_NOW, user.getSessionInvalidatedAt());
        assertEquals("deleted-password-hash", user.getPasswordHash());
        assertEquals("deleted+" + user.getId() + "@deleted.auth.local", user.getEmail());
        assertNotNull(user.getDeletedEmailHash());
        ArgumentCaptor<String> deletedPasswordCaptor = ArgumentCaptor.forClass(String.class);
        verify(passwordEncoder).encode(deletedPasswordCaptor.capture());
        assertTrue(deletedPasswordCaptor.getValue().getBytes(StandardCharsets.UTF_8).length <= 72);
        verify(authMetricsService).recordOperation("delete_account", "success", null);
    }

    @Test
    void deleteAuthenticatedAccountRejectsInvalidPassword() {
        User user = baseUser();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(
                user.getId(),
                user.getRole(),
                UUID.randomUUID(),
                "access-jti",
                FIXED_NOW.plusSeconds(300)
        );
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("wrong-password", user.getPasswordHash())).thenReturn(false);

        assertThrows(
                UnauthorizedException.class,
                () -> accountManagementService.deleteAuthenticatedAccount(
                        authenticatedUser,
                        new DeleteAccountRequest("wrong-password", user.getEmail(), "web-browser"),
                        "127.0.0.1"
                )
        );

        verify(userRepository, never()).save(user);
        verify(authMetricsService).recordOperation("delete_account", "invalid_current_password", null);
    }

    @Test
    void deleteAuthenticatedAccountRejectsWrongConfirmationEmail() {
        User user = baseUser();
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(
                user.getId(),
                user.getRole(),
                UUID.randomUUID(),
                "access-jti",
                FIXED_NOW.plusSeconds(300)
        );
        when(userRepository.findByIdForUpdate(user.getId())).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("StrongPass123", user.getPasswordHash())).thenReturn(true);

        assertThrows(
                BadRequestException.class,
                () -> accountManagementService.deleteAuthenticatedAccount(
                        authenticatedUser,
                        new DeleteAccountRequest("StrongPass123", "other@example.com", "web-browser"),
                        "127.0.0.1"
                )
        );

        verify(userRepository, never()).save(user);
        verify(authMetricsService).recordOperation("delete_account", "invalid_confirmation", null);
    }

    private User baseUser() {
        User user = new User();
        user.setId(UUID.randomUUID());
        user.setEmail("user@example.com");
        user.setPasswordHash("encoded-password");
        user.setRole(UserRole.USER);
        return user;
    }
}
