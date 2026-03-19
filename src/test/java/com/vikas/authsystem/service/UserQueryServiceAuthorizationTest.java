package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.UserProfileResponse;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.repository.UserRepository;
import com.vikas.authsystem.security.AuthenticatedUser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@SpringJUnitConfig(UserQueryServiceAuthorizationTest.TestConfig.class)
class UserQueryServiceAuthorizationTest {

    @Configuration
    @EnableMethodSecurity
    static class TestConfig {

        @Bean
        UserRepository userRepository() {
            return mock(UserRepository.class);
        }

        @Bean
        UserQueryService userQueryService(UserRepository userRepository) {
            return new UserQueryService(userRepository);
        }
    }

    @jakarta.annotation.Resource
    private UserQueryService userQueryService;

    @jakarta.annotation.Resource
    private UserRepository userRepository;

    @BeforeEach
    void clearInteractions() {
        reset(userRepository);
        SecurityContextHolder.clearContext();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void userCanFetchOwnProfile() {
        User user = user(UUID.randomUUID(), UserRole.USER, "self@example.com");
        authenticate(user.getId(), UserRole.USER);
        when(userRepository.findById(user.getId())).thenReturn(Optional.of(user));

        UserProfileResponse response = userQueryService.getUserProfile(user.getId());

        assertEquals(user.getId(), response.id());
        assertEquals(user.getEmail(), response.email());
    }

    @Test
    void userCannotFetchAnotherUsersProfile() {
        UUID authenticatedUserId = UUID.randomUUID();
        UUID targetUserId = UUID.randomUUID();
        authenticate(authenticatedUserId, UserRole.USER);

        assertThrows(AccessDeniedException.class, () -> userQueryService.getUserProfile(targetUserId));

        verify(userRepository, never()).findById(targetUserId);
    }

    @Test
    void adminCanFetchAnyProfile() {
        UUID targetUserId = UUID.randomUUID();
        User user = user(targetUserId, UserRole.USER, "target@example.com");
        authenticate(UUID.randomUUID(), UserRole.ADMIN);
        when(userRepository.findById(targetUserId)).thenReturn(Optional.of(user));

        UserProfileResponse response = userQueryService.getUserProfile(targetUserId);

        assertEquals(targetUserId, response.id());
    }

    @Test
    void adminCanListUsers() {
        User first = user(UUID.randomUUID(), UserRole.USER, "first@example.com");
        User second = user(UUID.randomUUID(), UserRole.ADMIN, "second@example.com");
        authenticate(UUID.randomUUID(), UserRole.ADMIN);
        when(userRepository.findAll()).thenReturn(List.of(first, second));

        List<UserProfileResponse> response = userQueryService.listUsers();

        assertEquals(2, response.size());
    }

    @Test
    void userCannotListUsers() {
        authenticate(UUID.randomUUID(), UserRole.USER);

        assertThrows(AccessDeniedException.class, () -> userQueryService.listUsers());

        verify(userRepository, never()).findAll();
    }

    private void authenticate(UUID userId, UserRole role) {
        AuthenticatedUser authenticatedUser = new AuthenticatedUser(userId, role, "token-id", Instant.now().plusSeconds(900));
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                authenticatedUser,
                null,
                List.of(new SimpleGrantedAuthority("ROLE_" + role.name()))
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }

    private User user(UUID id, UserRole role, String email) {
        User user = new User();
        user.setId(id);
        user.setEmail(email);
        user.setRole(role);
        user.setCreatedAt(Instant.parse("2026-03-18T10:15:30Z"));
        user.setUpdatedAt(Instant.parse("2026-03-18T10:15:30Z"));
        return user;
    }
}
