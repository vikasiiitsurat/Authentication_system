package com.vikas.authsystem.security;

import com.vikas.authsystem.config.JwtProperties;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.repository.UserRepository;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private final TokenBlacklistService tokenBlacklistService = mock(TokenBlacklistService.class);
    private final SessionBlacklistService sessionBlacklistService = mock(SessionBlacklistService.class);
    private final UserRepository userRepository = mock(UserRepository.class);

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void rejectsAccessTokenIssuedBeforePasswordChange() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil(), tokenBlacklistService, sessionBlacklistService, userRepository);
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Instant issuedAt = Instant.parse("2026-03-26T10:15:30Z");
        User user = new User();
        user.setId(userId);
        user.setRole(UserRole.USER);
        user.setPasswordChangedAt(issuedAt.plusSeconds(300));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(sessionBlacklistService.isBlacklisted(sessionId)).thenReturn(false);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + token(userId, sessionId, issuedAt));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void acceptsAccessTokenIssuedAfterPasswordChange() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil(), tokenBlacklistService, sessionBlacklistService, userRepository);
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Instant issuedAt = Instant.parse("2026-03-26T10:15:30Z");
        User user = new User();
        user.setId(userId);
        user.setRole(UserRole.USER);
        user.setPasswordChangedAt(issuedAt.minusSeconds(300));
        when(userRepository.findById(userId)).thenReturn(Optional.of(user));
        when(sessionBlacklistService.isBlacklisted(sessionId)).thenReturn(false);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + token(userId, sessionId, issuedAt));

        filter.doFilterInternal(request, response, filterChain);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    private JwtUtil jwtUtil() {
        JwtProperties jwtProperties = new JwtProperties();
        jwtProperties.setIssuer("test-issuer");
        jwtProperties.setAccessTokenMinutes(5);
        jwtProperties.setRefreshTokenDays(7);
        SecretKey secretKey = new SecretKeySpec("01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        jwtProperties.setSecret(Base64.getEncoder().encodeToString(secretKey.getEncoded()));
        return new JwtUtil(jwtProperties);
    }

    private String token(UUID userId, UUID sessionId, Instant issuedAt) {
        SecretKey signingKey = new SecretKeySpec("01234567890123456789012345678901".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        return Jwts.builder()
                .issuer("test-issuer")
                .subject(userId.toString())
                .id(UUID.randomUUID().toString())
                .issuedAt(java.util.Date.from(issuedAt))
                .expiration(java.util.Date.from(issuedAt.plusSeconds(300)))
                .claim("user_id", userId.toString())
                .claim("role", UserRole.USER.name())
                .claim("session_id", sessionId.toString())
                .signWith(signingKey)
                .compact();
    }
}
