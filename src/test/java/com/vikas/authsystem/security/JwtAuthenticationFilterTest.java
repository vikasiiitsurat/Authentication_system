package com.vikas.authsystem.security;

import com.vikas.authsystem.config.JwtProperties;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.service.UserSecurityStateService;
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
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class JwtAuthenticationFilterTest {

    private final TokenBlacklistService tokenBlacklistService = mock(TokenBlacklistService.class);
    private final SessionBlacklistService sessionBlacklistService = mock(SessionBlacklistService.class);
    private final UserSecurityStateService userSecurityStateService = mock(UserSecurityStateService.class);

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void rejectsAccessTokenIssuedBeforePasswordChange() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil(), tokenBlacklistService, sessionBlacklistService, userSecurityStateService);
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Instant issuedAt = Instant.now().plusSeconds(300);
        when(userSecurityStateService.getSecurityState(userId)).thenReturn(
                new UserSecurityStateService.UserSecurityState(false, issuedAt.plusSeconds(300).getEpochSecond(), null)
        );
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
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil(), tokenBlacklistService, sessionBlacklistService, userSecurityStateService);
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Instant issuedAt = Instant.now().plusSeconds(300);
        when(userSecurityStateService.getSecurityState(userId)).thenReturn(
                new UserSecurityStateService.UserSecurityState(false, issuedAt.minusSeconds(300).getEpochSecond(), null)
        );
        when(sessionBlacklistService.isBlacklisted(sessionId)).thenReturn(false);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + token(userId, sessionId, issuedAt));

        filter.doFilterInternal(request, response, filterChain);

        assertNotNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void rejectsAccessTokenIssuedAtOrBeforeGlobalLogout() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil(), tokenBlacklistService, sessionBlacklistService, userSecurityStateService);
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Instant issuedAt = Instant.now().plusSeconds(300);
        when(userSecurityStateService.getSecurityState(userId)).thenReturn(
                new UserSecurityStateService.UserSecurityState(false, null, issuedAt.getEpochSecond())
        );
        when(sessionBlacklistService.isBlacklisted(sessionId)).thenReturn(false);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + token(userId, sessionId, issuedAt));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    @Test
    void rejectsAccessTokenForSoftDeletedAccount() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil(), tokenBlacklistService, sessionBlacklistService, userSecurityStateService);
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Instant issuedAt = Instant.now().plusSeconds(300);
        when(userSecurityStateService.getSecurityState(userId)).thenReturn(
                new UserSecurityStateService.UserSecurityState(true, null, null)
        );
        when(sessionBlacklistService.isBlacklisted(sessionId)).thenReturn(false);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + token(userId, sessionId, issuedAt));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
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

    @Test
    void rejectsJwtWithoutAccessTokenType() throws Exception {
        JwtAuthenticationFilter filter = new JwtAuthenticationFilter(jwtUtil(), tokenBlacklistService, sessionBlacklistService, userSecurityStateService);
        UUID userId = UUID.randomUUID();
        UUID sessionId = UUID.randomUUID();
        Instant issuedAt = Instant.now().plusSeconds(300);
        when(sessionBlacklistService.isBlacklisted(sessionId)).thenReturn(false);

        HttpServletRequest request = mock(HttpServletRequest.class);
        HttpServletResponse response = mock(HttpServletResponse.class);
        FilterChain filterChain = mock(FilterChain.class);
        when(request.getHeader(HttpHeaders.AUTHORIZATION)).thenReturn("Bearer " + token(userId, sessionId, issuedAt, "refresh"));

        filter.doFilterInternal(request, response, filterChain);

        assertNull(SecurityContextHolder.getContext().getAuthentication());
    }

    private String token(UUID userId, UUID sessionId, Instant issuedAt) {
        return token(userId, sessionId, issuedAt, "access");
    }

    private String token(UUID userId, UUID sessionId, Instant issuedAt, String tokenType) {
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
                .claim("token_type", tokenType)
                .signWith(signingKey)
                .compact();
    }
}
