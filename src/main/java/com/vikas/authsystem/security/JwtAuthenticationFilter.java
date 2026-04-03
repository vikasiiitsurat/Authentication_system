package com.vikas.authsystem.security;

import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.service.UserSecurityStateService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.UUID;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);
    private final JwtUtil jwtUtil;
    private final TokenBlacklistService tokenBlacklistService;
    private final SessionBlacklistService sessionBlacklistService;
    private final UserSecurityStateService userSecurityStateService;

    public JwtAuthenticationFilter(
            JwtUtil jwtUtil,
            TokenBlacklistService tokenBlacklistService,
            SessionBlacklistService sessionBlacklistService,
            UserSecurityStateService userSecurityStateService
    ) {
        this.jwtUtil = jwtUtil;
        this.tokenBlacklistService = tokenBlacklistService;
        this.sessionBlacklistService = sessionBlacklistService;
        this.userSecurityStateService = userSecurityStateService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        try {
            Jws<Claims> parsed = jwtUtil.parseToken(token);
            Claims claims = parsed.getPayload();
            requireAccessToken(claims);
            String jti = claims.getId();
            if (jti != null && tokenBlacklistService.isBlacklisted(jti)) {
                filterChain.doFilter(request, response);
                return;
            }

            UUID userId = extractUserId(claims);
            UserRole role = extractRole(claims);
            UUID sessionId = extractSessionId(claims);
            if (sessionBlacklistService.isBlacklisted(sessionId)) {
                filterChain.doFilter(request, response);
                return;
            }
            Instant tokenExpiresAt = claims.getExpiration() == null ? null : claims.getExpiration().toInstant();
            Instant tokenIssuedAt = claims.getIssuedAt() == null ? null : claims.getIssuedAt().toInstant();
            if (isSecurityStateNewerThanToken(userId, tokenIssuedAt)) {
                filterChain.doFilter(request, response);
                return;
            }
            AuthenticatedUser authenticatedUser = new AuthenticatedUser(userId, role, sessionId, jti, tokenExpiresAt);
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            authenticatedUser,
                            null,
                            Collections.singletonList(new SimpleGrantedAuthority("ROLE_" + role.name()))
                    );
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException | IllegalArgumentException ex) {
            log.warn("Invalid JWT for request {}: {}", request.getRequestURI(), ex.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private boolean isSecurityStateNewerThanToken(UUID userId, Instant tokenIssuedAt) {
        UserSecurityStateService.UserSecurityState securityState = userSecurityStateService.getSecurityState(userId);
        if (securityState.deleted()) {
            return true;
        }
        return isTokenStale(tokenIssuedAt, toInstant(securityState.passwordChangedAtEpochSecond()))
                || isTokenStale(tokenIssuedAt, toInstant(securityState.sessionInvalidatedAtEpochSecond()));
    }

    private boolean isTokenStale(Instant tokenIssuedAt, Instant invalidationMarker) {
        return invalidationMarker != null && (tokenIssuedAt == null || !tokenIssuedAt.isAfter(invalidationMarker));
    }

    private UUID extractUserId(Claims claims) {
        String subject = claims.getSubject();
        String userIdClaim = claims.get("user_id", String.class);
        String resolvedUserId = subject != null ? subject : userIdClaim;
        if (resolvedUserId == null || resolvedUserId.isBlank()) {
            throw new JwtException("JWT is missing the user identifier");
        }
        if (subject != null && userIdClaim != null && !subject.equals(userIdClaim)) {
            throw new JwtException("JWT subject does not match user_id claim");
        }
        try {
            return UUID.fromString(resolvedUserId);
        } catch (IllegalArgumentException ex) {
            throw new JwtException("JWT contains an invalid user identifier", ex);
        }
    }

    private UUID extractSessionId(Claims claims) {
        String sessionIdClaim = claims.get("session_id", String.class);
        if (sessionIdClaim == null || sessionIdClaim.isBlank()) {
            throw new JwtException("JWT is missing the session identifier");
        }
        try {
            return UUID.fromString(sessionIdClaim);
        } catch (IllegalArgumentException ex) {
            throw new JwtException("JWT contains an invalid session identifier", ex);
        }
    }

    private UserRole extractRole(Claims claims) {
        String roleClaim = claims.get("role", String.class);
        if (roleClaim == null || roleClaim.isBlank()) {
            throw new JwtException("JWT is missing the role claim");
        }
        try {
            return UserRole.valueOf(roleClaim);
        } catch (IllegalArgumentException ex) {
            throw new JwtException("JWT contains an invalid role claim", ex);
        }
    }

    private void requireAccessToken(Claims claims) {
        String tokenType = claims.get("token_type", String.class);
        if (!"access".equals(tokenType)) {
            throw new JwtException("JWT is not an access token");
        }
    }

    private Instant toInstant(Long epochSecond) {
        return epochSecond == null ? null : Instant.ofEpochSecond(epochSecond);
    }
}
