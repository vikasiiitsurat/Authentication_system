package com.vikas.authsystem.security;

import com.vikas.authsystem.entity.UserRole;
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

    public JwtAuthenticationFilter(JwtUtil jwtUtil, TokenBlacklistService tokenBlacklistService) {
        this.jwtUtil = jwtUtil;
        this.tokenBlacklistService = tokenBlacklistService;
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
            String jti = claims.getId();
            if (jti != null && tokenBlacklistService.isBlacklisted(jti)) {
                filterChain.doFilter(request, response);
                return;
            }

            UUID userId = extractUserId(claims);
            UserRole role = extractRole(claims);
            Instant tokenExpiresAt = claims.getExpiration() == null ? null : claims.getExpiration().toInstant();
            AuthenticatedUser authenticatedUser = new AuthenticatedUser(userId, role, jti, tokenExpiresAt);
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
}
