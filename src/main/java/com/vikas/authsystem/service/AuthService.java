package com.vikas.authsystem.service;

import com.vikas.authsystem.dto.LoginRequest;
import com.vikas.authsystem.dto.LoginResponse;
import com.vikas.authsystem.dto.LogoutRequest;
import com.vikas.authsystem.dto.RefreshTokenRequest;
import com.vikas.authsystem.dto.RegisterRequest;
import com.vikas.authsystem.dto.RegisterResponse;
import com.vikas.authsystem.entity.User;
import com.vikas.authsystem.entity.UserRole;
import com.vikas.authsystem.exception.AccountLockedException;
import com.vikas.authsystem.exception.ResourceConflictException;
import com.vikas.authsystem.exception.UnauthorizedException;
import com.vikas.authsystem.repository.UserRepository;
import com.vikas.authsystem.security.JwtUtil;
import com.vikas.authsystem.security.TokenBlacklistService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class AuthService {

    private static final Logger log = LoggerFactory.getLogger(AuthService.class);
    private static final int MAX_FAILED_ATTEMPTS = 5;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtil jwtUtil;
    private final RefreshTokenService refreshTokenService;
    private final TemporaryCacheService temporaryCacheService;
    private final TokenBlacklistService tokenBlacklistService;

    public AuthService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil,
            RefreshTokenService refreshTokenService,
            TemporaryCacheService temporaryCacheService,
            TokenBlacklistService tokenBlacklistService
    ) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
        this.refreshTokenService = refreshTokenService;
        this.temporaryCacheService = temporaryCacheService;
        this.tokenBlacklistService = tokenBlacklistService;
    }

    @Transactional
    public RegisterResponse register(RegisterRequest request) {
        String normalizedEmail = normalizeEmail(request.email());
        if (userRepository.existsByEmail(normalizedEmail)) {
            throw new ResourceConflictException("Email is already registered");
        }

        User user = new User();
        user.setEmail(normalizedEmail);
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setRole(UserRole.USER);
        user.setFailedAttempts(0);
        user.setAccountLocked(false);
        User savedUser = userRepository.save(user);

        log.info("User registered successfully with userId={}", savedUser.getId());
        return new RegisterResponse(savedUser.getId(), savedUser.getEmail(), "Registration successful", savedUser.getCreatedAt());
    }

    @Transactional
    public LoginResponse login(LoginRequest request, String clientIp) {
        String normalizedEmail = normalizeEmail(request.email());
        User user = userRepository.findByEmail(normalizedEmail)
                .orElseThrow(() -> new UnauthorizedException("Invalid credentials"));

        if (user.isAccountLocked()) {
            throw new AccountLockedException("Account is locked due to multiple failed login attempts");
        }

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            handleFailedLogin(user);
            throw new UnauthorizedException("Invalid credentials");
        }

        resetFailedAttempts(user);
        String accessToken = jwtUtil.generateAccessToken(user.getId(), user.getRole().name());
        String refreshToken = refreshTokenService.generateRawRefreshToken();
        refreshTokenService.storeRefreshToken(user, refreshToken, request.deviceId());
        temporaryCacheService.cacheLastLoginMetadata(user.getId(), clientIp);
        refreshTokenService.deleteExpiredRefreshTokens();

        log.info("User login succeeded for userId={} from ip={}", user.getId(), clientIp);
        return new LoginResponse(accessToken, refreshToken, "Bearer", jwtUtil.accessTokenTtlSeconds());
    }

    @Transactional
    public LoginResponse refresh(RefreshTokenRequest request) {
        return refreshTokenService.refreshAccessToken(request.refreshToken(), request.deviceId());
    }

    @Transactional
    public void logout(LogoutRequest request, String bearerToken) {
        java.util.UUID authenticatedUserId = null;
        if (bearerToken != null && !bearerToken.isBlank()) {
            Jws<Claims> parsedToken = jwtUtil.parseToken(bearerToken);
            Claims claims = parsedToken.getPayload();
            authenticatedUserId = java.util.UUID.fromString(claims.getSubject());
            String jti = claims.getId();
            if (jti != null && claims.getExpiration() != null) {
                long ttlSeconds = Math.max(0, (claims.getExpiration().toInstant().getEpochSecond() - java.time.Instant.now().getEpochSecond()));
                tokenBlacklistService.blacklist(jti, java.time.Duration.ofSeconds(ttlSeconds));
            }
        }
        refreshTokenService.revokeRefreshToken(request.refreshToken(), authenticatedUserId);
    }

    private void handleFailedLogin(User user) {
        int updatedAttempts = user.getFailedAttempts() + 1;
        user.setFailedAttempts(updatedAttempts);
        if (updatedAttempts >= MAX_FAILED_ATTEMPTS) {
            user.setAccountLocked(true);
            log.warn("User account locked after {} failed attempts for userId={}", updatedAttempts, user.getId());
        } else {
            log.warn("Failed login attempt {} for userId={}", updatedAttempts, user.getId());
        }
        userRepository.save(user);
    }

    private void resetFailedAttempts(User user) {
        user.setFailedAttempts(0);
        user.setAccountLocked(false);
        userRepository.save(user);
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }
}
