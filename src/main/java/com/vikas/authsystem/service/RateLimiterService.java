package com.vikas.authsystem.service;

import com.vikas.authsystem.config.RateLimitProperties;
import com.vikas.authsystem.exception.TooManyRequestsException;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RateLimiterService {

    private static final String LOGIN_KEY_PREFIX = "auth:rl:login:";
    private static final String OTP_GENERATION_KEY_PREFIX = "auth:rl:otp-generation:";
    private static final String OTP_VERIFICATION_KEY_PREFIX = "auth:rl:otp-verification:";
    private static final String PASSWORD_RESET_REQUEST_KEY_PREFIX = "auth:rl:password-reset-request:";
    private static final String PASSWORD_RESET_CONFIRMATION_KEY_PREFIX = "auth:rl:password-reset-confirmation:";
    private static final DefaultRedisScript<Long> INCREMENT_WITH_TTL_SCRIPT = new DefaultRedisScript<>(
            """
            local current = redis.call('INCR', KEYS[1])
            if current == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return current
            """,
            Long.class
    );

    private final StringRedisTemplate redisTemplate;
    private final RateLimitProperties rateLimitProperties;
    private final AuthMetricsService authMetricsService;

    public RateLimiterService(
            StringRedisTemplate redisTemplate,
            RateLimitProperties rateLimitProperties,
            AuthMetricsService authMetricsService
    ) {
        this.redisTemplate = redisTemplate;
        this.rateLimitProperties = rateLimitProperties;
        this.authMetricsService = authMetricsService;
    }

    public void validateLoginRateLimit(String email, String ipAddress) {
        String key = LOGIN_KEY_PREFIX + normalize(email) + ":" + normalize(ipAddress);
        validateLimit(
                key,
                "login",
                rateLimitProperties.getLogin(),
                "Too many login attempts. Please try again later."
        );
    }

    public void validateOtpGenerationRateLimit(String email, String ipAddress) {
        String key = OTP_GENERATION_KEY_PREFIX + normalize(email) + ":" + normalize(ipAddress);
        validateLimit(
                key,
                "otp_generation",
                rateLimitProperties.getOtpGeneration(),
                "Too many OTP requests. Please wait before requesting another code."
        );
    }

    public void validateOtpVerificationRateLimit(String email, String ipAddress) {
        String key = OTP_VERIFICATION_KEY_PREFIX + normalize(email) + ":" + normalize(ipAddress);
        validateLimit(
                key,
                "otp_verification",
                rateLimitProperties.getOtpVerification(),
                "Too many OTP verification attempts. Please request a new code or try again later."
        );
    }

    public void validatePasswordResetRequestRateLimit(String email, String ipAddress) {
        String key = PASSWORD_RESET_REQUEST_KEY_PREFIX + normalize(email) + ":" + normalize(ipAddress);
        validateLimit(
                key,
                "password_reset_request",
                rateLimitProperties.getPasswordResetRequest(),
                "Too many password reset requests. Please try again later."
        );
    }

    public void validatePasswordResetConfirmationRateLimit(String email, String ipAddress) {
        String key = PASSWORD_RESET_CONFIRMATION_KEY_PREFIX + normalize(email) + ":" + normalize(ipAddress);
        validateLimit(
                key,
                "password_reset_confirmation",
                rateLimitProperties.getPasswordResetConfirmation(),
                "Too many password reset attempts. Please request a new code or try again later."
        );
    }

    private void validateLimit(String key, String limiter, RateLimitProperties.Limit limit, String errorMessage) {
        Long currentCount;
        try {
            currentCount = redisTemplate.execute(
                    INCREMENT_WITH_TTL_SCRIPT,
                    List.of(key),
                    String.valueOf(limit.getWindowSeconds())
            );
        } catch (RuntimeException ex) {
            authMetricsService.recordRateLimitDecision(limiter, "backend_error");
            throw ex;
        }

        if (currentCount == null) {
            authMetricsService.recordRateLimitDecision(limiter, "backend_error");
            throw new IllegalStateException("Failed to evaluate rate limit");
        }

        if (currentCount > limit.getMaxAttempts()) {
            authMetricsService.recordRateLimitDecision(limiter, "rejected");
            throw new TooManyRequestsException(errorMessage, retryAfterSeconds(key));
        }
        authMetricsService.recordRateLimitDecision(limiter, "allowed");
    }

    private long retryAfterSeconds(String key) {
        Long ttl = redisTemplate.getExpire(key);
        return ttl == null || ttl < 0 ? 0 : ttl;
    }

    private String normalize(String value) {
        return value == null ? "unknown" : value.trim().toLowerCase();
    }
}
