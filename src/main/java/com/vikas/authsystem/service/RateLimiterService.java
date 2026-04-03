package com.vikas.authsystem.service;

import com.vikas.authsystem.config.RateLimitProperties;
import com.vikas.authsystem.exception.TooManyRequestsException;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class RateLimiterService {

    private static final String OTP_GENERATION_KEY_PREFIX = "auth:rl:otp-generation:";
    private static final String OTP_VERIFICATION_KEY_PREFIX = "auth:rl:otp-verification:";
    private static final String PASSWORD_RESET_REQUEST_KEY_PREFIX = "auth:rl:password-reset-request:";
    private static final String PASSWORD_RESET_CONFIRMATION_KEY_PREFIX = "auth:rl:password-reset-confirmation:";
    private static final String ACCOUNT_UNLOCK_REQUEST_KEY_PREFIX = "auth:rl:account-unlock-request:";
    private static final String ACCOUNT_UNLOCK_CONFIRMATION_KEY_PREFIX = "auth:rl:account-unlock-confirmation:";
    private static final String LOGIN_TWO_FACTOR_REQUEST_KEY_PREFIX = "auth:rl:login-two-factor-request:";
    private static final String LOGIN_TWO_FACTOR_CONFIRMATION_KEY_PREFIX = "auth:rl:login-two-factor-confirmation:";
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

    public void validateOtpGenerationRateLimit(String email, String ipAddress) {
        validateScopedLimit(
                OTP_GENERATION_KEY_PREFIX,
                "otp_generation",
                rateLimitProperties.getOtpGeneration(),
                normalize(email),
                normalize(ipAddress),
                "Too many OTP requests. Please wait before requesting another code."
        );
    }

    public void validateOtpVerificationRateLimit(String email, String ipAddress) {
        validateScopedLimit(
                OTP_VERIFICATION_KEY_PREFIX,
                "otp_verification",
                rateLimitProperties.getOtpVerification(),
                normalize(email),
                normalize(ipAddress),
                "Too many OTP verification attempts. Please request a new code or try again later."
        );
    }

    public void validatePasswordResetRequestRateLimit(String email, String ipAddress) {
        validateScopedLimit(
                PASSWORD_RESET_REQUEST_KEY_PREFIX,
                "password_reset_request",
                rateLimitProperties.getPasswordResetRequest(),
                normalize(email),
                normalize(ipAddress),
                "Too many password reset requests. Please try again later."
        );
    }

    public void validatePasswordResetConfirmationRateLimit(String email, String ipAddress) {
        validateScopedLimit(
                PASSWORD_RESET_CONFIRMATION_KEY_PREFIX,
                "password_reset_confirmation",
                rateLimitProperties.getPasswordResetConfirmation(),
                normalize(email),
                normalize(ipAddress),
                "Too many password reset attempts. Please request a new code or try again later."
        );
    }

    public void validateAccountUnlockRequestRateLimit(String email, String ipAddress) {
        validateScopedLimit(
                ACCOUNT_UNLOCK_REQUEST_KEY_PREFIX,
                "account_unlock_request",
                rateLimitProperties.getAccountUnlockRequest(),
                normalize(email),
                normalize(ipAddress),
                "Too many account unlock requests. Please try again later."
        );
    }

    public void validateAccountUnlockConfirmationRateLimit(String email, String ipAddress) {
        validateScopedLimit(
                ACCOUNT_UNLOCK_CONFIRMATION_KEY_PREFIX,
                "account_unlock_confirmation",
                rateLimitProperties.getAccountUnlockConfirmation(),
                normalize(email),
                normalize(ipAddress),
                "Too many account unlock attempts. Please request a new code or try again later."
        );
    }

    public void validateLoginTwoFactorRequestRateLimit(String email, String ipAddress) {
        validateScopedLimit(
                LOGIN_TWO_FACTOR_REQUEST_KEY_PREFIX,
                "login_two_factor_request",
                rateLimitProperties.getLoginTwoFactorRequest(),
                normalize(email),
                normalize(ipAddress),
                "Too many login verification requests. Please try again later."
        );
    }

    public void validateLoginTwoFactorConfirmationRateLimit(String email, String ipAddress) {
        validateScopedLimit(
                LOGIN_TWO_FACTOR_CONFIRMATION_KEY_PREFIX,
                "login_two_factor_confirmation",
                rateLimitProperties.getLoginTwoFactorConfirmation(),
                normalize(email),
                normalize(ipAddress),
                "Too many login verification attempts. Please request a new code or try again later."
        );
    }

    private void validateScopedLimit(
            String keyPrefix,
            String limiter,
            RateLimitProperties.ScopedLimit scopedLimit,
            String accountKey,
            String ipKey,
            String errorMessage
    ) {
        validateLimit(keyPrefix + "account:" + accountKey, limiter, "account", scopedLimit.getPerAccount(), errorMessage);
        validateLimit(keyPrefix + "ip:" + ipKey, limiter, "ip", scopedLimit.getPerIp(), errorMessage);
        validateLimit(keyPrefix + "account-ip:" + accountKey + ":" + ipKey, limiter, "account_ip", scopedLimit.getPerAccountIp(), errorMessage);
    }

    private void validateLimit(
            String key,
            String limiter,
            String scope,
            RateLimitProperties.Limit limit,
            String errorMessage
    ) {
        if (limit.getMaxAttempts() <= 0 || limit.getWindowSeconds() <= 0) {
            return;
        }
        Long currentCount;
        try {
            currentCount = redisTemplate.execute(
                    INCREMENT_WITH_TTL_SCRIPT,
                    List.of(key),
                    String.valueOf(limit.getWindowSeconds())
                );
        } catch (RuntimeException ex) {
            authMetricsService.recordRateLimitDecision(limiter, scope, "backend_error");
            throw ex;
        }

        if (currentCount == null) {
            authMetricsService.recordRateLimitDecision(limiter, scope, "backend_error");
            throw new IllegalStateException("Failed to evaluate rate limit");
        }

        if (currentCount > limit.getMaxAttempts()) {
            authMetricsService.recordRateLimitDecision(limiter, scope, "rejected");
            throw new TooManyRequestsException(errorMessage, retryAfterSeconds(key));
        }
        authMetricsService.recordRateLimitDecision(limiter, scope, "allowed");
    }

    private long retryAfterSeconds(String key) {
        Long ttl = redisTemplate.getExpire(key);
        return ttl == null || ttl < 0 ? 0 : ttl;
    }

    private String normalize(String value) {
        return value == null ? "unknown" : value.trim().toLowerCase();
    }
}
