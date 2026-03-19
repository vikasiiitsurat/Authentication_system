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

    public RateLimiterService(StringRedisTemplate redisTemplate, RateLimitProperties rateLimitProperties) {
        this.redisTemplate = redisTemplate;
        this.rateLimitProperties = rateLimitProperties;
    }

    public void validateLoginRateLimit(String email, String ipAddress) {
        String key = LOGIN_KEY_PREFIX + normalize(email) + ":" + normalize(ipAddress);
        validateLimit(
                key,
                rateLimitProperties.getLogin(),
                "Too many login attempts. Please try again later."
        );
    }

    public void validateOtpGenerationRateLimit(String email, String ipAddress) {
        String key = OTP_GENERATION_KEY_PREFIX + normalize(email) + ":" + normalize(ipAddress);
        validateLimit(
                key,
                rateLimitProperties.getOtpGeneration(),
                "Too many OTP requests. Please wait before requesting another code."
        );
    }

    public void validateOtpVerificationRateLimit(String email, String ipAddress) {
        String key = OTP_VERIFICATION_KEY_PREFIX + normalize(email) + ":" + normalize(ipAddress);
        validateLimit(
                key,
                rateLimitProperties.getOtpVerification(),
                "Too many OTP verification attempts. Please request a new code or try again later."
        );
    }

    private void validateLimit(String key, RateLimitProperties.Limit limit, String errorMessage) {
        Long currentCount = redisTemplate.execute(
                INCREMENT_WITH_TTL_SCRIPT,
                List.of(key),
                String.valueOf(limit.getWindowSeconds())
        );

        if (currentCount == null) {
            throw new IllegalStateException("Failed to evaluate rate limit");
        }

        if (currentCount > limit.getMaxAttempts()) {
            throw new TooManyRequestsException(errorMessage);
        }
    }

    private String normalize(String value) {
        return value == null ? "unknown" : value.trim().toLowerCase();
    }
}
