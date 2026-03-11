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
        String key = LOGIN_KEY_PREFIX + email + ":" + ipAddress;
        Long currentCount = redisTemplate.execute(
                INCREMENT_WITH_TTL_SCRIPT,
                List.of(key),
                String.valueOf(rateLimitProperties.getWindowSeconds())
        );

        if (currentCount == null) {
            throw new IllegalStateException("Failed to evaluate login rate limit");
        }

        if (currentCount > rateLimitProperties.getMaxAttemptsPerMinute()) {
            throw new TooManyRequestsException("Too many login attempts. Please try again later.");
        }
    }
}
