package com.vikas.authsystem.security;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
public class SessionBlacklistService {

    private static final String KEY_PREFIX = "auth:session-blacklist:";

    private final StringRedisTemplate redisTemplate;

    public SessionBlacklistService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void blacklist(UUID sessionId, Duration ttl) {
        if (sessionId == null || ttl == null || ttl.isZero() || ttl.isNegative()) {
            return;
        }
        redisTemplate.opsForValue().set(KEY_PREFIX + sessionId, "1", ttl);
    }

    public boolean isBlacklisted(UUID sessionId) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(KEY_PREFIX + sessionId));
    }
}
