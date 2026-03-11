package com.vikas.authsystem.service;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.UUID;

@Service
public class TemporaryCacheService {

    private static final String LAST_LOGIN_KEY_PREFIX = "auth:last-login:";
    private final StringRedisTemplate redisTemplate;

    public TemporaryCacheService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void cacheLastLoginMetadata(UUID userId, String ipAddress) {
        redisTemplate.opsForValue().set(
                LAST_LOGIN_KEY_PREFIX + userId,
                ipAddress,
                Duration.ofMinutes(15)
        );
    }
}
