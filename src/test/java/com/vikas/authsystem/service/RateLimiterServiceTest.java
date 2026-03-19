package com.vikas.authsystem.service;

import com.vikas.authsystem.config.RateLimitProperties;
import com.vikas.authsystem.exception.TooManyRequestsException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class RateLimiterServiceTest {

    private final StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
    private RateLimiterService rateLimiterService;

    @BeforeEach
    void setUp() {
        RateLimitProperties properties = new RateLimitProperties();
        properties.getLogin().setMaxAttempts(10);
        properties.getLogin().setWindowSeconds(60);
        properties.getOtpGeneration().setMaxAttempts(5);
        properties.getOtpGeneration().setWindowSeconds(900);
        properties.getOtpVerification().setMaxAttempts(10);
        properties.getOtpVerification().setWindowSeconds(300);
        rateLimiterService = new RateLimiterService(redisTemplate, properties);
    }

    @Test
    void allowsOtpGenerationWithinLimit() {
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(5L);

        assertDoesNotThrow(() -> rateLimiterService.validateOtpGenerationRateLimit("user@example.com", "127.0.0.1"));
    }

    @Test
    void rejectsOtpGenerationBeyondLimit() {
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(6L);

        assertThrows(
                TooManyRequestsException.class,
                () -> rateLimiterService.validateOtpGenerationRateLimit("user@example.com", "127.0.0.1")
        );
    }

    @Test
    void rejectsOtpVerificationBeyondLimit() {
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(11L);

        assertThrows(
                TooManyRequestsException.class,
                () -> rateLimiterService.validateOtpVerificationRateLimit("user@example.com", "127.0.0.1")
        );
    }
}
