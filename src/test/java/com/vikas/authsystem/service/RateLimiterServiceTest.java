package com.vikas.authsystem.service;

import com.vikas.authsystem.config.RateLimitProperties;
import com.vikas.authsystem.exception.TooManyRequestsException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RateLimiterServiceTest {

    private final StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
    private final AuthMetricsService authMetricsService = mock(AuthMetricsService.class);
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
        rateLimiterService = new RateLimiterService(redisTemplate, properties, authMetricsService);
    }

    @Test
    void allowsOtpGenerationWithinLimit() {
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(5L);

        assertDoesNotThrow(() -> rateLimiterService.validateOtpGenerationRateLimit("user@example.com", "127.0.0.1"));
        verify(authMetricsService).recordRateLimitDecision("otp_generation", "allowed");
    }

    @Test
    void rejectsOtpGenerationBeyondLimit() {
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(6L);
        when(redisTemplate.getExpire(anyString())).thenReturn(900L);

        TooManyRequestsException exception = assertThrows(
                TooManyRequestsException.class,
                () -> rateLimiterService.validateOtpGenerationRateLimit("user@example.com", "127.0.0.1")
        );
        assertEquals(900L, exception.getRetryAfterSeconds());
        verify(authMetricsService).recordRateLimitDecision("otp_generation", "rejected");
    }

    @Test
    void rejectsOtpVerificationBeyondLimit() {
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(11L);
        when(redisTemplate.getExpire(anyString())).thenReturn(300L);

        TooManyRequestsException exception = assertThrows(
                TooManyRequestsException.class,
                () -> rateLimiterService.validateOtpVerificationRateLimit("user@example.com", "127.0.0.1")
        );
        assertEquals(300L, exception.getRetryAfterSeconds());
        verify(authMetricsService).recordRateLimitDecision("otp_verification", "rejected");
    }
}
