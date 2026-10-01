package com.vikas.authsystem.service;

import com.vikas.authsystem.config.OtpProperties;
import com.vikas.authsystem.exception.TooManyRequestsException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EmailVerificationOtpServiceTest {

    private static final Instant FIXED_NOW = Instant.parse("2026-03-20T10:15:30Z");

    private final StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final HashOperations<String, Object, Object> hashOperations = mock(HashOperations.class);

    private EmailVerificationOtpService otpService;

    @BeforeEach
    void setUp() {
        OtpProperties otpProperties = new OtpProperties();
        otpProperties.setSecret("test-otp-secret");
        Clock clock = Clock.fixed(FIXED_NOW, ZoneOffset.UTC);
        otpService = new EmailVerificationOtpService(redisTemplate, otpProperties, clock);
        when(redisTemplate.opsForHash()).thenReturn(hashOperations);
    }

    @Test
    void issueOtpStoresHashedOtpWithThreeMinuteTtl() {
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(1L);

        EmailVerificationOtpService.OtpIssueResult result = otpService.issueOtp(UUID.randomUUID());

        assertNotNull(result.otp());
        assertEquals(180, result.expiresInSeconds());
        assertEquals(30, result.resendAvailableInSeconds());
        verify(hashOperations).putAll(anyString(), anyMap());
        verify(redisTemplate).expire(anyString(), any());
    }

    @Test
    void issueOtpRejectsGenerationBudgetOverflow() {
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(6L);
        when(redisTemplate.getExpire(anyString())).thenReturn(900L);

        TooManyRequestsException exception = assertThrows(
                TooManyRequestsException.class,
                () -> otpService.issueOtp(UUID.randomUUID())
        );

        assertEquals(900L, exception.getRetryAfterSeconds());
    }

    @Test
    void reissueOtpRejectsResendBudgetOverflow() {
        UUID userId = UUID.randomUUID();
        when(hashOperations.entries(anyString())).thenReturn(Map.of(
                "createdAtEpochSecond", String.valueOf(FIXED_NOW.minusSeconds(30).getEpochSecond()),
                "resendAvailableAtEpochSecond", String.valueOf(FIXED_NOW.minusSeconds(1).getEpochSecond()),
                "otpVersion", "2"
        ));
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(4L);
        when(redisTemplate.getExpire(anyString())).thenReturn(600L);

        TooManyRequestsException exception = assertThrows(
                TooManyRequestsException.class,
                () -> otpService.reissueOtp(userId)
        );

        assertEquals(600L, exception.getRetryAfterSeconds());
    }

    @Test
    void reissueOtpReturnsTheSameOtpUntilItExpires() {
        UUID userId = UUID.randomUUID();
        String key = "auth:email-verification:" + userId;
        Map<Object, Object> metadata = Map.of(
                "createdAtEpochSecond", String.valueOf(FIXED_NOW.minusSeconds(45).getEpochSecond()),
                "resendAvailableAtEpochSecond", String.valueOf(FIXED_NOW.minusSeconds(1).getEpochSecond()),
                "otpVersion", "2",
                "attemptCount", "0"
        );
        when(hashOperations.entries(key)).thenReturn(metadata);
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(1L);
        when(redisTemplate.getExpire(key)).thenReturn(135L);

        EmailVerificationOtpService.OtpIssueResult first = otpService.reissueOtp(userId);
        EmailVerificationOtpService.OtpIssueResult second = otpService.reissueOtp(userId);

        assertEquals(first.otp(), second.otp());
        assertEquals(135L, first.expiresInSeconds());
        assertEquals(30L, first.resendAvailableInSeconds());
        verify(hashOperations, times(2)).put(
                eq(key),
                eq("resendAvailableAtEpochSecond"),
                eq(String.valueOf(FIXED_NOW.plusSeconds(30).getEpochSecond()))
        );
    }

    @Test
    void reissueOtpRejectsCooldownWithRetryAfter() {
        UUID userId = UUID.randomUUID();
        when(hashOperations.entries(anyString())).thenReturn(Map.of(
                "createdAtEpochSecond", String.valueOf(FIXED_NOW.minusSeconds(10).getEpochSecond()),
                "resendAvailableAtEpochSecond", String.valueOf(FIXED_NOW.plusSeconds(12).getEpochSecond()),
                "otpVersion", "2"
        ));

        TooManyRequestsException exception = assertThrows(
                TooManyRequestsException.class,
                () -> otpService.reissueOtp(userId)
        );

        assertEquals("OTP can be resent in 12 seconds.", exception.getMessage());
        assertEquals(12L, exception.getRetryAfterSeconds());
    }
}
