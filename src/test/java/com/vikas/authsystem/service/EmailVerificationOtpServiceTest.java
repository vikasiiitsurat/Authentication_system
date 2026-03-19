package com.vikas.authsystem.service;

import com.vikas.authsystem.exception.BadRequestException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.HashOperations;
import org.springframework.data.redis.core.StringRedisTemplate;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class EmailVerificationOtpServiceTest {

    private final StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final HashOperations<String, Object, Object> hashOperations = mock(HashOperations.class);

    private EmailVerificationOtpService otpService;

    @BeforeEach
    void setUp() {
        otpService = new EmailVerificationOtpService(redisTemplate);
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

        assertThrows(BadRequestException.class, () -> otpService.issueOtp(UUID.randomUUID()));
    }

    @Test
    void reissueOtpRejectsResendBudgetOverflow() {
        UUID userId = UUID.randomUUID();
        when(hashOperations.entries(anyString())).thenReturn(Map.of(
                "resendAvailableAtEpochSecond", String.valueOf(Instant.now().minusSeconds(1).getEpochSecond())
        ));
        when(redisTemplate.execute(any(), anyList(), anyString())).thenReturn(4L);

        assertThrows(BadRequestException.class, () -> otpService.reissueOtp(userId));
    }
}
