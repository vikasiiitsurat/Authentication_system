package com.vikas.authsystem.service;

import com.vikas.authsystem.entity.AuditAction;
import io.micrometer.core.instrument.Timer;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class AuthMetricsServiceTest {

    private final SimpleMeterRegistry meterRegistry = new SimpleMeterRegistry();
    private final AuthMetricsService authMetricsService = new AuthMetricsService(meterRegistry);

    @Test
    void recordsOperationCountersAndTimers() {
        Timer.Sample sample = authMetricsService.startTimer();

        authMetricsService.recordOperation("login", "success", sample);

        assertEquals(
                1.0,
                meterRegistry.get("auth.operation.total")
                        .tag("operation", "login")
                        .tag("outcome", "success")
                        .counter()
                        .count()
        );
        assertEquals(
                1L,
                meterRegistry.get("auth.operation.duration")
                        .tag("operation", "login")
                        .tag("outcome", "success")
                        .timer()
                        .count()
        );
    }

    @Test
    void recordsAuditAndRateLimitMetrics() {
        Timer.Sample sample = authMetricsService.startTimer();

        authMetricsService.recordAuditPersistence(AuditAction.LOGIN_FAILED, "persisted", sample);
        authMetricsService.recordRateLimitDecision("otp_generation", "rejected");

        assertEquals(
                1.0,
                meterRegistry.get("auth.audit.event.total")
                        .tag("action", "login_failed")
                        .tag("outcome", "persisted")
                        .counter()
                        .count()
        );
        assertEquals(
                1L,
                meterRegistry.get("auth.audit.persistence.duration")
                        .tag("action", "login_failed")
                        .tag("outcome", "persisted")
                        .timer()
                        .count()
        );
        assertEquals(
                1.0,
                meterRegistry.get("auth.rate_limit.total")
                        .tag("limiter", "otp_generation")
                        .tag("outcome", "rejected")
                        .counter()
                        .count()
        );
    }
}
