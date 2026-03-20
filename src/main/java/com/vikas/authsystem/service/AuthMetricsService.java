package com.vikas.authsystem.service;

import com.vikas.authsystem.entity.AuditAction;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tag;
import io.micrometer.core.instrument.Timer;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Locale;

@Service
public class AuthMetricsService {

    private static final Duration[] AUTH_OPERATION_SLOS = {
            Duration.ofMillis(50),
            Duration.ofMillis(100),
            Duration.ofMillis(250),
            Duration.ofMillis(500),
            Duration.ofSeconds(1),
            Duration.ofSeconds(3)
    };
    private static final Duration[] AUDIT_PERSISTENCE_SLOS = {
            Duration.ofMillis(10),
            Duration.ofMillis(25),
            Duration.ofMillis(50),
            Duration.ofMillis(100),
            Duration.ofMillis(250)
    };

    private final MeterRegistry meterRegistry;

    public AuthMetricsService(MeterRegistry meterRegistry) {
        this.meterRegistry = meterRegistry;
    }

    public Timer.Sample startTimer() {
        return Timer.start(meterRegistry);
    }

    public void recordOperation(String operation, String outcome, Timer.Sample sample) {
        String normalizedOperation = normalizeTag(operation);
        String normalizedOutcome = normalizeTag(outcome);
        counter(
                "auth.operation.total",
                List.of(
                        Tag.of("operation", normalizedOperation),
                        Tag.of("outcome", normalizedOutcome)
                )
        ).increment();

        if (sample != null) {
            sample.stop(
                    Timer.builder("auth.operation.duration")
                            .description("Latency of authentication service operations")
                            .publishPercentileHistogram()
                            .serviceLevelObjectives(AUTH_OPERATION_SLOS)
                            .tags("operation", normalizedOperation, "outcome", normalizedOutcome)
                            .register(meterRegistry)
            );
        }
    }

    public void recordRateLimitDecision(String limiter, String outcome) {
        counter(
                "auth.rate_limit.total",
                List.of(
                        Tag.of("limiter", normalizeTag(limiter)),
                        Tag.of("outcome", normalizeTag(outcome))
                )
        ).increment();
    }

    public void recordAuditPersistence(AuditAction action, String outcome, Timer.Sample sample) {
        String normalizedAction = normalizeTag(action.name());
        String normalizedOutcome = normalizeTag(outcome);
        counter(
                "auth.audit.event.total",
                List.of(
                        Tag.of("action", normalizedAction),
                        Tag.of("outcome", normalizedOutcome)
                )
        ).increment();

        if (sample != null) {
            sample.stop(
                    Timer.builder("auth.audit.persistence.duration")
                            .description("Latency of auth audit event persistence")
                            .publishPercentileHistogram()
                            .serviceLevelObjectives(AUDIT_PERSISTENCE_SLOS)
                            .tags("action", normalizedAction, "outcome", normalizedOutcome)
                            .register(meterRegistry)
            );
        }
    }

    private Counter counter(String name, Iterable<Tag> tags) {
        return Counter.builder(name)
                .tags(tags)
                .register(meterRegistry);
    }

    private String normalizeTag(String value) {
        if (value == null || value.isBlank()) {
            return "unknown";
        }
        return value.trim().toLowerCase(Locale.ROOT).replace(' ', '_');
    }
}
