package com.vikas.authsystem.dto;

import java.time.Instant;
import java.util.UUID;

public record SessionResponse(
        UUID sessionId,
        String deviceId,
        Instant sessionStartedAt,
        Instant lastUsedAt,
        Instant expiresAt,
        String lastSeenIp,
        boolean current
) {
}
