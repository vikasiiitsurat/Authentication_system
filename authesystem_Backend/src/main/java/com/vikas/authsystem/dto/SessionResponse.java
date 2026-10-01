package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;
import java.util.UUID;

@Schema(name = "SessionResponse", description = "Active session information for a refresh-token-backed device session.")
public record SessionResponse(
        @Schema(description = "Unique session identifier", example = "9f4af534-4e16-4f80-b50a-0dd547f1de4d")
        UUID sessionId,
        @Schema(description = "Client-provided device identifier", example = "macbook-pro-16")
        String deviceId,
        @Schema(description = "Timestamp when the session was first created", example = "2026-03-20T10:47:27Z")
        Instant sessionStartedAt,
        @Schema(description = "Timestamp of the last successful token use for the session", example = "2026-03-20T11:15:00Z")
        Instant lastUsedAt,
        @Schema(description = "Refresh token expiration time for the session", example = "2026-04-19T10:47:27Z")
        Instant expiresAt,
        @Schema(description = "Last observed client IP address for the session", example = "203.0.113.24")
        String lastSeenIp,
        @Schema(description = "Whether the session corresponds to the currently authenticated device", example = "true")
        boolean current
) {
}
