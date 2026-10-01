package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(name = "GlobalLogoutResponse", description = "Result of revoking all active sessions for the authenticated account.")
public record GlobalLogoutResponse(
        @Schema(description = "User-facing operation result message", example = "All active sessions were revoked")
        String message,
        @Schema(description = "Number of active refresh-token sessions revoked by the operation", example = "3")
        int revokedSessions,
        @Schema(description = "Access tokens issued at or before this timestamp are no longer accepted", example = "2026-03-26T10:15:30Z")
        Instant accessTokensInvalidatedAt
) {
}
