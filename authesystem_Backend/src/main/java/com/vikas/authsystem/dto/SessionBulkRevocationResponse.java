package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "SessionBulkRevocationResponse", description = "Result of revoking all sessions except the current one.")
public record SessionBulkRevocationResponse(
        @Schema(description = "User-facing operation result message", example = "Other active sessions revoked")
        String message,
        @Schema(description = "Number of sessions revoked by the operation", example = "2")
        int revokedSessions
) {
}
