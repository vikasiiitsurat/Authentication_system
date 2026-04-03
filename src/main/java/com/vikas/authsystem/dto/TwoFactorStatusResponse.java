package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(name = "TwoFactorStatusResponse", description = "Current login 2FA status for the authenticated account.")
public record TwoFactorStatusResponse(
        @Schema(description = "Whether email-based login 2FA is enabled", example = "true")
        boolean enabled,

        @Schema(description = "Timestamp when login 2FA was enabled, or null when disabled", example = "2026-04-01T11:15:30Z", nullable = true)
        Instant enabledAt,

        @Schema(description = "Human-readable status message", example = "Two-factor authentication is enabled")
        String message
) {
}
