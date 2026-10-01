package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;
import java.util.UUID;

@Schema(name = "RegisterResponse", description = "Registration result and OTP verification metadata for the created or pending account.")
public record RegisterResponse(
        @Schema(description = "Unique identifier of the registered user", example = "6a6c97fb-2a07-455c-8b2f-b6d21e70f98e")
        UUID userId,
        @Schema(description = "Full name stored for the account", example = "Vikas Sharma")
        String fullName,
        @Schema(description = "Email address associated with the account", example = "new.user@example.com")
        String email,
        @Schema(description = "User-facing registration status message", example = "Registration successful. Verify the OTP within 3 minutes to activate the account.")
        String message,
        @Schema(description = "Timestamp when the user record was created", example = "2026-03-20T10:47:27Z")
        Instant createdAt,
        @Schema(description = "Whether email verification must be completed before login", example = "true")
        boolean emailVerificationRequired,
        @Schema(description = "OTP validity window in seconds", example = "180")
        long otpExpiresInSeconds,
        @Schema(description = "Seconds remaining before a new OTP can be resent", example = "30")
        long resendAvailableInSeconds
) {
}
