package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;

@Schema(name = "EmailVerificationStatusResponse", description = "Result of verifying or reissuing an email verification OTP.")
public record EmailVerificationStatusResponse(
        @Schema(description = "Email address associated with the verification flow", example = "new.user@example.com")
        String email,
        @Schema(description = "Verification status message", example = "Email verified successfully")
        String message,
        @Schema(description = "Whether the email address is currently verified", example = "true")
        boolean verified,
        @Schema(description = "Timestamp when the email was verified, if applicable", example = "2026-03-20T10:50:00Z")
        Instant verifiedAt,
        @Schema(description = "OTP validity window in seconds when a code is active", example = "180")
        long expiresInSeconds,
        @Schema(description = "Seconds until another OTP resend is allowed", example = "30")
        long resendAvailableInSeconds
) {
}
