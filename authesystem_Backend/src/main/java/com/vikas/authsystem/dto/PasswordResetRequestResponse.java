package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "PasswordResetRequestResponse", description = "Generic password reset request response that does not expose account existence.")
public record PasswordResetRequestResponse(
        @Schema(description = "Normalized email provided in the request", example = "user@example.com")
        String email,

        @Schema(
                description = "Generic status message that avoids disclosing whether an account exists",
                example = "If the account exists and is eligible, a password reset code will be sent. The code expires in 10 minutes."
        )
        String message,

        @Schema(description = "Password reset OTP lifetime in seconds", example = "600")
        long expiresInSeconds,

        @Schema(description = "Recommended resend delay in seconds", example = "60")
        long resendAvailableInSeconds
) {
}
