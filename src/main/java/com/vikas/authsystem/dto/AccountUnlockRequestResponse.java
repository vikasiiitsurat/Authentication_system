package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(name = "AccountUnlockRequestResponse", description = "Generic account unlock request response that does not expose account state.")
public record AccountUnlockRequestResponse(
        @Schema(description = "Normalized email provided in the request", example = "user@example.com")
        String email,

        @Schema(
                description = "Generic status message that avoids disclosing whether the account exists or is currently protected",
                example = "If the account exists and protection is active, an account unlock code will be sent. The code expires in 10 minutes."
        )
        String message,

        @Schema(description = "Account unlock OTP lifetime in seconds", example = "600")
        long expiresInSeconds,

        @Schema(description = "Recommended resend delay in seconds", example = "60")
        long resendAvailableInSeconds
) {
}
