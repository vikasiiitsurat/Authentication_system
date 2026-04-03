package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "ResendLoginTwoFactorRequest", description = "Requests a resend of the email OTP for an active 2FA login challenge.")
public record ResendLoginTwoFactorRequest(
        @NotBlank(message = "challengeToken is required")
        @Size(max = 256, message = "challengeToken must not exceed 256 characters")
        @Schema(description = "Opaque challenge token returned from the password step of login", example = "y6wpr0yZ4n2XH5N6G6i8GsbSx0qnLxul8QK-v7Q9Or4")
        String challengeToken
) {
}
