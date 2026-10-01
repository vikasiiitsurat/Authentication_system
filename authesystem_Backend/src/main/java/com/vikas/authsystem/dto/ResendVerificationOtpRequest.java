package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@Schema(name = "ResendVerificationOtpRequest", description = "Request payload for issuing another email verification OTP.")
public record ResendVerificationOtpRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email format is invalid")
        @Schema(description = "Email address for the unverified account", example = "new.user@example.com")
        String email
) {
}
