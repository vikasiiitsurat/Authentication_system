package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

@Schema(name = "AccountUnlockRequest", description = "Payload used to request an account unlock OTP when login protection is active.")
public record AccountUnlockRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email format is invalid")
        @Schema(description = "Email address associated with the protected account", example = "user@example.com")
        String email
) {
}
