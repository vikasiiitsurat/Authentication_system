package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

@Schema(name = "VerifyAccountUnlockRequest", description = "Payload used to unlock an account with an emailed OTP.")
public record VerifyAccountUnlockRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email format is invalid")
        @Schema(description = "Email address associated with the protected account", example = "user@example.com")
        String email,

        @NotBlank(message = "OTP is required")
        @Pattern(regexp = "\\d{6}", message = "OTP must be a 6 digit code")
        @Schema(description = "Six-digit account unlock OTP sent to the user's email", example = "214590")
        String otp
) {
}
