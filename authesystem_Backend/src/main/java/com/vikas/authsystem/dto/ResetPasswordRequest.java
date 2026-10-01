package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Schema(name = "ResetPasswordRequest", description = "Payload used to complete a password reset with an emailed OTP.")
public record ResetPasswordRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email format is invalid")
        @Schema(description = "Email address associated with the account", example = "user@example.com")
        String email,

        @NotBlank(message = "OTP is required")
        @Pattern(regexp = "\\d{6}", message = "OTP must be a 6 digit code")
        @Schema(description = "Six-digit password reset OTP sent to the user's email", example = "438291")
        String otp,

        @NotBlank(message = "newPassword is required")
        @Size(min = 8, max = 72, message = "newPassword must be between 8 and 72 characters")
        @Schema(description = "Replacement password for the account", example = "NewSecurePass@123")
        String newPassword,

        @Size(max = 128, message = "deviceId must not exceed 128 characters")
        @Schema(description = "Optional device identifier for audit attribution", example = "macbook-pro-16")
        String deviceId
) {
}
