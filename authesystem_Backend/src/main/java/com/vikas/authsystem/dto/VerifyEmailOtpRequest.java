package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Schema(name = "VerifyEmailOtpRequest", description = "Payload used to verify an email address with a one-time passcode.")
public record VerifyEmailOtpRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email format is invalid")
        @Schema(description = "Email address for the account being verified", example = "new.user@example.com")
        String email,

        @NotBlank(message = "OTP is required")
        @Pattern(regexp = "\\d{6}", message = "OTP must be a 6 digit code")
        @Schema(description = "Six-digit one-time passcode sent to the user's email address", example = "482913")
        String otp,

        @Size(max = 128, message = "deviceId must not exceed 128 characters")
        @Schema(description = "Optional device identifier associated with the verification attempt", example = "pixel-8-pro")
        String deviceId
) {
}
