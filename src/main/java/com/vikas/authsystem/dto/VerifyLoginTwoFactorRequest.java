package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

@Schema(name = "VerifyLoginTwoFactorRequest", description = "Verifies the email OTP for a pending 2FA login challenge.")
public record VerifyLoginTwoFactorRequest(
        @NotBlank(message = "challengeToken is required")
        @Size(max = 256, message = "challengeToken must not exceed 256 characters")
        @Schema(description = "Opaque challenge token returned from the password step of login", example = "y6wpr0yZ4n2XH5N6G6i8GsbSx0qnLxul8QK-v7Q9Or4")
        String challengeToken,

        @NotBlank(message = "otp is required")
        @Pattern(regexp = "\\d{6}", message = "otp must be a 6-digit code")
        @Schema(description = "6-digit email OTP sent for login verification", example = "123456")
        String otp
) {
}
