package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "LoginRequest", description = "Credentials and device metadata used to authenticate a user.")
public record LoginRequest(
        @NotBlank(message = "Email is required")
        @Email(message = "Email format is invalid")
        @Schema(description = "User email address used as the login identifier", example = "user@example.com")
        String email,

        @NotBlank(message = "Password is required")
        @Size(min = 8, max = 72, message = "Password must be between 8 and 72 characters")
        @Schema(description = "Plain-text account password", example = "StrongPass@123")
        String password,

        @Size(max = 128, message = "deviceId must not exceed 128 characters")
        @Schema(description = "Client-controlled device identifier used to bind refresh-token sessions", example = "pixel-8-pro")
        String deviceId
) {
}
