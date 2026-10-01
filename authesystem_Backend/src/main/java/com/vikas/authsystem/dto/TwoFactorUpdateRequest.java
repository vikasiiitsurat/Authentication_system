package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Schema(name = "TwoFactorUpdateRequest", description = "Current-password confirmation payload used to enable or disable login 2FA.")
public record TwoFactorUpdateRequest(
        @NotBlank(message = "currentPassword is required")
        @Size(min = 8, max = 72, message = "currentPassword must be between 8 and 72 characters")
        @Schema(description = "Current password used to confirm the account security change", example = "StrongPass@123")
        String currentPassword,

        @Size(max = 128, message = "deviceId must not exceed 128 characters")
        @Schema(description = "Optional client device identifier for audit visibility", example = "web-browser")
        String deviceId
) {
}
