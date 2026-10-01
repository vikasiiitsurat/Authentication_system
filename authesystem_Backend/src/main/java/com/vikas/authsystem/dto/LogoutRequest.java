package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Size;

@Schema(
        name = "LogoutRequest",
        description = "Optional legacy payload for logout. The authenticated access-token session is always revoked, even when no refresh token is supplied."
)
public record LogoutRequest(
        @Size(max = 512, message = "refreshToken must not exceed 512 characters")
        @Schema(
                description = "Optional refresh token previously associated with the session being logged out",
                example = "r3fR35hTok3nValue",
                nullable = true
        )
        String refreshToken
) {
}
