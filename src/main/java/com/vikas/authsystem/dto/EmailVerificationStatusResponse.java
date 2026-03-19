package com.vikas.authsystem.dto;

import java.time.Instant;

public record EmailVerificationStatusResponse(
        String email,
        String message,
        boolean verified,
        Instant verifiedAt,
        long expiresInSeconds,
        long resendAvailableInSeconds
) {
}
