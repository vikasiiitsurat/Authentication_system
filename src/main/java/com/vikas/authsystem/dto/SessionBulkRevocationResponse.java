package com.vikas.authsystem.dto;

public record SessionBulkRevocationResponse(
        String message,
        int revokedSessions
) {
}
