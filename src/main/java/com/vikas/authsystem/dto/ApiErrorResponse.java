package com.vikas.authsystem.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.time.Instant;
import java.util.Map;

@Schema(name = "ApiErrorResponse", description = "Standard error payload returned by the API for validation, authentication, authorization, and business-rule failures.")
public record ApiErrorResponse(
        @Schema(description = "HTTP status code", example = "400")
        int status,
        @Schema(description = "HTTP reason phrase", example = "Bad Request")
        String error,
        @Schema(description = "Human-readable error summary", example = "Validation failed")
        String message,
        @Schema(description = "Timestamp when the error response was produced", example = "2026-03-20T10:53:00Z")
        Instant timestamp,
        @Schema(description = "Field-level validation errors when request validation fails", example = "{\"email\":\"Email is required\"}")
        Map<String, String> validationErrors
) {
}
